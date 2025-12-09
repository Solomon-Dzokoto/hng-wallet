"""
Wallet Operations Router

Implements wallet management:
1. GET /wallet/balance - Get wallet balance
2. POST /wallet/deposit - Initiate Paystack deposit
3. POST /wallet/paystack/webhook - Receive Paystack webhook (credits wallet)
4. GET /wallet/deposit/{reference}/status - Check deposit status
5. POST /wallet/transfer - Transfer funds between wallets
6. GET /wallet/transactions - Get transaction history
"""

import hmac
import hashlib
import secrets
import httpx
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_

from ..database import get_db, settings
from ..models import Transaction, User, Wallet
from ..auth_deps import get_current_user_or_service, require_permissions
from ..schemas import (
    WalletBalanceResponse,
    WalletDepositRequest,
    PaymentInitiateResponse,
    TransactionStatusResponse,
    WebhookResponse,
    WalletTransferRequest,
    TransactionResponse
)

router = APIRouter(prefix="/wallet", tags=["wallet"])

# Paystack API endpoints
PAYSTACK_INITIALIZE_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify"


def generate_reference() -> str:
    """Generate a unique transaction reference."""
    return f"txn_{secrets.token_hex(16)}"


def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    """Verify the Paystack webhook signature."""
    if not settings.PAYSTACK_WEBHOOK_SECRET:
        return False
    
    expected_signature = hmac.new(
        settings.PAYSTACK_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)


@router.get("/balance", response_model=WalletBalanceResponse)
async def get_wallet_balance(
    current_user: User = Depends(require_permissions(["read"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the current wallet balance.
    
    Requires: JWT or API key with 'read' permission
    """
    # Find user's wallet
    result = await db.execute(
        select(Wallet).where(Wallet.user_id == current_user.id)
    )
    wallet = result.scalars().first()
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found. Please contact support."
        )
    
    return WalletBalanceResponse(balance=wallet.balance)


@router.post("/deposit", response_model=PaymentInitiateResponse, status_code=status.HTTP_201_CREATED)
async def initiate_deposit(
    deposit: WalletDepositRequest,
    current_user: User = Depends(require_permissions(["deposit"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate a wallet deposit using Paystack.
    
    Requires: JWT or API key with 'deposit' permission
    
    Steps:
    1. Create pending transaction
    2. Call Paystack to initialize payment
    3. Return authorization URL for user to complete payment
    4. Wallet will be credited via webhook after successful payment
    """
    # Find user's wallet
    result = await db.execute(
        select(Wallet).where(Wallet.user_id == current_user.id)
    )
    wallet = result.scalars().first()
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found. Please contact support."
        )
    
    if not settings.PAYSTACK_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Paystack credentials not configured"
        )
    
    # Generate unique reference
    reference = generate_reference()
    
    try:
        # Call Paystack Initialize Transaction API
        async with httpx.AsyncClient() as client:
            response = await client.post(
                PAYSTACK_INITIALIZE_URL,
                json={
                    "email": current_user.email,
                    "amount": deposit.amount,  # Amount in kobo
                    "reference": reference,
                },
                headers={
                    "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                    "Content-Type": "application/json",
                }
            )
            
            response_data = response.json()
            
            if response.status_code != 200 or not response_data.get("status"):
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=response_data.get("message", "Payment initiation failed")
                )
            
            authorization_url = response_data["data"]["authorization_url"]
    
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error communicating with Paystack: {str(e)}"
        )
    
    # Create transaction record
    transaction = Transaction(
        reference=reference,
        user_id=current_user.id,
        wallet_id=wallet.id,
        amount=deposit.amount,
        transaction_type="deposit",
        status="pending"
    )
    db.add(transaction)
    await db.commit()
    await db.refresh(transaction)
    
    return PaymentInitiateResponse(
        reference=reference,
        authorization_url=authorization_url
    )


@router.post("/paystack/webhook", response_model=WebhookResponse)
async def paystack_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Receive transaction updates from Paystack via webhook.
    
    This is the ONLY endpoint that credits wallets.
    
    Security: Validates Paystack signature header (x-paystack-signature).
    Idempotency: Prevents double-crediting by checking transaction status.
    """
    # Get raw body for signature verification
    body = await request.body()
    
    # Get signature from header
    signature = request.headers.get("x-paystack-signature", "")
    
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing signature header"
        )
    
    # Verify signature
    if not verify_paystack_signature(body, signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature"
        )
    
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    
    event = payload.get("event")
    data = payload.get("data", {})
    reference = data.get("reference")
    
    if not reference:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing transaction reference"
        )
    
    # Find transaction
    result = await db.execute(
        select(Transaction).where(Transaction.reference == reference)
    )
    transaction = result.scalars().first()
    
    if not transaction:
        # Transaction not found - might be from a different system
        return WebhookResponse(status=True)
    
    # Idempotency check: if already successful, don't process again
    if transaction.status == "success":
        return WebhookResponse(status=True)
    
    # Update transaction status based on event
    if event == "charge.success":
        # Get wallet
        result = await db.execute(
            select(Wallet).where(Wallet.id == transaction.wallet_id)
        )
        wallet = result.scalars().first()
        
        if wallet:
            # Credit wallet (atomic operation)
            wallet.balance += transaction.amount
            transaction.status = "success"
            
            paid_at_str = data.get("paid_at")
            if paid_at_str:
                try:
                    transaction.paid_at = datetime.fromisoformat(paid_at_str.replace("Z", "+00:00"))
                except ValueError:
                    transaction.paid_at = datetime.utcnow()
            else:
                transaction.paid_at = datetime.utcnow()
    
    elif event == "charge.failed":
        transaction.status = "failed"
    
    await db.commit()
    
    return WebhookResponse(status=True)


@router.get("/deposit/{reference}/status", response_model=TransactionStatusResponse)
async def get_deposit_status(
    reference: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get the status of a deposit transaction by reference.
    
    WARNING: This endpoint does NOT credit wallets.
    Only the webhook endpoint credits wallets.
    """
    # Find transaction in database
    result = await db.execute(
        select(Transaction).where(Transaction.reference == reference)
    )
    transaction = result.scalars().first()
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found"
        )
    
    return TransactionStatusResponse(
        reference=transaction.reference,
        status=transaction.status,
        amount=transaction.amount,
        paid_at=transaction.paid_at
    )


@router.post("/transfer", status_code=status.HTTP_200_OK)
async def transfer_funds(
    transfer: WalletTransferRequest,
    current_user: User = Depends(require_permissions(["transfer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Transfer funds from your wallet to another user's wallet.
    
    Requires: JWT or API key with 'transfer' permission
    
    Steps:
    1. Validate sender balance
    2. Find recipient wallet by wallet_number
    3. Atomically deduct from sender and credit recipient
    4. Record transaction
    """
    # Get sender's wallet
    result = await db.execute(
        select(Wallet).where(Wallet.user_id == current_user.id)
    )
    sender_wallet = result.scalars().first()
    
    if not sender_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Your wallet not found. Please contact support."
        )
    
    # Check sufficient balance
    if sender_wallet.balance < transfer.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient balance. Available: ₦{sender_wallet.balance / 100:.2f}"
        )
    
    # Find recipient wallet
    result = await db.execute(
        select(Wallet).where(Wallet.wallet_number == transfer.wallet_number)
    )
    recipient_wallet = result.scalars().first()
    
    if not recipient_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient wallet not found. Please verify the wallet number."
        )
    
    # Prevent self-transfer
    if sender_wallet.id == recipient_wallet.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot transfer to your own wallet."
        )
    
    # Atomic transfer
    sender_wallet.balance -= transfer.amount
    recipient_wallet.balance += transfer.amount
    
    # Create transaction reference
    reference = generate_reference()
    
    # Record transaction for sender
    transaction = Transaction(
        reference=reference,
        user_id=current_user.id,
        wallet_id=sender_wallet.id,
        amount=transfer.amount,
        transaction_type="transfer",
        status="success",
        recipient_wallet_id=recipient_wallet.id,
        paid_at=datetime.utcnow()
    )
    db.add(transaction)
    
    await db.commit()
    
    return {
        "status": "success",
        "message": "Transfer completed",
        "data": {
            "reference": reference,
            "amount": transfer.amount,
            "recipient_wallet_number": transfer.wallet_number
        }
    }


@router.get("/transactions", response_model=list[TransactionResponse])
async def get_transactions(
    current_user: User = Depends(require_permissions(["read"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get transaction history for the current user's wallet.
    
    Requires: JWT or API key with 'read' permission
    
    Returns all deposits and transfers (both sent and received).
    """
    # Get user's wallet
    result = await db.execute(
        select(Wallet).where(Wallet.user_id == current_user.id)
    )
    wallet = result.scalars().first()
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found. Please contact support."
        )
    
    # Get all transactions for this wallet (sent or received)
    result = await db.execute(
        select(Transaction).where(
            or_(
                Transaction.wallet_id == wallet.id,
                Transaction.recipient_wallet_id == wallet.id
            )
        ).order_by(Transaction.created_at.desc())
    )
    transactions = result.scalars().all()
    
    # Format response
    response = []
    for txn in transactions:
        # Determine recipient wallet number for transfers
        recipient_wallet_number = None
        if txn.transaction_type == "transfer" and txn.recipient_wallet_id:
            result = await db.execute(
                select(Wallet).where(Wallet.id == txn.recipient_wallet_id)
            )
            recipient_w = result.scalars().first()
            if recipient_w:
                recipient_wallet_number = recipient_w.wallet_number
        
        response.append(TransactionResponse(
            type=txn.transaction_type,
            amount=txn.amount,
            status=txn.status,
            created_at=txn.created_at,
            reference=txn.reference,
            recipient_wallet_number=recipient_wallet_number
        ))
    
    return response
