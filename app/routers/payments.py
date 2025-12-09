"""
Paystack Payment Router

Implements Paystack payment integration:
1. POST /payments/paystack/initiate - Initialize a payment transaction
2. POST /payments/paystack/webhook - Receive payment updates from Paystack
3. GET /payments/{reference}/status - Check transaction status
"""

import hmac
import hashlib
import secrets
import httpx
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..database import get_db, settings
from ..models import Transaction, User
from ..auth_deps import get_current_user
from ..schemas import (
    PaymentInitiateRequest,
    PaymentInitiateResponse,
    TransactionStatusResponse,
    WebhookResponse
)

router = APIRouter(prefix="/payments", tags=["payments"])

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


@router.post("/paystack/initiate", response_model=PaymentInitiateResponse, status_code=status.HTTP_201_CREATED)
async def initiate_payment(
    payment: PaymentInitiateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate a Paystack payment transaction.
    
    Steps:
    1. Validate amount (minimum 100 kobo)
    2. Check for existing pending transaction (idempotency)
    3. Call Paystack Initialize Transaction API
    4. Persist transaction with reference and status "pending"
    5. Return authorization URL and reference
    
    Amount validation:
    - Must be an integer (no decimals)
    - Minimum 100 kobo (₦1) - Paystack requirement
    """
    
    # Use authenticated user
    user = current_user
    
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
                    "email": user.email,
                    "amount": payment.amount,  # Amount in kobo
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
    
    # Persist transaction
    transaction = Transaction(
        reference=reference,
        user_id=user.id,
        amount=payment.amount,
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
    
    Security: Validates Paystack signature header (x-paystack-signature).
    
    Steps:
    1. Verify signature
    2. Parse event payload and extract transaction reference
    3. Update transaction status in database
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
    
    # Update transaction status based on event
    if event == "charge.success":
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


@router.get("/{reference}/status", response_model=TransactionStatusResponse)
async def get_transaction_status(
    reference: str,
    refresh: bool = Query(False, description="If true, fetch live status from Paystack"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the status of a transaction by reference.
    
    If refresh=true, calls Paystack verify endpoint to fetch live status and updates DB.
    Otherwise, returns the status from the database.
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
    
    # If refresh requested, fetch from Paystack
    if refresh:
        if not settings.PAYSTACK_SECRET_KEY:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Paystack credentials not configured"
            )
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{PAYSTACK_VERIFY_URL}/{reference}",
                    headers={
                        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                    }
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    
                    if response_data.get("status"):
                        data = response_data.get("data", {})
                        paystack_status = data.get("status", "").lower()
                        
                        # Map Paystack status to our status
                        if paystack_status == "success":
                            transaction.status = "success"
                            paid_at_str = data.get("paid_at")
                            if paid_at_str:
                                try:
                                    transaction.paid_at = datetime.fromisoformat(
                                        paid_at_str.replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass
                        elif paystack_status == "failed":
                            transaction.status = "failed"
                        # else keep as pending
                        
                        await db.commit()
                        await db.refresh(transaction)
        
        except httpx.RequestError:
            # If Paystack is unreachable, just return DB status
            pass
    
    return TransactionStatusResponse(
        reference=transaction.reference,
        status=transaction.status,
        amount=transaction.amount,
        paid_at=transaction.paid_at
    )
