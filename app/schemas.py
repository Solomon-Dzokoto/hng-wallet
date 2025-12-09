from pydantic import BaseModel, EmailStr, field_validator, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID


# ============== Google OAuth Schemas ==============

class GoogleAuthURLResponse(BaseModel):
    """Response containing Google OAuth authorization URL."""
    google_auth_url: str


class GoogleUserResponse(BaseModel):
    """Response after successful Google OAuth callback."""
    user_id: UUID
    email: str
    name: Optional[str] = None
    access_token: str
    token_type: str

    class Config:
        from_attributes = True


# ============== Paystack Payment Schemas ==============

class PaymentInitiateRequest(BaseModel):
    """Request body for initiating a Paystack payment."""
    amount: float = Field(..., ge=1.0, description="Amount in Naira (₦) - minimum ₦1.00")
    
    @field_validator('amount')
    @classmethod
    def validate_and_convert_amount(cls, v: float) -> int:
        """
        Validate amount and convert from Naira to kobo.
        
        Args:
            v: Amount in Naira (can be decimal like 50.50)
            
        Returns:
            Amount in kobo (integer like 5050)
            
        Raises:
            ValueError: If amount is less than ₦1.00
        """
        if v < 1.0:
            raise ValueError('Amount must be at least ₦1.00 (Paystack minimum)')
        
        # Convert Naira to kobo (₦1 = 100 kobo)
        amount_in_kobo = int(v * 100)
        
        if amount_in_kobo < 100:
            raise ValueError('Amount must be at least ₦1.00 (100 kobo)')
        
        return amount_in_kobo


class PaymentInitiateResponse(BaseModel):
    """Response after successful payment initiation."""
    reference: str
    authorization_url: str


class TransactionStatusResponse(BaseModel):
    """Response for transaction status check."""
    reference: str
    status: str  # pending, success, failed
    amount: int
    paid_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WebhookResponse(BaseModel):
    """Response for webhook endpoint."""
    status: bool


# ============== API Key Schemas ==============

class APIKeyCreate(BaseModel):
    """Request to create a new API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Descriptive name for the key")
    permissions: List[str] = Field(..., description="List of permissions: deposit, transfer, read")
    expiry: str = Field(..., description="Expiry format: 1H, 1D, 1M, 1Y")
    
    @field_validator('permissions')
    @classmethod
    def validate_permissions(cls, v: List[str]) -> List[str]:
        """Validate that permissions are valid."""
        valid_permissions = {"deposit", "transfer", "read"}
        if not v:
            raise ValueError("At least one permission is required")
        
        for perm in v:
            if perm not in valid_permissions:
                raise ValueError(f"Invalid permission '{perm}'. Must be one of: {valid_permissions}")
        
        return list(set(v))  # Remove duplicates


class APIKeyResponse(BaseModel):
    """Response after creating an API key (includes raw key - only shown once)."""
    api_key: str
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class APIKeyInfo(BaseModel):
    """API key metadata for listing (no raw key)."""
    id: UUID
    name: str
    key_prefix: str
    permissions: List[str]
    expires_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RolloverRequest(BaseModel):
    """Request to rollover an expired API key."""
    expired_key_id: str = Field(..., description="ID of the expired key to rollover")
    expiry: str = Field(..., description="Expiry format for new key: 1H, 1D, 1M, 1Y")


# ============== Wallet Schemas ==============

class WalletBalanceResponse(BaseModel):
    """Response for wallet balance."""
    balance: int  # Balance in kobo

    class Config:
        from_attributes = True


class WalletDepositRequest(BaseModel):
    """Request to initiate a wallet deposit via Paystack."""
    amount: float = Field(..., ge=1.0, description="Amount in Naira (₦)")
    
    @field_validator('amount')
    @classmethod
    def validate_and_convert_amount(cls, v: float) -> int:
        """Convert Naira to kobo."""
        if v < 1.0:
            raise ValueError('Amount must be at least ₦1.00')
        return int(v * 100)


class WalletTransferRequest(BaseModel):
    """Request to transfer funds to another wallet."""
    wallet_number: str = Field(..., min_length=13, max_length=13, description="13-digit recipient wallet number")
    amount: int = Field(..., ge=100, description="Amount in kobo (minimum 100 kobo = ₦1)")


class TransactionResponse(BaseModel):
    """Response for transaction history item."""
    type: str  # deposit, transfer, withdrawal
    amount: int
    status: str  # pending, success, failed
    created_at: datetime
    reference: Optional[str] = None
    recipient_wallet_number: Optional[str] = None

    class Config:
        from_attributes = True

