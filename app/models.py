import uuid
import secrets
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, BigInteger, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from .database import Base


class User(Base):
    """User model for storing Google OAuth authenticated users."""
    __tablename__ = "google_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    picture = Column(String, nullable=True)  # Profile picture URL from Google
    google_id = Column(String, unique=True, index=True, nullable=True)  # Google's unique user ID
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Wallet(Base):
    """Wallet model for storing user wallet balances."""
    __tablename__ = "wallets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("google_users.id"), unique=True, nullable=False)
    wallet_number = Column(String(13), unique=True, index=True, nullable=False)  # 13-digit unique wallet number
    balance = Column(BigInteger, default=0, nullable=False)  # Balance in kobo (lowest currency unit)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    @staticmethod
    def generate_wallet_number() -> str:
        """Generate a unique 13-digit wallet number."""
        # Generate 13-digit number (starts with 4 to avoid 0)
        return f"4{secrets.randbelow(10**12):012d}"


class APIKey(Base):
    """API Key model for service-to-service authentication."""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, nullable=False)  # Descriptive name for the key
    key_prefix = Column(String(16), nullable=False)  # First 8-16 chars for identification
    key_hash = Column(String, unique=True, index=True, nullable=False)  # SHA-256 hash of the key
    owner_id = Column(UUID(as_uuid=True), ForeignKey("google_users.id"), nullable=False)
    permissions = Column(JSON, nullable=False)  # Array of permissions: ["deposit", "transfer", "read"]
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Nullable for no expiration
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Transaction(Base):
    """Transaction model for storing wallet transactions (deposits, transfers, etc.)."""
    __tablename__ = "paystack_transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    reference = Column(String, unique=True, index=True, nullable=False)  # Transaction reference
    user_id = Column(UUID(as_uuid=True), ForeignKey("google_users.id"), nullable=False)
    wallet_id = Column(UUID(as_uuid=True), ForeignKey("wallets.id"), nullable=True)  # Associated wallet
    amount = Column(Integer, nullable=False)  # Amount in kobo (lowest currency unit)
    transaction_type = Column(String, nullable=False)  # deposit, transfer, withdrawal
    status = Column(String, default="pending")  # pending, success, failed
    recipient_wallet_id = Column(UUID(as_uuid=True), ForeignKey("wallets.id"), nullable=True)  # For transfers
    paid_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
