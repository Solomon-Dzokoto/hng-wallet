import secrets
import hashlib
from datetime import datetime, timedelta
from jose import jwt
from fastapi import HTTPException, status
from .database import settings


def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing data to encode (e.g., user_id)
        expires_delta: Optional expiry time duration
    
    Returns:
        Encoded JWT string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # Default 30 minutes if not specified
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Store expiry as 'exp' claim (standard JWT claim)
    to_encode.update({"exp": expire})
    
    # Encode with secret key
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def generate_api_key() -> str:
    """
    Generate a cryptographically secure API key.
    
    Format: sk_live_<32_hex_chars>
    
    Returns:
        API key string
    """
    random_part = secrets.token_hex(32)  # 64 characters
    return f"sk_live_{random_part}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using SHA-256.
    
    Args:
        api_key: Raw API key string
        
    Returns:
        SHA-256 hash in hexadecimal format
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_api_key_prefix(api_key: str) -> str:
    """
    Extract the prefix from an API key for identification.
    
    Args:
        api_key: Raw API key string
        
    Returns:
        First 16 characters of the key
    """
    return api_key[:16]


def parse_expiry(expiry_str: str) -> datetime:
    """
    Parse expiry shorthand format (1H, 1D, 1M, 1Y) into a datetime.
    
    Args:
        expiry_str: Expiry string (e.g., "1H", "7D", "1M", "1Y")
        
    Returns:
        Expiry datetime
        
    Raises:
        HTTPException: If format is invalid
    """
    if not expiry_str or len(expiry_str) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid expiry format. Use format like '1H', '1D', '1M', '1Y'"
        )
    
    # Extract number and unit
    try:
        num_str = expiry_str[:-1]
        unit = expiry_str[-1].upper()
        
        num = int(num_str)
        
        if num <= 0:
            raise ValueError("Number must be positive")
            
    except (ValueError, IndexError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid expiry format. Use format like '1H', '1D', '1M', '1Y'"
        )
    
    # Calculate expiry based on unit
    now = datetime.utcnow()
    
    if unit == 'H':
        return now + timedelta(hours=num)
    elif unit == 'D':
        return now + timedelta(days=num)
    elif unit == 'M':
        # Approximate month as 30 days
        return now + timedelta(days=num * 30)
    elif unit == 'Y':
        # Approximate year as 365 days
        return now + timedelta(days=num * 365)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid expiry unit '{unit}'. Must be H (hour), D (day), M (month), or Y (year)"
        )

