from datetime import datetime
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from ..database import get_db
from ..models import User, APIKey
from ..schemas import APIKeyCreate, APIKeyResponse, APIKeyInfo, RolloverRequest
from ..auth_deps import get_current_user_from_jwt
from ..utils import generate_api_key, hash_api_key, get_api_key_prefix, parse_expiry

router = APIRouter(prefix="/keys", tags=["api-keys"])


@router.post("/create", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user_from_jwt),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for service-to-service authentication.
    
    - **name**: Descriptive name for the key (e.g., "Production Service")
    - **permissions**: Array of permissions: ["deposit", "transfer", "read"]
    - **expiry**: Expiry format: 1H, 1D, 1M, 1Y
    
    Maximum of 5 active API keys per user.
    """
    # Check if user is active
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is inactive. Cannot create API keys."
        )
    
    # Check active key count (maximum 5)
    result = await db.execute(
        select(func.count()).select_from(APIKey).where(
            APIKey.owner_id == current_user.id,
            APIKey.is_active == True
        )
    )
    active_count = result.scalar()
    
    if active_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 5 active API keys allowed. Please revoke an existing key first."
        )
    
    # Generate API key
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    prefix = get_api_key_prefix(raw_key)
    
    # Parse expiry
    expires_at = parse_expiry(key_data.expiry)
    
    # Create new API key
    new_key = APIKey(
        name=key_data.name,
        key_prefix=prefix,
        key_hash=hashed,
        owner_id=current_user.id,
        permissions=key_data.permissions,
        expires_at=expires_at,
        is_active=True
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return APIKeyResponse(
        api_key=raw_key,
        expires_at=new_key.expires_at
    )


@router.post("/rollover", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def rollover_api_key(
    rollover_data: RolloverRequest,
    current_user: User = Depends(get_current_user_from_jwt),
    db: AsyncSession = Depends(get_db)
):
    """
    Rollover an expired API key with the same permissions.
    
    - **expired_key_id**: ID of the expired key to rollover
    - **expiry**: New expiry format: 1H, 1D, 1M, 1Y
    
    The expired key must be truly expired and owned by the current user.
    """
    # Find the expired key
    try:
        key_uuid = UUID(rollover_data.expired_key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format"
        )
    
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_uuid,
            APIKey.owner_id == current_user.id
        )
    )
    old_key = result.scalars().first()
    
    if not old_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or you don't have permission to rollover it."
        )
    
    # Verify the key is expired
    if not old_key.expires_at or old_key.expires_at > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not expired. Only expired keys can be rolled over."
        )
    
    # Check active key count (maximum 5)
    result = await db.execute(
        select(func.count()).select_from(APIKey).where(
            APIKey.owner_id == current_user.id,
            APIKey.is_active == True
        )
    )
    active_count = result.scalar()
    
    if active_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 5 active API keys allowed. Please revoke an existing key first."
        )
    
    # Generate new API key with same permissions
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    prefix = get_api_key_prefix(raw_key)
    
    # Parse new expiry
    expires_at = parse_expiry(rollover_data.expiry)
    
    # Create new API key
    new_key = APIKey(
        name=f"{old_key.name} (Renewed)",
        key_prefix=prefix,
        key_hash=hashed,
        owner_id=current_user.id,
        permissions=old_key.permissions,  # Reuse same permissions
        expires_at=expires_at,
        is_active=True
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return APIKeyResponse(
        api_key=raw_key,
        expires_at=new_key.expires_at
    )


@router.get("/", response_model=list[APIKeyInfo])
async def list_api_keys(
    current_user: User = Depends(get_current_user_from_jwt),
    db: AsyncSession = Depends(get_db)
):
    """
    List all API keys belonging to the authenticated user.
    
    Returns metadata only (no raw keys).
    """
    result = await db.execute(
        select(APIKey).where(APIKey.owner_id == current_user.id)
    )
    keys = result.scalars().all()
    return keys


@router.post("/revoke/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user_from_jwt),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke an API key by its ID.
    
    - **key_id**: The UUID of the API key to revoke
    """
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format"
        )
    
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_uuid,
            APIKey.owner_id == current_user.id
        )
    )
    key = result.scalars().first()
    
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or you don't have permission to revoke it."
        )
    
    if not key.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is already revoked."
        )
    
    key.is_active = False
    await db.commit()
    
    return {
        "success": True,
        "message": "API key revoked successfully.",
        "data": {"key_id": str(key_id), "key_name": key.name}
    }
