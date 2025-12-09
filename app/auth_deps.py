from datetime import datetime
from typing import Optional, List, Union
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from .database import get_db, settings
from .models import User, APIKey
from .utils import hash_api_key

# Defines that the client should send the token in: Authorization: Bearer <token>
security = HTTPBearer(auto_error=False)


async def get_current_user_from_jwt(
    token: HTTPAuthorizationCredentials = Depends(security), 
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Validate the JWT token and retrieve the current user.
    Used for endpoints that ONLY accept JWT authentication.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode token
        payload = jwt.decode(
            token.credentials, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        # Get user_id (sub) from payload
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    # Fetch user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    
    if user is None:
        raise credentials_exception
        
    return user


async def get_current_user_from_api_key(
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, APIKey]:
    """
    Validate API key and retrieve the user and API key object.
    Returns tuple of (User, APIKey).
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    
    # Hash the provided API key
    key_hash = hash_api_key(x_api_key)
    
    # Find API key in database
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    api_key = result.scalars().first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    
    # Check if API key is active
    if not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked",
        )
    
    # Check if API key is expired
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
        )
    
    # Get the user who owns this API key
    result = await db.execute(
        select(User).where(User.id == api_key.owner_id)
    )
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key owner not found",
        )
    
    return user, api_key


async def get_current_user_or_service(
    token: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, Optional[APIKey]]:
    """
    Dual authentication: Accept either JWT token or API key.
    Returns tuple of (User, APIKey or None).
    
    Checks Authorization header first, then x-api-key header.
    """
    # Try JWT first
    if token:
        try:
            user = await get_current_user_from_jwt(token, db)
            return user, None
        except HTTPException:
            pass
    
    # Try API key
    if x_api_key:
        user, api_key = await get_current_user_from_api_key(x_api_key, db)
        return user, api_key
    
    # Neither worked
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials. Provide either Bearer token or x-api-key header.",
    )


def require_permissions(required_permissions: List[str]):
    """
    Dependency factory to check if API key has required permissions.
    If authenticated via JWT, always allows access.
    If authenticated via API key, checks permissions.
    
    Usage:
        @router.post("/endpoint", dependencies=[Depends(require_permissions(["deposit"]))])
    """
    async def permission_checker(
        user_and_key: tuple[User, Optional[APIKey]] = Depends(get_current_user_or_service)
    ):
        user, api_key = user_and_key
        
        # If JWT authentication (no API key), allow access
        if api_key is None:
            return user
        
        # If API key authentication, check permissions
        api_key_permissions = api_key.permissions if isinstance(api_key.permissions, list) else []
        
        missing_permissions = [perm for perm in required_permissions if perm not in api_key_permissions]
        
        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required permissions: {', '.join(missing_permissions)}",
            )
        
        return user
    
    return permission_checker

