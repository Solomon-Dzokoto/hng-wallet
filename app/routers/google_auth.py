"""
Google OAuth 2.0 Authentication Router

Implements the server-side OAuth 2.0 flow:
1. GET /auth/google - Redirects to Google OAuth consent page
2. GET /auth/google/callback - Handles callback, exchanges code for tokens, creates/updates user
"""

import secrets
import httpx
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..database import get_db, settings
from ..models import User
from ..schemas import GoogleAuthURLResponse, GoogleUserResponse

router = APIRouter(prefix="/auth", tags=["auth"])

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# In-memory state storage (use Redis in production)
oauth_states: dict[str, bool] = {}


@router.get("/google", response_model=GoogleAuthURLResponse)
async def google_auth():
    """
    Trigger Google sign-in flow.
    
    Returns a JSON response with the Google OAuth authorization URL.
    The client should redirect the user to this URL.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth credentials not configured"
        )
    
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    oauth_states[state] = True
    
    # Build authorization URL
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    
    return GoogleAuthURLResponse(google_auth_url=auth_url)


@router.get("/google/redirect")
async def google_auth_redirect():
    """
    Alternative endpoint that returns a 302 redirect to Google OAuth consent page.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google OAuth credentials not configured"
        )
    
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    oauth_states[state] = True
    
    # Build authorization URL
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    
    return RedirectResponse(url=auth_url, status_code=302)


from ..utils import create_access_token

@router.get("/google/callback", response_model=GoogleUserResponse)
async def google_callback(
    code: str = Query(None, description="Authorization code from Google"),
    state: str = Query(None, description="State parameter for CSRF validation"),
    error: str = Query(None, description="Error from Google OAuth"),
    db: AsyncSession = Depends(get_db)
):
    """
    Google OAuth callback endpoint.
    
    Handles the OAuth callback from Google:
    1. Validates the state parameter
    2. Exchanges the authorization code for an access token
    3. Fetches user info from Google
    4. Creates or updates the user in the database
    5. GENERATES AND RETURNS A JWT ACCESS TOKEN
    """
    # Validations
    print(f"DEBUG: Callback received. Code: {bool(code)}, State: {state}, Error: {error}")
    
    # Check for errors from Google
    if error:
        print(f"DEBUG: Google returned error: {error}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth error: {error}"
        )
    
    # Validate required parameters
    if not code:
        print("DEBUG: Missing code")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code"
        )
    
    if not state:
        print("DEBUG: Missing state")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing state parameter"
        )
    
    # Validate state parameter (CSRF protection)
    if state not in oauth_states:
        print(f"DEBUG: Invalid state. Received: {state}. Available: {list(oauth_states.keys())}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )
    
    # Remove used state
    del oauth_states[state]
    print("DEBUG: State validated and removed")
    
    try:
        # Exchange authorization code for access token
        async with httpx.AsyncClient() as client:
            print("DEBUG: Exchanging code for token...")
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            
            if token_response.status_code != 200:
                print(f"DEBUG: Token exchange failed: {token_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to exchange authorization code"
                )
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            print("DEBUG: Access token received")
            
            # Fetch user info from Google
            print("DEBUG: Fetching user info...")
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if userinfo_response.status_code != 200:
                print(f"DEBUG: User info fetch failed: {userinfo_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to fetch user info from Google"
                )
            
            user_info = userinfo_response.json()
            print(f"DEBUG: User info received: {user_info.get('email')}")
    
    except httpx.RequestError as e:
        print(f"DEBUG: HTTP Request error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error communicating with Google: {str(e)}"
        )
    
    # Extract user information
    google_id = user_info.get("id")
    email = user_info.get("email")
    name = user_info.get("name")
    picture = user_info.get("picture")
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not provided by Google"
        )
    
    try:
        # Check if user exists (by google_id or email)
        result = await db.execute(
            select(User).where(
                (User.google_id == google_id) | (User.email == email)
            )
        )
        existing_user = result.scalars().first()
        
        if existing_user:
            print("DEBUG: Updating existing user")
            # Update existing user
            existing_user.google_id = google_id
            existing_user.name = name
            existing_user.picture = picture
            await db.commit()
            await db.refresh(existing_user)
            user = existing_user
        else:
            print("DEBUG: Creating new user")
            # Create new user
            user = User(
                email=email,
                name=name,
                picture=picture,
                google_id=google_id,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            # Create wallet for new user
            from ..models import Wallet
            wallet = Wallet(
                user_id=user.id,
                wallet_number=Wallet.generate_wallet_number(),
                balance=0
            )
            db.add(wallet)
            await db.commit()
            print(f"DEBUG: Wallet created with number: {wallet.wallet_number}")
        print("DEBUG: User saved successfully")
        
        # Generate JWT Token using our utility
        access_token = create_access_token(data={"sub": str(user.id)})
        print("DEBUG: JWT generated")
        
        return GoogleUserResponse(
            user_id=user.id,
            email=user.email,
            name=user.name,
            access_token=access_token,
            token_type="bearer"
        )
    except Exception as e:
        print(f"DEBUG: DB Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error handling user"
        )
