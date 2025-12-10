from fastapi import FastAPI
from .routers import google_auth, payments, api_keys, wallet
from .database import engine, Base

app = FastAPI(
    title="Wallet Service API",
    description="Backend API for wallet management with Google OAuth, Paystack payments, and API key authentication",
    version="1.0.0"
)

# Include routers
app.include_router(google_auth.router)
app.include_router(payments.router)
app.include_router(api_keys.router)
app.include_router(wallet.router)


@app.on_event("startup")
async def startup():
    """Create database tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/")
def read_root():
    """Health check endpoint."""
    return {
        "message": "Wallet Service API - HNG Stage 9",
        "status": "running",
        "endpoints": {
            "google_auth": "/auth/google",
            "google_callback": "/auth/google/callback",
            "api_keys_create": "/keys/create",
            "api_keys_rollover": "/keys/rollover",
            "wallet_balance": "/wallet/balance",
            "wallet_deposit": "/wallet/deposit",
            "wallet_transfer": "/wallet/transfer",
            "wallet_transactions": "/wallet/transactions",
            "paystack_webhook": "/wallet/paystack/webhook"
        },
        "documentation": "/docs"
    }


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy"}

