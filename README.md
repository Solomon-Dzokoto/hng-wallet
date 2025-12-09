# Wallet Service API - HNG Stage 9

A complete backend wallet service with Paystack integration, Google OAuth authentication, and API key management for service-to-service access.

## Features

- ✅ **Google OAuth 2.0** - User authentication with JWT tokens
- ✅ **Wallet System** - Balance tracking, deposits, and transfers
- ✅ **Paystack Integration** - Secure payment processing
- ✅ **API Keys** - Service-to-service authentication with granular permissions
- ✅ **Dual Authentication** - Support for both JWT and API keys
- ✅ **Webhook Handling** - Secure Paystack webhook validation
- ✅ **Permission System** - deposit, transfer, read permissions for API keys

## Setup

### 1. Install Dependencies

```bash
cd wallet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file with your credentials:

```env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5433/wallet_db
SECRET_KEY=your-secret-key-here
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
PAYSTACK_SECRET_KEY=sk_test_your-key
PAYSTACK_WEBHOOK_SECRET=your-webhook-secret
```

### 3. Create PostgreSQL Database

```bash
createdb wallet_db
```

### 4. Run the Server

```bash
uvicorn app.main:app --reload
```

Server will start at `http://localhost:8000`

## Authentication

This API supports **dual authentication**:

### 1. JWT (User Authentication)
- Sign in with Google OAuth to receive a JWT token
- Use header: `Authorization: Bearer <token>`

### 2. API Key (Service Authentication)
- Create API keys with specific permissions
- Use header: `x-api-key: <key>`

## API Endpoints

### Google OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/google` | Returns Google OAuth URL (JSON) |
| GET | `/auth/google/redirect` | Redirects to Google consent page (302) |
| GET | `/auth/google/callback` | Handles OAuth callback, returns JWT |

**Example - Google Sign-In:**
```bash
# Step 1: Get Google auth URL
curl http://localhost:8000/auth/google

# Step 2: Visit the returned URL in browser
# Step 3: After callback, receive JWT token
```

### API Key Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/keys/create` | Create new API key | JWT |
| POST | `/keys/rollover` | Rollover expired key | JWT |
| GET | `/keys/` | List your API keys | JWT |
| POST | `/keys/revoke/{key_id}` | Revoke an API key | JWT |

**Example - Create API Key:**
```bash
curl -X POST http://localhost:8000/keys/create \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Service",
    "permissions": ["deposit", "transfer", "read"],
    "expiry": "1D"
  }'
```

**Expiry Formats:**
- `1H` - 1 hour
- `1D` - 1 day
- `7D` - 7 days
- `1M` - 1 month (30 days)
- `1Y` - 1 year (365 days)

**Permissions:**
- `deposit` - Can initiate wallet deposits
- `transfer` - Can transfer funds between wallets
- `read` - Can view balance and transaction history

**Limits:**
- Maximum 5 active API keys per user

### Wallet Operations

| Method | Endpoint | Description | Auth | Permissions |
|--------|----------|-------------|------|-------------|
| GET | `/wallet/balance` | Get wallet balance | JWT or API Key | read |
| POST | `/wallet/deposit` | Initiate Paystack deposit | JWT or API Key | deposit |
| POST | `/wallet/paystack/webhook` | Paystack webhook (internal) | - | - |
| GET | `/wallet/deposit/{reference}/status` | Check deposit status | - | - |
| POST | `/wallet/transfer` | Transfer to another wallet | JWT or API Key | transfer |
| GET | `/wallet/transactions` | Get transaction history | JWT or API Key | read |

**Example - Check Balance (using JWT):**
```bash
curl http://localhost:8000/wallet/balance \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

**Example - Check Balance (using API Key):**
```bash
curl http://localhost:8000/wallet/balance \
  -H "x-api-key: sk_live_xxxxx"
```

**Example - Deposit:**
```bash
curl -X POST http://localhost:8000/wallet/deposit \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"amount": 5000}'

# Returns authorization_url - visit to complete payment
```

**Example - Transfer:**
```bash
curl -X POST http://localhost:8000/wallet/transfer \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_number": "4567890123456",
    "amount": 1000
  }'
```

**Example - Transaction History:**
```bash
curl http://localhost:8000/wallet/transactions \
  -H "x-api-key: sk_live_xxxxx"
```

## Paystack Webhook Setup

Configure your Paystack webhook URL to:
```
https://your-domain.com/wallet/paystack/webhook
```

The webhook endpoint:
- Validates signature using `x-paystack-signature` header
- Credits wallet only on `charge.success` event
- Prevents double-crediting (idempotent)

## Interactive Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Security Features

- ✅ JWT token validation
- ✅ API key hashing (SHA-256)
- ✅ Paystack webhook signature verification
- ✅ Permission-based access control
- ✅ API key expiration
- ✅ Atomic wallet transfers
- ✅ Idempotent webhook processing

## Database Schema

### Tables
- `google_users` - User accounts from Google OAuth
- `wallets` - User wallets with balance and unique wallet numbers
- `api_keys` - API keys with permissions
- `paystack_transactions` - All wallet transactions (deposits, transfers)

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200` - Success
- `201` - Created (new resource)
- `400` - Bad request (validation error)
- `401` - Unauthorized (missing/invalid credentials)
- `403` - Forbidden (insufficient permissions)
- `404` - Not found
- `500` - Internal server error

## Development

Run server in development mode:
```bash
uvicorn app.main:app --reload --port 8000
```

## HNG Stage 9 Compliance

This implementation meets all HNG Stage 9 requirements:
- ✅ Google sign-in with JWT
- ✅ Wallet creation per user
- ✅ Paystack deposits
- ✅ Balance, transaction history, status checking
- ✅ Wallet-to-wallet transfers
- ✅ API key system with permissions
- ✅ Maximum 5 active keys per user
- ✅ API key expiration (1H, 1D, 1M, 1Y format)
- ✅ API key rollover
- ✅ Mandatory webhook handling

