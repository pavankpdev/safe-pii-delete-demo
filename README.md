# SafeDelete Demo

A minimal, production-faithful demo that shows secure storage of displayable PII (name, email, phone), authenticated profile viewing, a deletion workflow that proves data was purged, and an auditable tamper-evident log — all without external KMS or real DB servers.

## Features

- **Secure PII Storage**: AES-256-GCM encryption for sensitive data
- **Authenticated Access**: JWT-based authentication with HttpOnly cookies
- **Auditable Deletion**: Tamper-evident audit logs with cryptographic proof
- **Crypto-Shred Simulation**: Key destruction demonstration
- **PII-Safe Logging**: Logger that throws on PII detection
- **Backup Scrubbing**: Automatic backup cleanup after deletion

## Quick Start

### Prerequisites

- Node.js LTS
- Bun (for package management)

### Installation

```bash
# Install dependencies
bun install

# Build the project
bun run build

# Start the server
bun run start
```

The application will be available at `http://localhost:3000`

### Development Mode

```bash
# Watch mode for development
bun run dev
```

## Demo Script

### 1. Create Admin Account
- Navigate to `http://localhost:3000`
- Use the **Login** tab
- **Email**: `admin@example.com` (pre-configured admin)
- **Password**: `admin123`

### 2. Create Regular User
- Switch to **Sign Up** tab
- Fill in name, email, phone, and password
- Note the returned User ID

### 3. View Encrypted Data
- Switch to **Debug** tab
- Click **Show Database** to see encrypted PII fields
- Notice all sensitive data is encrypted (`[ENCRYPTED]`)

### 4. View Profile
- Switch to **Profile** tab
- Click **Load Profile** to see decrypted data
- Verify the data matches what you entered

### 5. Delete Data
- In **Profile** tab, click **Delete My Data**
- Confirm the deletion
- View the proof modal showing:
  - Audit ID
  - Cryptographic proof hash
  - Deletion confirmation

### 6. Verify Deletion
- Switch to **Debug** tab
- Click **Show Database** again
- Notice the user's PII fields are now `null`
- Check **Show Audit Logs** to see deletion records

### 7. Crypto-Shred Simulation
- In **Debug** tab, click **Simulate Crypto-Shred**
- This destroys encryption keys
- Try to load profile again - decryption will fail

## API Endpoints

### Authentication Required
All endpoints except `/signup`, `/login`, and `/health` require JWT authentication.

### POST /signup
Create a new user account.

**Request:**
```json
{
  "name": "John Doe",
  "email": "john@example.com", 
  "phone": "+1234567890",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "ok": true,
  "userId": "uuid-here"
}
```

### POST /login
Authenticate user and set HttpOnly cookie.

**Request:**
```json
{
  "email": "john@example.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "ok": true
}
```

### GET /me
Get current user's decrypted profile data.

**Response:**
```json
{
  "id": "uuid-here",
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "created_at": "2025-01-20T12:00:00Z"
}
```

### POST /me/delete
Delete current user's PII data.

**Response:**
```json
{
  "ok": true,
  "auditId": "uuid-here",
  "proof_hash": "cryptographic-proof-hash"
}
```

### GET /audit/:userId
Get audit logs for a user (admin or own user only).

**Response:**
```json
{
  "logs": [
    {
      "id": "uuid-here",
      "user_id": "uuid-here",
      "action": "CREATE",
      "performed_by": "user",
      "timestamp": "2025-01-20T12:00:00Z",
      "notes": "User account created",
      "proof_hash": "cryptographic-proof-hash"
    }
  ]
}
```

### POST /simulate/crypto-shred
Simulate encryption key destruction (admin only).

**Response:**
```json
{
  "ok": true,
  "message": "Keys destroyed"
}
```

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-20T12:00:00Z"
}
```

## Security Implementation

### Encryption
- **Algorithm**: AES-256-GCM
- **Key Management**: Environment variables (demo only)
- **Data Encrypted**: name, email, phone fields
- **Storage Format**: `{iv}:{authTag}:{ciphertext}` (base64)

### Authentication
- **Method**: JWT with HS256 algorithm
- **Storage**: HttpOnly cookies (15-minute expiry)
- **Fallback**: Authorization header
- **Password Hashing**: bcrypt with 12 salt rounds

### Audit Logging
- **Tamper Evidence**: HMAC-SHA256 proof hashes
- **Canonicalization**: Lexicographically sorted JSON
- **Actions Tracked**: CREATE, DELETE_REQUEST, DATA_PURGED, KEY_DESTROYED
- **Immutable**: Append-only audit.json file

### PII Protection
- **Logging**: Throws error if PII detected in logs
- **Indexing**: HMAC-SHA256 of normalized email for lookups
- **Backup Scrubbing**: Automatic PII removal from backups

## Environment Variables

```bash
# Encryption key (32 bytes, base64)
ENC_KEY=your-32-byte-base64-key

# Email indexing key (32 bytes, base64)  
INDEX_KEY=your-32-byte-base64-key

# Audit signing key (32 bytes, base64)
SIGNING_KEY=your-32-byte-base64-key

# JWT secret (32 bytes, base64)
JWT_SECRET=your-32-byte-base64-key

# bcrypt salt rounds
BCRYPT_SALT_ROUNDS=12

# Admin user IDs (comma-separated)
ADMIN_USER_IDS=00000000-0000-0000-0000-000000000001

# Environment
NODE_ENV=development
```

## Security Notes

⚠️ **DEMO ONLY - NOT FOR PRODUCTION**

This demo uses local file storage and environment variables for key management. For production deployments:

- Use proper Key Management Service (AWS KMS, Google KMS, HashiCorp Vault)
- Implement key rotation policies
- Use HTTPS with proper SSL certificates
- Implement proper CSP headers
- Use secure cookie settings for production
- Store keys in secure, encrypted storage
- Implement proper backup encryption
- Use database-level encryption for additional security

## File Structure

```
src/
├── types/           # TypeScript type definitions
├── services/        # Core business logic
│   ├── crypto.ts    # Encryption/decryption utilities
│   ├── auth.ts      # Authentication and authorization
│   ├── database.ts  # Database operations
│   └── logger.ts    # PII-safe logging
├── server.ts        # Express server and API routes
└── index.ts         # Application entry point

public/
├── index.html       # Frontend application
├── style.css        # Styling
└── script.js        # Frontend JavaScript

db.json              # User data (encrypted)
audit.json           # Audit logs (append-only)
backups/             # Backup snapshots
```

## Testing Checklist

- [ ] Signup stores encrypted fields (no plaintext)
- [ ] Login succeeds using email index lookup
- [ ] GET /me returns decrypted data after auth
- [ ] POST /me/delete purges PII and updates audit
- [ ] Audit logs contain valid proof hashes
- [ ] Crypto-shred simulation prevents decryption
- [ ] Logger throws on PII detection
- [ ] Backup scrubbing removes PII from snapshots

## Troubleshooting

### Common Issues

1. **"Cannot find module" errors**: Run `bun install` to install dependencies
2. **Port already in use**: Change port in `src/index.ts` or kill existing process
3. **Environment variables missing**: Ensure `.env` file exists with all required keys
4. **Admin login fails**: Use email `admin@example.com` with password `admin123`

### Debug Mode

The debug tab provides access to:
- Database contents (with PII masked)
- Audit log entries
- Crypto-shred simulation

Admin access required for debug features.
