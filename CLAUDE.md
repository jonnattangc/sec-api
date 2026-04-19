# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Flask-based OAuth/JWT authentication API (`sec-api`) that serves as a security layer for internal services. The API manages user authentication, JWT token lifecycle, and integrates with a MySQL database for credential storage.

## Architecture

### Core Components

- **server.py**: Main Flask application with OAuth endpoints (`/oauth/login`, `/oauth/refresh`, `/oauth/validate`, `/oauth/logout`). Handles JWT token generation and validation. Uses Flask-JWT-Extended for token management and Flask-CORS for cross-origin requests. Swagger documentation available at `/apidocs/`.

- **security.py**: `Security` class manages all database interactions for authentication:
  - User credential verification via bcrypt password hashing
  - JWT token lifecycle (create, store, revoke, validate)
  - API key client lookup
  - Token refresh and revocation tracking

- **checker.py**: `Checker` class provides system health checks:
  - Database connectivity validation
  - Memory, disk, and CPU usage monitoring (via psutil)
  - System uptime tracking

- **coordinator.py**: `Coordinator` class handles deposit processing workflows:
  - Processes deposit notifications from external systems
  - Notifies middleware about deposit updates via HTTP requests
  - Manages bank account queries
  - Sends notifications to Slack
  - Contains `Deposit` class for parsing deposit data

- **utils.py**: Utility classes:
  - `Banks`: Loads bank configurations from JSON (`app/static/bank/banks.json`)
  - `Deposits`: Database operations for deposit records
  - `Cipher`: AES encryption/decryption utilities

### Database Schema (MySQL)

- `oauth`: User credentials with username, password (hashed), role, status, last_login
- `clients`: API clients with id, company, apikey, mail credentials
- `user_jwt`: JWT token tracking with id (jti), user, token, refresh_id, status, create_at
- `deposits`: Financial transaction records

### Authentication Flow

1. Client sends credentials + x-api-key header to `/oauth/login`
2. API key verified against `clients` table
3. User credentials verified via bcrypt in `oauth` table
4. JWT access token and refresh token generated
5. Tokens stored in `user_jwt` table
6. Client receives tokens with expiration (default: 300 seconds, configurable via `EXPIRES_TOKEN_IN_SECONDS`)

## Environment Variables

```bash
# Database connection
HOST_BD=          # MySQL host
PORT_BD=          # MySQL port (default: 3306)
USER_BD=          # MySQL user
PASS_BD=          # MySQL password
SCHEMA_BD=        # Database schema name

# JWT Configuration
EXPIRES_TOKEN_IN_SECONDS=300        # Access token TTL
SECRET_KEY_JWT=super-secret-key-aca-debe-ir  # JWT signing key (CHANGE IN PRODUCTION)

# API Configuration
CONTEXT_PATH=/oauth              # OAuth endpoint prefix

# External Services
BEARER_MIDDLEWARE=    # Bearer token for middleware notifications
NOTIFICATION_URL=     # Middleware URL for deposit notifications
TRANSBOT_ID=          # Transbot identifier for deposit processing
SLACK_NOTIFICATION=   # Slack webhook URL for notifications

# Encryption
AES_KEY=          # AES encryption key for cipher operations
```

Load via `envs/security.env` file (referenced in docker-compose.yml).

## Development Commands

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask app locally (requires port as argument)
python app/server.py 8079

# The app will start with debug=True and listen on 0.0.0.0:8079
```

### Docker

```bash
# Build the Docker image
docker build -t security:prd .

# Run with docker-compose (loads envs/security.env)
docker-compose up -d

# View logs
docker-compose logs -f test-api

# Stop containers
docker-compose down
```

### Testing Endpoints

```bash
# Login - requires x-api-key header
curl -X POST http://localhost:8079/oauth/login \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# Validate token - requires JWT Bearer token
curl -X GET http://localhost:8079/oauth/validate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "x-api-key: YOUR_API_KEY"

# Refresh token
curl -X GET http://localhost:8079/oauth/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN"

# Logout
curl -X DELETE http://localhost:8079/oauth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Key Implementation Details

### Security Considerations

- **Password hashing**: Uses werkzeug's `generate_password_hash` and `check_password_hash` (bcrypt-based)
- **Token storage**: JWT tokens persisted in database for revocation tracking
- **CORS**: Restricted to specific domains: dev.jonnattan.com, api.jonnattan.cl, www.jonna.cl, docs.jonna.cl
- **Secret key**: Default value in code must be changed via `SECRET_KEY_JWT` env var in production

### Deposit Processing

The Coordinator processes deposit updates in two scenarios:
1. **Bank deposits**: Received via `/notify/bank_deposits_update`, notifies middleware
2. **Dreams platform**: Received via `/notify/dreams/*` paths, sends Slack notifications

Coordinator evaluates date ranges for bank queries and formats deposit data for downstream systems.

### Error Handling

- Import errors gracefully handled with informative exit codes (-2 for import errors)
- Database connection failures logged but don't halt app startup
- All database operations wrapped in try-except with rollback on failure
- JWT exceptions return 401 with descriptive error messages

### Logging

- Uses Python logging to stdout (compatible with Docker container logging)
- Log format: `%(asctime)s %(levelname)s : %(message)s`
- Logger named 'HTTP' for all Flask endpoint logging
- Info level by default

## Common Development Tasks

### Adding a New OAuth Endpoint

1. Define route in server.py with `@app.post()` or `@app.get()`
2. Add `@jwt_required()` decorator if authentication needed
3. Use `get_jwt_identity()` to get username from token
4. Create Security instance for database operations
5. Delete Security instance when done (closes DB connection)
6. Return JSON response with appropriate HTTP status

### Modifying Authentication Rules

Changes go in `security.py`:
- `verify_credentials()`: User login logic
- `is_token_valid()`: Token validation logic
- `is_token_revoked()`: Token revocation tracking
- User role checking: Modify role extraction in JWT claims

### Testing Database Connectivity

Use `Checker.get_info()` and `Checker.is_connect()` to validate database setup. Returns detailed system and database information.

## Debugging Notes

- Check `SCHEMA_BD` environment variable — most connection failures are due to missing database schema
- Token validation requires active entry in `user_jwt` table with status='ACTIVE'
- Refresh tokens use separate `refresh_id` column; access tokens use `id` (jti)
- Deposit processing requires `banks.json` at `app/static/bank/banks.json`
