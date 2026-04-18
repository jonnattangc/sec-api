# Security API - OAuth2 Authentication Server

A lightweight Flask-based OAuth2 JWT authentication server that manages user credentials, API client validation, and JWT token lifecycle. Designed for use as a centralized authentication provider for internal services and microservices.

## Features

- **User Authentication**: Username/password verification with bcrypt hashing
- **JWT Token Management**: Access and refresh token generation with configurable TTL
- **API Key Validation**: Client-based API key authentication
- **Token Revocation**: Track and revoke tokens via token blacklist
- **Token Refresh**: Issue new access tokens using refresh tokens
- **CORS Support**: Configurable cross-origin request handling
- **Swagger Documentation**: Interactive API documentation via Flasgger

## Quick Start

### Prerequisites

- Python 3.10+
- MySQL 5.7+
- Docker & Docker Compose (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sec-api
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file or set environment variables:
   ```bash
   # Database Configuration
   HOST_BD=localhost
   PORT_BD=3306
   USER_BD=root
   PASS_BD=password
   SCHEMA_BD=oauth_db
   
   # JWT Configuration
   SECRET_KEY_JWT=your-super-secret-key-change-in-production
   EXPIRES_TOKEN_IN_SECONDS=300
   
   # API Configuration
   CONTEXT_PATH=/oauth
   ```

4. **Set up the database**
   
   Create the required tables:
   ```sql
   -- Users table
   CREATE TABLE oauth (
     id INT AUTO_INCREMENT PRIMARY KEY,
     username VARCHAR(255) UNIQUE NOT NULL,
     password VARCHAR(255) NOT NULL,
     role VARCHAR(50) DEFAULT 'USER',
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     last_login TIMESTAMP NULL,
     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
   );
   
   -- API Clients table
   CREATE TABLE clients (
     id INT AUTO_INCREMENT PRIMARY KEY,
     company VARCHAR(255) NOT NULL,
     apikey VARCHAR(255) UNIQUE NOT NULL,
     mail_pass VARCHAR(255),
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   
   -- JWT Token tracking table
   CREATE TABLE user_jwt (
     id VARCHAR(255) PRIMARY KEY,
     user VARCHAR(255) NOT NULL,
     token LONGTEXT NOT NULL,
     refresh_id VARCHAR(255),
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY (user) REFERENCES oauth(username)
   );
   ```

5. **Run the server**
   ```bash
   python app/server.py 8079
   ```
   
   The API will be available at `http://localhost:8079`
   
   Swagger documentation available at `http://localhost:8079/apidocs/`

### Docker Deployment

1. **Build the image**
   ```bash
   docker build -t security:prd .
   ```

2. **Run with docker-compose**
   
   Create `envs/security.env`:
   ```
   HOST_BD=db
   PORT_BD=3306
   USER_BD=root
   PASS_BD=rootpassword
   SCHEMA_BD=oauth_db
   SECRET_KEY_JWT=your-secure-key
   EXPIRES_TOKEN_IN_SECONDS=300
   ```
   
   Start the containers:
   ```bash
   docker-compose up -d
   ```

## API Endpoints

### 1. Login
**POST** `/oauth/login`

Authenticate user and obtain JWT tokens.

**Headers:**
```
x-api-key: your_api_key
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "secure_password"
}
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "user": {
    "id": 1,
    "username": "john_doe",
    "role": "user",
    "status": "ACTIVE",
    "last_login": "2026-04-18 15:30:00"
  },
  "client": {
    "id": 1,
    "company": "Acme Corp",
    "status": "ACTIVE"
  }
}
```

**Error Response (401):**
```json
{
  "message": "No autorizado"
}
```

### 2. Validate Token
**GET** `/oauth/validate`

Verify that a token is valid and user has proper access.

**Headers:**
```
Authorization: Bearer {access_token}
x-api-key: your_api_key
```

**Success Response (200):**
```json
{
  "message": "OK"
}
```

**Error Response (401):**
```json
{
  "message": "Token no autorizado"
}
```

### 3. Refresh Token
**GET** `/oauth/refresh`

Generate a new access token using a valid refresh token.

**Headers:**
```
Authorization: Bearer {refresh_token}
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "user": {
    "id": 1,
    "username": "john_doe",
    "role": "user",
    "status": "ACTIVE"
  },
  "client": {
    "id": 1,
    "company": "Acme Corp"
  }
}
```

**Error Response (401):**
```json
{
  "message": "Tu sesión ha expirado"
}
```

### 4. Logout
**DELETE** `/oauth/logout`

Revoke the current access token and invalidate the session.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Success Response (200):**
```json
{
  "message": "Sesión cerrada con exito"
}
```

**Error Response (401):**
```json
{
  "message": "No se encontró un token de acceso. Debes iniciar sesión."
}
```

## Authentication Flow

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 1. POST /oauth/login (username + password + x-api-key)
       ↓
┌────────────────────┐
│  Validate API Key  │
└────────┬───────────┘
         │
         │ 2. Check client in clients table
         ↓
┌────────────────────────┐
│ Verify Credentials     │
└────────┬───────────────┘
         │
         │ 3. Check user in oauth table, verify password hash
         ↓
┌────────────────────┐
│ Generate JWT Pair  │
└────────┬───────────┘
         │
         │ 4. Create access_token + refresh_token
         ↓
┌────────────────────────────┐
│ Store Tokens in Database   │
└────────┬───────────────────┘
         │
         │ 5. Save tokens in user_jwt table
         ↓
┌─────────────────────────┐
│ Return Tokens & User    │
│ Info to Client          │
└────────┬────────────────┘
         │
         │ 200 OK + tokens
         ↓
┌─────────────┐
│   Client    │
└─────────────┘
```

## Usage Examples

### Using cURL

**Login:**
```bash
curl -X POST http://localhost:8079/oauth/login \
  -H "x-api-key: your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "secure_password"
  }'
```

**Validate Token:**
```bash
curl -X GET http://localhost:8079/oauth/validate \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "x-api-key: your_api_key_here"
```

**Refresh Token:**
```bash
curl -X GET http://localhost:8079/oauth/refresh \
  -H "Authorization: Bearer refresh_token_here"
```

**Logout:**
```bash
curl -X DELETE http://localhost:8079/oauth/logout \
  -H "Authorization: Bearer access_token_here"
```

### Using Python Requests

```python
import requests

BASE_URL = "http://localhost:8079"
API_KEY = "your_api_key_here"

# 1. Login
login_response = requests.post(
    f"{BASE_URL}/oauth/login",
    headers={"x-api-key": API_KEY},
    json={
        "username": "john_doe",
        "password": "secure_password"
    }
)

tokens = login_response.json()
access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]

# 2. Validate Token
validate_response = requests.get(
    f"{BASE_URL}/oauth/validate",
    headers={
        "Authorization": f"Bearer {access_token}",
        "x-api-key": API_KEY
    }
)

print(validate_response.json())

# 3. Refresh Token
refresh_response = requests.get(
    f"{BASE_URL}/oauth/refresh",
    headers={"Authorization": f"Bearer {refresh_token}"}
)

new_access_token = refresh_response.json()["access_token"]

# 4. Logout
logout_response = requests.delete(
    f"{BASE_URL}/oauth/logout",
    headers={"Authorization": f"Bearer {access_token}"}
)

print(logout_response.json())
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST_BD` | - | MySQL database host |
| `PORT_BD` | 3306 | MySQL database port |
| `USER_BD` | - | MySQL database user |
| `PASS_BD` | - | MySQL database password |
| `SCHEMA_BD` | - | Database schema name |
| `SECRET_KEY_JWT` | `super-secret-key-aca-debe-ir` | JWT signing key (⚠️ change in production) |
| `EXPIRES_TOKEN_IN_SECONDS` | 300 | Access token expiration time in seconds |
| `CONTEXT_PATH` | `/oauth` | Base path for OAuth endpoints |

### CORS Configuration

The API allows requests from the following origins:
- `https://dev.jonnattan.com`
- `https://api.jonnattan.cl`
- `https://www.jonna.cl`
- `https://www.jonnattan.cl`
- `https://api.jonna.cl`
- `https://docs.jonna.cl`
- `https://docs.jonnattan.cl`

To modify, edit the `cors = CORS(...)` line in `app/server.py`.

## Security Considerations

### Password Security
- Passwords are hashed using **bcrypt** via werkzeug's `generate_password_hash()`
- Plain-text passwords are never stored in the database
- Implement password strength requirements in your client application

### JWT Security
- Tokens are signed with a secret key (`SECRET_KEY_JWT`)
- **⚠️ Change the default secret key in production**
- Access tokens have configurable TTL (default: 300 seconds / 5 minutes)
- Refresh tokens have longer validity and are stored in the database for revocation tracking
- Tokens are invalidated when users log out

### API Key Management
- API keys are stored in the `clients` table
- Each client company has one API key
- API keys are required for `/login` and `/validate` endpoints
- Implement key rotation policies

### Best Practices

1. **Use HTTPS in production** - Tokens are sensitive and must be transmitted securely
2. **Short access token TTL** - Use short expiration times and refresh tokens for longer sessions
3. **Secure secret storage** - Use environment variables or secrets management system for `SECRET_KEY_JWT`
4. **Database security** - Limit database access, use strong credentials, enable SSL/TLS for DB connections
5. **Rate limiting** - Implement rate limiting on login endpoint to prevent brute-force attacks
6. **Logging** - Monitor authentication logs for suspicious activity

## Development

### Project Structure

```
sec-api/
├── app/
│   ├── server.py          # Main Flask application and OAuth endpoints
│   ├── security.py        # Authentication and token management logic
│   ├── checker.py         # Health check utilities
│   ├── coordinator.py     # External integrations (not OAuth-related)
│   └── utils.py           # Helper utilities
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container image definition
├── docker-compose.yml    # Docker Compose configuration
├── CLAUDE.md             # Claude Code guidance
└── README.md             # This file
```

### Running Tests

Create a test client in the `clients` table:

```sql
INSERT INTO clients (company, apikey) VALUES ('Test Company', 'test_api_key_123');
```

Create a test user in the `oauth` table:

```sql
INSERT INTO oauth (username, password, role) 
VALUES ('testuser', '...bcrypt_hash...', 'user');
```

Use the provided cURL or Python examples to test the endpoints.

### Logging

The application logs all authentication events to stdout with format:
```
2026-04-18 15:30:00,123 INFO : Cliente: Acme Corp
```

View logs in Docker:
```bash
docker-compose logs -f test-api
```

## Troubleshooting

### Database Connection Issues
- Verify MySQL is running and accessible
- Check environment variables (`HOST_BD`, `PORT_BD`, `USER_BD`, `PASS_BD`, `SCHEMA_BD`)
- Ensure the database schema exists and tables are created

### Authentication Failures
- Verify API key exists in `clients` table and is correct
- Ensure user exists in `oauth` table with status='ACTIVE'
- Confirm password hash is valid (use bcrypt when creating test users)

### Token Validation Fails
- Ensure token exists in `user_jwt` table with status='ACTIVE'
- Verify token hasn't expired (`create_at + EXPIRES_TOKEN_IN_SECONDS`)
- Check that the token wasn't revoked by logout

### Port Already in Use
Change the port when running locally:
```bash
python app/server.py 8080
```

## Support

For issues, questions, or contributions, please open an issue in the repository.

## License

[Add your license information here]
