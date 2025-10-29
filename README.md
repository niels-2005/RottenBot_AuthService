# RottenBot - Authentication Service

## 🎯 Overview

This repository provides a authentication microservice for the RottenBot project. Built with *FastAPI*, this service handles user registration, login, logout, and access token renewal with security practices and comprehensive observability.

The Authentication Service was developed to simulate real-world authentication scenarios, providing secure access control for the RottenBot_InferenceService and other microservices in the RottenBot ecosystem. Its not a complete production-ready solution!

## ✨ Key Features

### Security & Authentication
- ✅ **Secure Password Hashing** using Passlib for credential storage
- ✅ **JWT-Based Authentication** with access and refresh tokens
- ✅ **Token Lifecycle Management** - Access tokens (60 minutes), Refresh tokens (7 days)
- ✅ **Token Revocation** via Redis blocklist on logout
- ✅ **Pydantic Validation** for all API endpoints
- ✅ **Email Uniqueness** enforcement for user accounts

### Database Architecture
- **PostgreSQL** for persistent user data storage with UUID-based primary keys
- **Redis** for high-performance token blocklist management
- **SQLModel** for type-safe database operations with async support
- **User Roles** system (e.g. admin, user)

### Observability & Monitoring
- 📊 **OpenTelemetry Tracing** for distributed tracing across all endpoints
- 📈 **Latency Metrics** to measure endpoint performance
- 📊 **API Call Counters** to track usage patterns
- 📝 **Structured Logging** for all critical operations
- 🔍 **Bottleneck Detection** through detailed span tracking

### API Endpoints
- `POST /signup` - User registration with validation when email exists
- `POST /login` - User login authentication with JWT token generation
- `GET /logout` - Token revocation, so it can no longer be used for other microservices
- `GET /refresh_token` - Access token renewal using refresh tokens

## 🗄️ Database Schema

### User Accounts Table

```python
class User(SQLModel, table=True):
    __tablename__ = "user_accounts"

    uid: uuid.UUID           # Primary key, auto-generated UUID
    role: str                # User role (default: "user")
    first_name: str          # User's first name
    last_name: str           # User's last name
    is_verified: bool        # Email verification status (default: False)
    email: str               # Unique email address
    password_hash: str       # Hashed password (never stored in plaintext)
    created_at: datetime     # Account creation timestamp
    updated_at: datetime     # Last update timestamp
```

**Note on Email Verification:**  
The `is_verified` field is included for email confirmation workflows. However, actual confirmation emails are not sent in the current implementation. In a production environment, this can be implemented using **FastAPI Mail** with HTML templates for a complete user verification flow.

## 🔐 Token Management

### Access Tokens
- **Lifetime:** 60 minutes (configurable)
- **Purpose:** Authenticate API requests to protected endpoints
- **Auto-Renewal:** Automatically renewed using refresh tokens

### Refresh Tokens
- **Lifetime:** 7 days (configurable)
- **Purpose:** Generate new access tokens without re-authentication

### Token Revocation
When a user logs out:
1. Access token JTI (JWT ID) is added to Redis blocklist
2. User becomes immediately unauthenticated
3. All RottenBot services (e.g., InferenceService) reject the revoked token

**Configuration Note:**  
Token expiry times are example settings and can be adjusted based on security requirements and user experience preferences.

## 📊 API Endpoints Overview

### POST /signup
**Register a new user account**

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePassword123!"
}
```

**Possible Responses:**

#### ✅ 201 Created - User Successfully Registered
User account was created successfully. Note that the user is NOT automatically logged in and must call `/login` to receive tokens.

```json
{
  "message": "User created successfully",
  "user": {
    "uid": "123e4567-e89b-12d3-a456-426614174000",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "created_at": "2025-10-20T12:00:00",
    "updated_at": "2025-10-20T12:00:00"
  }
}
```

#### ❌ 403 Forbidden - Email Already Exists
A user with the provided email address already exists in the database.

```json
{
  "detail": "User with email already exists."
}
```

#### ❌ 500 Internal Server Error - Server Error
An unexpected error occurred during user creation (e.g., database connection failure, password hashing error).

```json
{
  "detail": "Oops. Something went wrong. Please try again later."
}
```

---

### POST /login
**Authenticate and receive tokens**

**Request Body:**
```json
{
  "email": "john.doe@example.com",
  "password": "SecurePassword123!"
}
```

**Possible Responses:**

#### ✅ 200 OK - Login Successful
User credentials are valid. Returns access token (60 min lifetime), refresh token (7 days lifetime), and user details.

```json
{
  "message": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "uid": "123e4567-e89b-12d3-a456-426614174000",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "created_at": "2025-10-20T12:00:00",
    "updated_at": "2025-10-20T12:00:00"
  }
}
```

#### ❌ 401 Unauthorized - Invalid Credentials
Either the email does not exist or the password is incorrect.

```json
{
  "detail": "Invalid email or password"
}
```

#### ❌ 500 Internal Server Error - Server Error
An unexpected error occurred during login (e.g., database connection failure, token generation error).

```json
{
  "detail": "Oops. Something went wrong. Please try again later."
}
```

---

### GET /logout
**Revoke access token and end session**

**Headers:**
```
Authorization: Bearer <access_token>
```

**Possible Responses:**

#### ✅ 200 OK - Logout Successful
Access token was successfully added to the Redis blocklist and is now revoked. User must login again to access protected endpoints.

```json
{
  "message": "Logged Out Successfully"
}
```

#### ❌ 401 Unauthorized - Invalid or Missing Token
The access token is missing, malformed, expired, or already revoked.

```json
{
  "detail": "Token is invalid or expired"
}
```

#### ❌ 500 Internal Server Error - Server Error
An unexpected error occurred while adding the token to the blocklist (e.g., Redis connection failure).

```json
{
  "detail": "Oops. Something went wrong. Please try again later."
}
```

---

### GET /refresh_token
**Obtain a new access token using refresh token**

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Possible Responses:**

#### ✅ 200 OK - Token Refresh Successful
A new access token (60 min lifetime) was successfully generated using the valid refresh token.

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### ❌ 401 Unauthorized - Invalid or Missing Token
The refresh token is missing, malformed, or has been revoked.

```json
{
  "detail": "Token is invalid or expired"
}
```

## 🔍 Observability Features

### Distributed Tracing
Every endpoint is instrumented with **OpenTelemetry spans** tracking:
- Overall endpoint duration
- Database query performance
- Password verification time
- Token generation time
- Redis operations

### Metrics Collection
- **API Call Counter:** Tracks the number of requests per endpoint
- **Latency Measurements:** Records response times in milliseconds
- **Error Rates:** Monitors failed authentication attempts and server errors

### Structured Logging
All operations log relevant information (examples):
```python
logger.info("Endpoint called")
logger.warning("Something weird happened.")
logger.error("Database connection failed.")
```

### Performance Monitoring
Use observability data to:
- Identify slow database queries
- Detect bottlenecks in authentication flow

## 🚀 Quick Start

### Prerequisites
- **Docker & Docker Compose** for service orchestration

### Running with Docker Compose 

```bash
auth_service:
container_name: auth_service
image: nielsscholz/rotten_bot_auth:latest
ports:
    - "8000:8000"
environment:
    # look in the .env.example file for all required environment variables.
    DATABASE_URL: ${DATABASE_URL}
    REDIS_PASSWORD: ${REDIS_PASSWORD}
    REDIS_HOST: ${REDIS_HOST}
    REDIS_PORT: ${REDIS_PORT}
    JWT_SECRET: ${JWT_SECRET}
    JWT_ALGORITHM: ${JWT_ALGORITHM}
    ALLOY_ENDPOINT: ${ALLOY_ENPOINT}
```

## 🤝 Integration with RottenBot Services

This authentication service provides secure access control for:
- **RottenBot_InferenceService** - ML model inference endpoints
- **Other RottenBot microservices** - Future service integrations

All services validate JWT tokens issued by this auth service, ensuring consistent authentication across the entire RottenBot ecosystem.

## 🤖 CI/CD Pipeline

### Current Implementation

This project includes a **simple CI pipeline** that automatically builds and deploys the Docker image to Docker Hub.

**Pipeline Trigger:**
- Runs on every commit to the `main` branch
- Automatically builds the Docker image using the Dockerfile
- Pushes the image to Docker Hub as `nielsscholz/rotten_bot_auth:latest`

### ⚠️ Important Notes

**This is NOT a production-ready pipeline!** The current setup was implemented for simplicity and demonstration purposes.

**Current Limitations:**
- No branch strategy (dev, staging, prod)
- Commits directly to `main` trigger deployment
- No automated testing before deployment
- No security scanning
- No secret detection

## License

This project is part of the RottenBot ecosystem. See the main RottenBot repository for licensing information.


