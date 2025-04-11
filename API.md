# Novelized API Documentation

## Overview

The Novelized API provides endpoints for managing user signups and email verifications. This document describes all available endpoints, their requirements, and expected responses.

## Base URL

```
https://api.novelized.online
```

## Authentication

Currently, the API does not require authentication for its endpoints. However, all sensitive operations (like email verification) use secure tokens.

## Endpoints

### 1. Health Check

**GET** `/health`

Check if the API is running and healthy.

#### Response

```json
{
    "status": "ok",
    "timestamp": "2025-04-11T05:49:40Z"
}
```

### 2. Sign Up

**POST** `/signup`

Register a new user for updates.

#### Request Body

```json
{
    "name": "John Doe",
    "email": "john@example.com"
}
```

#### Requirements
- `name`: String, required, max 100 characters
- `email`: String, required, valid email format

#### Response

Success (200 OK):
```json
{
    "message": "Signup successful. Please check your email to verify your address."
}
```

Error (400 Bad Request):
```json
{
    "error": "Invalid email format"
}
```

### 3. Verify Email

**GET** `/verify`

Verify a user's email address using a verification token.

#### Query Parameters
- `token`: String, required, verification token received via email

#### Response

Success (200 OK):
```json
{
    "message": "Email verified successfully"
}
```

Error (400 Bad Request):
```json
{
    "error": "Invalid or expired verification token"
}
```

### 4. Get All Signups

**GET** `/signups`

Retrieve all verified signups.

#### Query Parameters
- `sort`: String, optional, sort field (name, email, created_at)
- `order`: String, optional, sort order (asc, desc)

#### Response

Success (200 OK):
```json
[
    {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "name": "John Doe",
        "email": "john@example.com",
        "is_verified": true,
        "is_active": true,
        "created_at": "2025-04-11T05:49:40Z"
    }
]
```

## Error Handling

All endpoints follow a consistent error response format:

```json
{
    "error": "Error message describing what went wrong"
}
```

Common HTTP status codes:
- 200: Success
- 400: Bad Request (invalid input)
- 500: Internal Server Error

## Rate Limiting

The API implements rate limiting to prevent abuse:
- 100 requests per minute per IP address
- 1000 requests per hour per IP address

## Data Encryption

Sensitive fields in the database are encrypted:
- Email addresses
- Verification tokens

## Email Templates

The API sends HTML emails with the following templates:
1. Verification Email
   - Subject: "Verify your Novelized signup"
   - Contains: Logo, verification link, and welcome message

## Environment Variables

Required environment variables for the API:
```env
# Database
DATABASE_URL=postgres://user:password@host:5432/dbname
POSTGRES_PASSWORD=your_secure_password

# Application
ENCRYPTION_KEY=your_encryption_key
APP_URL=https://your-domain.com

# SMTP
SMTP_FROM=contact@your-domain.com
SMTP_HOST=smtp.your-domain.com
SMTP_PORT=587
SMTP_USER=your-smtp-username
SMTP_PASS=your-smtp-password
```

## Database Schema

```sql
CREATE TABLE signups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    is_verified BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Security Considerations

1. All sensitive data is encrypted at rest
2. Email verification tokens are single-use and expire
3. Rate limiting is implemented to prevent abuse
4. Input validation is performed on all endpoints
5. Database queries use parameterized statements to prevent SQL injection

## Deployment

The API is designed to run in a Docker container with PostgreSQL. See the `docker-compose.yml` and `Dockerfile` for deployment details.

## Monitoring

The API includes built-in logging for:
- Request/response cycles
- Database operations
- Email sending
- Error conditions

## Support

For support or questions, please contact:
- Email: contact@novelized.online
- Documentation: https://novelized.online/docs