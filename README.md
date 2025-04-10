# Novelized Landing Backend

![Novelized](https://img.shields.io/badge/Novelized-Landing%20Backend-blue)
![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-336791?logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-green)

A secure, high-performance backend service for the Novelized landing page, built with Go Fiber and PostgreSQL. This service handles email signups and verifications with full end-to-end encryption for all sensitive data.

## Features

- **Secure Email Signup**: Collect and store user information with PGP encryption
- **Email Verification**: Built-in email verification flow with secure token generation
- **Data Encryption**: End-to-end encryption for all personally identifiable information
- **Health Monitoring**: Comprehensive health checks for application and database status
- **Detailed Logging**: Extensive logging with configurable levels

## Architecture

The application follows a clean architecture approach:

- **API Layer**: Go Fiber routes and handlers
- **Service Layer**: Business logic and email functionality
- **Data Layer**: PostgreSQL with encryption/decryption functions
- **Migration System**: Version-controlled database schema changes

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 14+ database
- SMTP server for sending verification emails

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/novelized-landing-backend.git
   cd novelized-landing-backend
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

## Configuration

Configure the application using environment variables in a `.env` file:

```
# Database Configuration
DATABASE_URL=postgres://username:password@localhost:5432/dbname?sslmode=disable

# Application Configuration
PORT=3000
APP_URL=http://localhost:3000
ENCRYPTION_KEY=your-secure-encryption-key

# SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_USER=your-smtp-username
SMTP_PASS=your-smtp-password
SMTP_FROM=noreply@example.com
```

## Database Setup

1. Create a PostgreSQL database:
   ```sql
   CREATE DATABASE novelized_landing;
   ```

2. Run the migrations:
   ```bash
   go run main.go migrate
   ```

## Running the Application

### Development

```bash
go run main.go
```

### Production

```bash
# Build the binary
go build -o novelized-backend

# Run the application
./novelized-backend
```

The server will start on the configured port (default: 3000).

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | /        | Index page |
| GET    | /health  | Health check for the application and database |
| POST   | /signup  | Email signup endpoint |
| GET    | /verify  | Email verification endpoint |
| GET    | /test    | Test endpoint to verify server response |

### Health Check

```
GET http://localhost:3000/health
```

Response:
```json
{
    "status": "ok",
    "database": "ok",
    "timestamp": "2024-04-10T14:00:00Z"
}
```

### Signup

```
POST http://localhost:3000/signup
Content-Type: application/json

{
    "name": "User Name",
    "email": "user@example.com"
}
```

Response:
```json
{
    "message": "Successfully signed up! Please check your email to verify your address."
}
```

### Verification

```
GET http://localhost:3000/verify?token=your-verification-token
```

Response:
```json
{
    "message": "Email verified successfully! Thank you for signing up for Novelized updates."
}
```

## Security Considerations

- All sensitive data (names, emails, tokens) is encrypted in the database
- Only authorized personnel should have access to the database encryption key
- Regular security audits are recommended

## Testing

For API testing, a Postman collection is included. See [POSTMAN.md](POSTMAN.md) for details.

## Troubleshooting

Common issues and solutions:

- **Database connection issues**: Verify your DATABASE_URL configuration
- **Email sending failures**: Check SMTP settings and network connectivity
- **Encryption errors**: Ensure your ENCRYPTION_KEY is set correctly

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

© 2024 Novelized. All rights reserved. 