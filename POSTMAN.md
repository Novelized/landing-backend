# Novelized API Postman Collection

![Postman](https://img.shields.io/badge/Postman-FF6C37?logo=postman&logoColor=white)
![API](https://img.shields.io/badge/API-Testing-blue)

## Overview

This document provides comprehensive guidelines for testing the Novelized Landing Backend API using Postman. The included collection and environment files enable streamlined API testing across different environments and scenarios.

## Included Files

| File | Description |
|------|-------------|
| `novelized-api.postman_collection.json` | Collection containing all API endpoints with detailed request configurations |
| `novelized-api.postman_environment.json` | Environment variables for local testing with configurable parameters |

## Installation Guide

### Prerequisites

- [Postman](https://www.postman.com/downloads/) application installed
- Novelized Landing Backend server running locally or in a remote environment

### Import Procedure

1. Launch Postman application
2. Navigate to "Collections" in the sidebar
3. Click the "Import" button in the upper right
4. Select both collection and environment files:
   - `novelized-api.postman_collection.json`
   - `novelized-api.postman_environment.json`
5. Confirm the import

## Configuration

### Environment Setup

1. Click on "Environments" in the Postman sidebar
2. Select "Novelized API - Local" from the environment dropdown
3. Verify and adjust the following variables:

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `base_url` | `http://localhost:3000` | Base URL of the API server |
| `verification_token` | Empty | Placeholder for email verification tokens |

4. Click "Save" to apply changes

## Testing Procedures

### 1. Health Check Endpoint

**Purpose**: Verify API and database connectivity

1. Select "Health Check" request from the collection
2. Click "Send"
3. Expected response (200 OK):
   ```json
   {
       "status": "ok",
       "database": "ok",
       "timestamp": "2024-04-10T14:00:00Z"
   }
   ```
4. Verify all status fields show "ok"

### 2. Test Endpoint

**Purpose**: Basic server response verification

1. Select "Test" request from the collection
2. Click "Send"
3. Expected response (200 OK):
   ```json
   {
       "message": "Server is responding correctly!"
   }
   ```

### 3. Email Signup Flow

**Purpose**: Test the complete signup and verification flow

#### Step 1: Sign Up

1. Select "Sign Up" request
2. Modify the request body with test data:
   ```json
   {
       "name": "Test User",
       "email": "test.user@example.com"
   }
   ```
3. Click "Send"
4. Expected response (201 Created):
   ```json
   {
       "message": "Successfully signed up! Please check your email to verify your address."
   }
   ```
5. Check the server logs for the verification token if email sending is disabled

#### Step 2: Email Verification

1. Obtain the verification token:
   - From the verification email link (`token` query parameter), or
   - From server logs during development
2. Set the `verification_token` environment variable with the token value
3. Select "Verify Email" request
4. Click "Send"
5. Expected response (200 OK):
   ```json
   {
       "message": "Email verified successfully! Thank you for signing up for Novelized updates."
   }
   ```

## Multi-Environment Testing

### Creating Additional Environments

1. Click "Environments" in the sidebar
2. Click "+" to create a new environment (e.g., "Novelized API - Production")
3. Add the same variables as in the local environment:
   - `base_url`: Set to production URL (e.g., `https://api.novelized.com`)
   - `verification_token`: Leave empty initially
4. Click "Save"

### Environment Switching

1. Use the environment dropdown in the upper right corner
2. Select the appropriate environment for testing (Local/Staging/Production)
3. All requests will automatically use the selected environment's variables

## Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Connection errors | Server not running | Start the server or check the `base_url` |
| 404 Not Found | Incorrect endpoint URL | Verify endpoint paths in the collection |
| 400 Bad Request | Invalid request body | Check JSON format and required fields |
| 500 Server Error | Database or server issues | Check server logs for details |
| Email verification failures | Invalid token | Ensure token is correctly copied from email |

## Security Notes

- Do not commit environment files with production credentials to source control
- For production testing, use test accounts only
- API keys and tokens should be kept confidential

## Maintenance

As the API evolves, this collection should be updated to reflect changes:

1. Export the updated collection from Postman
2. Replace the existing JSON file
3. Update this documentation to reflect new endpoints or parameters

---

For questions or support, please contact the Novelized development team.

*Last updated: April 10, 2024* 