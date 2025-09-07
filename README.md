# rs-passkey-auth

A secure authentication service using WebAuthn passkeys and PASETO tokens, built with Rust and Axum.

## Features

- **WebAuthn Authentication**: Full support for passwordless passkeys
- **PASETO v4 Tokens**: Secure tokens with Ed25519 cryptography
- **RESTful API**: Well-documented endpoints with Swagger UI
- **PostgreSQL Database**: Robust and reliable storage
- **Redis Cache**: Efficient session and token blacklist management
- **Containerization**: Complete setup with Docker and Docker Compose
- **Configurable CORS**: Support for multi-origin applications
- **Structured Logging**: Complete operation tracing
- **Monitoring**: Prometheus metrics for observabilit

## Tech Stack

- **Rust** - Programming language
- **Axum** - Async web framework
- **WebAuthn-rs** - WebAuthn implementation
- **PASETO** - Secure authentication tokens
- **PostgreSQL** - Primary database
- **Redis** - Cache and session management
- **Docker** - Containerization
- **Prometheus** - Metrics and monitoring
- **Swagger UI** - Interactive API documentation

## Prerequisites

- Docker and Docker Compose
- Rust 1.89+ (for local development)
- Git

## Quick Start

### 1. Clone the repository

```bash
git clone <repository-url>
cd rs-passkey-auth
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit the `.env` file with your configurations:

```env
# PostgreSQL Database
DB_HOST=postgres
DB_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=passkey_db

# Redis
REDIS_URL=redis://redis:6379

# WebAuthn
WEBAUTHN_RP_NAME=your-app-name
URL_BACKEND=http://localhost:8080
ORIGIN_FRONTEND=http://localhost:3000

# JWT Secret (generate a secure key of at least 32 characters)
JWT_SECRET_KEY=your_very_long_and_secure_secret_key
```

### 3. Start the services

```bash
docker-compose up -d
```

The service will be available at:
- **API**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui
- **Prometheus metrics**: http://localhost:8080/metrics

### Complete Documentation

Visit http://localhost:8080/swagger-ui for complete interactive documentation with examples and real-time testing.

## Security

- **Ed25519 Cryptography**: PASETO tokens with secure digital signatures
- **WebAuthn Standard**: Standards-compliant passwordless authentication
- **Token Blacklisting**: Secure refresh token invalidation
- **Configurable CORS**: Cross-origin protection
- **Input Validation**: Rigorous validation of all inputs
- **Error Handling**: Secure error handling without information leakage
