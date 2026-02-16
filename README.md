# SafeVault

A secure web application for managing sensitive data including user credentials and financial records.

## Features

- **Secure Authentication**: JWT-based authentication with bcrypt password hashing
- **Data Encryption**: AES-256-GCM encryption for sensitive data at rest
- **Input Validation**: Comprehensive validation and sanitization using express-validator
- **Rate Limiting**: Protection against brute-force attacks
- **Security Headers**: Helmet.js for securing HTTP headers
- **CORS Protection**: Configurable CORS policies
- **User Management**: Secure user registration and authentication
- **Credential Management**: Encrypted storage of passwords and credentials
- **Financial Records**: Secure management of financial information

## Security Features

1. **Password Security**
   - Bcrypt hashing with 12 rounds
   - Minimum password requirements enforced
   - Passwords never stored in plain text

2. **Data Encryption**
   - AES-256-GCM encryption for sensitive fields
   - Unique IV and auth tag for each encrypted value
   - Encryption keys stored securely in environment variables

3. **Authentication & Authorization**
   - JWT tokens with configurable expiration
   - Secure token validation
   - User session management

4. **API Security**
   - Rate limiting on all endpoints
   - Strict rate limiting on authentication endpoints
   - Input validation and sanitization
   - SQL/NoSQL injection prevention

5. **Security Headers**
   - Content Security Policy
   - X-Frame-Options
   - X-Content-Type-Options
   - And more via Helmet.js

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jrigo23/SafeVault.git
   cd SafeVault
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   ```

4. Configure your `.env` file with secure values:
   - Generate a secure JWT secret (minimum 32 characters)
   - Generate a secure encryption key (64-character hex string)
   - Configure your MongoDB URI
   - Set other configuration options as needed

5. Generate secure keys:
   ```bash
   # Generate JWT secret (32+ characters)
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   
   # Generate encryption key (32 bytes = 64 hex characters)
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm start
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/profile` - Get user profile (requires authentication)

### Credentials
- `POST /api/credentials` - Create a new credential (requires authentication)
- `GET /api/credentials` - Get all credentials (requires authentication)
- `GET /api/credentials/:id` - Get specific credential (requires authentication)
- `PUT /api/credentials/:id` - Update credential (requires authentication)
- `DELETE /api/credentials/:id` - Delete credential (requires authentication)

### Financial Records
- `POST /api/financial` - Create a new financial record (requires authentication)
- `GET /api/financial` - Get all financial records (requires authentication)
- `GET /api/financial/:id` - Get specific financial record (requires authentication)
- `PUT /api/financial/:id` - Update financial record (requires authentication)
- `DELETE /api/financial/:id` - Delete financial record (requires authentication)

## Security Considerations

1. **Environment Variables**: Never commit `.env` file to version control
2. **HTTPS**: Always use HTTPS in production
3. **Database Security**: Use strong MongoDB authentication and network isolation
4. **Key Rotation**: Regularly rotate encryption keys and JWT secrets
5. **Backup**: Implement secure backup strategies for encrypted data
6. **Monitoring**: Monitor for suspicious activity and failed login attempts
7. **Updates**: Keep all dependencies up to date

## License

ISC