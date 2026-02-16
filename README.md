# SafeVault

A secure ASP.NET Core web application for managing sensitive data including user credentials and financial records with comprehensive authentication and authorization.

## Security Features

### Authentication & Authorization
✅ **ASP.NET Core Identity Integration**
- Modern, secure authentication framework
- Email-based user verification
- Password reset functionality
- Two-factor authentication (2FA) support
- Account lockout after 5 failed attempts (15-minute lockout)

✅ **Role-Based Authorization (RBAC)**
- Admin role - Full system access and user management
- User role - Manage own financial records
- Guest role - Read-only access
- Fine-grained permission control

✅ **Claims-Based Authorization**
- `CanManageFinancials` - Permission to create/update/delete financial records
- `CanViewReports` - Permission to view financial reports
- `CanManageUsers` - Permission to manage other users (admin only)

✅ **Resource-Based Authorization**
- Users can only access their own financial records
- Admins have access to all records
- Custom authorization handlers for financial data

✅ **Input Validation**
- Custom validation attributes for SQL injection prevention
- XSS attack prevention validators
- Data annotations on all models
- Both client-side and server-side validation

✅ **SQL Injection Prevention**
- Entity Framework Core with parameterized queries
- No raw SQL concatenation
- Secure query practices throughout

✅ **XSS Prevention**
- Automatic output encoding in Razor views
- Content Security Policy (CSP) headers
- Input sanitization validators

✅ **Password Security**
- ASP.NET Core Identity password hashing (PBKDF2 with HMAC-SHA256)
- BCrypt password hashing also available (work factor: 12)
- Strong password requirements (8+ chars, uppercase, lowercase, number, special char)
- Account lockout after 5 failed login attempts (15-minute lockout)
- Password history and complexity enforcement

✅ **Data Encryption**
- AES-256 encryption for financial records
- Random IV generation for each encryption operation
- Encrypted sensitive data at rest
- Secure key management (no hardcoded keys)
- IV prepended to ciphertext for secure decryption

✅ **Security Headers**
- Content-Security-Policy
- X-Frame-Options (DENY)
- X-Content-Type-Options (nosniff)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

✅ **Additional Security**
- HTTPS enforcement
- Anti-forgery tokens on all forms
- Secure session management
- HttpOnly and Secure cookie flags

## Technical Stack

- **Framework**: ASP.NET Core 8.0
- **Authentication**: ASP.NET Core Identity 8.0
- **ORM**: Entity Framework Core 8.0
- **Database**: SQLite (easily switchable to SQL Server)
- **Testing**: NUnit 3
- **Password Hashing**: ASP.NET Core Identity (PBKDF2), BCrypt.Net-Next
- **Encryption**: AES-256 (System.Security.Cryptography)

## Project Structure

```
SafeVault/
├── SafeVault.Web/              # Main web application
│   ├── Controllers/            # MVC controllers
│   │   ├── UserController.cs   # User registration/login/2FA
│   │   ├── FinancialController.cs # Financial records CRUD
│   │   ├── AdminController.cs  # User management (Admin only)
│   │   └── HomeController.cs
│   ├── Models/                 # Data models
│   │   ├── ApplicationUser.cs  # Identity user model
│   │   ├── User.cs            # Legacy user model
│   │   ├── UserCredential.cs  # Legacy credentials
│   │   ├── FinancialRecord.cs
│   │   ├── ViewModels.cs
│   │   └── AccountViewModels.cs # Account management models
│   ├── Data/                   # Database context
│   │   ├── SafeVaultDbContext.cs
│   │   └── DbInitializer.cs   # Role and admin seeding
│   ├── Services/               # Business logic
│   │   ├── EncryptionService.cs
│   │   ├── PasswordHasher.cs
│   │   └── EmailSender.cs     # Email notifications
│   ├── Authorization/          # Authorization policies
│   │   ├── Requirements.cs
│   │   └── FinancialRecordAuthorizationHandler.cs
│   ├── Validators/             # Custom validators
│   │   └── SecurityValidators.cs
│   └── Views/                  # Razor views
│       ├── User/              # Login, Register, 2FA
│       ├── Financial/         # Financial records
│       └── Admin/             # Admin panel
└── SafeVault.Tests/            # NUnit test project
    ├── TestInputValidation.cs
    ├── TestPasswordHashing.cs
    ├── TestEncryption.cs
    ├── TestDatabaseSecurity.cs
    └── TestAuthorization.cs   # Authorization tests
```

## Getting Started

### Prerequisites

- .NET 8.0 SDK or later
- Any IDE that supports .NET (Visual Studio, VS Code, Rider)

### Running the Application

1. Clone the repository:
```bash
git clone https://github.com/jrigo23/SafeVault.git
cd SafeVault
```

2. Build the solution:
```bash
dotnet build
```

3. Run the tests:
```bash
dotnet test
```

4. Run the web application:
```bash
cd SafeVault.Web
dotnet run
```

5. Navigate to `https://localhost:5001` in your browser

### Database

The application uses SQLite by default with the database file created at `SafeVault.Web/safevault.db`.

#### Default Admin Account

On first run, a default admin account is created:
- **Username**: admin
- **Email**: admin@safevault.com  
- **Password**: Admin@123456

⚠️ **IMPORTANT**: Change this password immediately after first login in production environments!

To switch to SQL Server, update the connection string in `appsettings.json`:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=SafeVault;Trusted_Connection=True;"
}
```

And update `Program.cs` to use SQL Server:

```csharp
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
```

## Features

### Authentication & User Management
- **Registration**: Secure user registration with email confirmation required
- **Email Confirmation**: Token-based email verification before first login
- **Login**: Multi-factor authentication with account lockout protection
- **Password Reset**: Secure password reset workflow via email
- **Two-Factor Authentication (2FA)**: Optional email-based 2FA for enhanced security
- **Session Management**: Secure cookie-based authentication with sliding expiration

### Authorization & Access Control
- **Role-Based Access**: Admin, User, and Guest roles with different permissions
- **Claims-Based Policies**: Fine-grained permissions for specific operations
- **Resource-Based Authorization**: Users can only access their own data (except Admins)
- **Admin Panel**: User management, role assignment, account locking/unlocking

### Financial Records
- **Create**: Add new financial records with encrypted sensitive data
- **Read**: View financial records (decrypted for authorized users)
- **Search**: Search records by description (SQL injection safe)
- **Delete**: Remove records with confirmation

## Security Testing

The application includes comprehensive security tests covering all critical security aspects:

### Input Validation Tests (8 tests)
Located in `SafeVault.Tests/TestInputValidation.cs`:

1. **TestForSQLInjection_DetectsSQLKeywords** - Validates detection of SQL injection attempts including `' or '1'='1`, `DROP TABLE`, `UNION SELECT`, and SQL comments
2. **TestForSQLInjection_AllowsValidInput** - Ensures legitimate input like usernames, emails, and product names are accepted
3. **TestForXSS_DetectsScriptTags** - Detects XSS attacks including `<script>` tags, `javascript:` protocol, event handlers, and data URIs
4. **TestForXSS_AllowsValidInput** - Allows safe text input without HTML/JavaScript
5. **TestNoMaliciousInput_DetectsDangerousCharacters** - Identifies dangerous characters like `<>`, quotes, and SQL comment sequences
6. **TestNoMaliciousInput_AllowsCleanInput** - Permits clean alphanumeric input with standard punctuation
7. **TestSQLInjection_CommonBypassAttempts** - Tests against advanced SQL injection bypass techniques including `UNION ALL SELECT` and comment-based attacks
8. **TestXSS_EventHandlerInjection** - Validates detection of XSS via event handlers (`onerror`, `onload`, `onclick`, `onmouseover`, `onfocus`)

### Password Hashing Tests (8 tests)
Located in `SafeVault.Tests/TestPasswordHashing.cs`:

1. **HashPassword_CreatesNonEmptyHash** - Verifies BCrypt hash generation produces non-empty strings with proper length
2. **HashPassword_CreatesDifferentHashesForSamePassword** - Confirms salting creates unique hashes for identical passwords
3. **VerifyPassword_ReturnsTrueForCorrectPassword** - Validates correct password verification
4. **VerifyPassword_ReturnsFalseForIncorrectPassword** - Ensures incorrect passwords are rejected
5. **VerifyPassword_ReturnsFalseForEmptyPassword** - Rejects empty password attempts
6. **HashPassword_ThrowsExceptionForEmptyPassword** - Prevents hashing of empty passwords
7. **HashPassword_WorksWithSpecialCharacters** - Handles special characters in passwords (`!@#$%^&*()`)
8. **HashPassword_WorksWithLongPasswords** - Supports long password strings (50+ characters)

### Encryption Tests (9 tests)
Located in `SafeVault.Tests/TestEncryption.cs`:

1. **Encrypt_CreatesNonEmptyEncryptedString** - Verifies AES-256 encryption produces non-empty ciphertext different from plaintext
2. **Decrypt_ReturnsOriginalPlainText** - Validates encryption/decryption round-trip accuracy
3. **Encrypt_HandlesEmptyString** - Properly handles empty string encryption/decryption
4. **Encrypt_WorksWithSpecialCharacters** - Encrypts/decrypts special characters correctly
5. **Encrypt_WorksWithNumbers** - Handles numeric strings
6. **Encrypt_WorksWithLongStrings** - Successfully encrypts strings up to 1000+ characters
7. **Encrypt_ProducesDifferentOutputForDifferentInput** - Different plaintext produces different ciphertext
8. **Encrypt_ProducesDifferentOutputForSameInput** - Random IV ensures same plaintext produces different ciphertext each time
9. **Encrypt_DataIsNotStoredInPlainText** - Confirms encrypted data doesn't contain plaintext fragments

### Database Security Tests (7 tests)
Located in `SafeVault.Tests/TestDatabaseSecurity.cs`:

1. **SQLInjection_PreventedByParameterizedQueries** - Verifies EF Core's parameterized queries block SQL injection attempts
2. **SQLInjection_DropTableAttemptFails** - Confirms `DROP TABLE` injection attempts fail and tables remain intact
3. **PasswordsAreHashedNotPlainText** - Validates passwords are stored as BCrypt hashes, not plaintext
4. **FinancialData_IsEncryptedAtRest** - Ensures sensitive financial data is encrypted in the database
5. **UnionSelectInjectionAttempt_IsBlocked** - Blocks `UNION SELECT` injection attempts in search queries
6. **UserDataIsolation_PreventsUnauthorizedAccess** - Enforces user data isolation (users can't access other users' records)
7. **CascadeDelete_RemovesRelatedData** - Verifies cascade deletion removes related credentials when user is deleted

### Authorization Tests (9 tests)
Located in `SafeVault.Tests/TestAuthorization.cs`:

1. **RoleCreation_SuccessfullyCreatesRole** - Tests ASP.NET Core Identity role creation
2. **UserRoleAssignment_SuccessfullyAssignsRole** - Validates user-to-role assignment functionality
3. **UserClaims_SuccessfullyAddsClaims** - Confirms claims-based authorization (`CanManageFinancials`, `CanViewReports`)
4. **MultipleRoles_UserCanHaveMultipleRoles** - Verifies users can be assigned multiple roles simultaneously
5. **RoleRemoval_SuccessfullyRemovesRole** - Tests role removal from users
6. **PasswordValidation_EnforcesPasswordPolicy** - Ensures weak passwords are rejected (short, no complexity)
7. **PasswordValidation_AcceptsStrongPassword** - Accepts passwords meeting complexity requirements
8. **EmailConfirmation_RequiredForLogin** - Validates email confirmation workflow
9. **TwoFactorAuthentication_CanBeEnabled** - Tests 2FA enablement for users

**Total: 41 tests - All passing! ✅**

## Running Tests

```bash
# Run all tests
dotnet test

# Run with detailed output
dotnet test --verbosity normal

# Run specific test class
dotnet test --filter "ClassName=TestInputValidation"
```

## Configuration

### Encryption Keys

⚠️ **Important Security Notice**:

The application requires an encryption key to be configured. The key **must** be at least 32 characters long.

**For Development:**
The key is pre-configured in `appsettings.Development.json` for local development only.

**For Production:**
1. **Remove** the example key from development settings
2. Store encryption keys in a secure location:
   - Azure Key Vault
   - AWS Secrets Manager
   - Environment variables
   - Secure configuration provider
   - HashiCorp Vault

**Setting via Environment Variable:**
```bash
# Linux/macOS
export Encryption__Key="Your32+CharacterProductionKeyHere"

# Windows
set Encryption__Key=Your32+CharacterProductionKeyHere
```

**Important:** The application will fail to start if no valid encryption key is configured - this is intentional for security.

### Encryption Implementation

This application uses AES-256 encryption with the following security features:
- **Random IV Generation**: Each encryption operation generates a unique initialization vector (IV)
- **IV Storage**: The IV is prepended to the ciphertext for decryption
- **No Static IVs**: Ensures no patterns can be detected in encrypted data
- **Secure Key Management**: Keys are never hardcoded in production code

### Security Headers

Security headers are configured in `Program.cs`:

```csharp
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("Content-Security-Policy", 
        "default-src 'self'; script-src 'self' 'unsafe-inline'; ...");
    // ... other headers
    await next();
});
```

## OWASP Compliance

This application follows OWASP Top 10 security guidelines:

1. ✅ **Injection** - Parameterized queries, input validation
2. ✅ **Broken Authentication** - Secure password hashing, account lockout
3. ✅ **Sensitive Data Exposure** - Encryption at rest, HTTPS
4. ✅ **XML External Entities (XXE)** - Not applicable (no XML processing)
5. ✅ **Broken Access Control** - User data isolation, session validation
6. ✅ **Security Misconfiguration** - Secure headers, HTTPS enforcement
7. ✅ **Cross-Site Scripting (XSS)** - Output encoding, CSP headers
8. ✅ **Insecure Deserialization** - Not applicable
9. ✅ **Using Components with Known Vulnerabilities** - Latest packages
10. ✅ **Insufficient Logging & Monitoring** - Logging implemented

## License

This project is for educational and demonstration purposes.

## Contributing

This is a demonstration project showcasing secure coding practices in ASP.NET Core.
