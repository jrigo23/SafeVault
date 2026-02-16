# SafeVault

A secure ASP.NET Core web application for managing sensitive data including user credentials and financial records.

## Security Features

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
- BCrypt password hashing (work factor: 12)
- Never stores passwords in plain text
- Account lockout after 5 failed login attempts (15-minute lockout)

✅ **Data Encryption**
- AES-256 encryption for financial records
- Encrypted sensitive data at rest
- Secure key management

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
- **ORM**: Entity Framework Core 8.0
- **Database**: SQLite (easily switchable to SQL Server)
- **Testing**: NUnit 3
- **Password Hashing**: BCrypt.Net-Next
- **Encryption**: AES-256 (System.Security.Cryptography)

## Project Structure

```
SafeVault/
├── SafeVault.Web/              # Main web application
│   ├── Controllers/            # MVC controllers
│   │   ├── UserController.cs   # User registration/login
│   │   ├── FinancialController.cs # Financial records CRUD
│   │   └── HomeController.cs
│   ├── Models/                 # Data models
│   │   ├── User.cs
│   │   ├── UserCredential.cs
│   │   ├── FinancialRecord.cs
│   │   └── ViewModels.cs
│   ├── Data/                   # Database context
│   │   └── SafeVaultDbContext.cs
│   ├── Services/               # Business logic
│   │   ├── EncryptionService.cs
│   │   └── PasswordHasher.cs
│   ├── Validators/             # Custom validators
│   │   └── SecurityValidators.cs
│   └── Views/                  # Razor views
└── SafeVault.Tests/            # NUnit test project
    ├── TestInputValidation.cs
    ├── TestPasswordHashing.cs
    ├── TestEncryption.cs
    └── TestDatabaseSecurity.cs
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

### User Management
- **Registration**: Secure user registration with password validation
- **Login**: Authentication with account lockout protection
- **Session Management**: Secure session handling

### Financial Records
- **Create**: Add new financial records with encrypted sensitive data
- **Read**: View financial records (decrypted for authorized users)
- **Search**: Search records by description (SQL injection safe)
- **Delete**: Remove records with confirmation

## Security Testing

The application includes comprehensive security tests:

### Input Validation Tests (8 tests)
- SQL injection detection
- XSS attack detection
- Malicious input detection
- Bypass attempt detection

### Password Hashing Tests (8 tests)
- Hash generation
- Password verification
- Special character handling
- Long password support

### Encryption Tests (9 tests)
- Data encryption/decryption
- Empty string handling
- Special character support
- Long string support

### Database Security Tests (7 tests)
- SQL injection prevention
- Password storage security
- Data encryption at rest
- User data isolation
- Cascade delete behavior

All 32 tests pass successfully! ✅

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

⚠️ **Important**: Change the encryption keys in production!

Update `appsettings.json`:

```json
"Encryption": {
  "Key": "Your32ByteProductionKeyHere!!",
  "IV": "Your16ByteIVHere"
}
```

In production, store these in:
- Azure Key Vault
- AWS Secrets Manager
- Environment variables
- Secure configuration provider

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
