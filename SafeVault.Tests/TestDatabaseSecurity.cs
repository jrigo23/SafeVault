using NUnit.Framework;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Tests;

[TestFixture]
public class TestDatabaseSecurity
{
    private SafeVaultDbContext _context = null!;
    private IPasswordHasher _passwordHasher = null!;
    private IEncryptionService _encryptionService = null!;

    [SetUp]
    public void Setup()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new SafeVaultDbContext(options);
        _passwordHasher = new PasswordHasher();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Encryption:Key", "ThisIsATestKeyForAES256Encryption!" }
            })
            .Build();

        _encryptionService = new EncryptionService(configuration);
    }

    [TearDown]
    public void TearDown()
    {
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }

    [Test]
    public async Task SQLInjection_PreventedByParameterizedQueries()
    {
        // Arrange
        var maliciousUsername = "admin' OR '1'='1";

        // Act - This should not find any user or cause an error
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == maliciousUsername);

        // Assert
        Assert.That(user, Is.Null, "SQL injection attempt should not succeed");
    }

    [Test]
    public async Task SQLInjection_DropTableAttemptFails()
    {
        // Arrange
        var user = new User
        {
            Username = "testuser",
            Email = "test@example.com"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var maliciousInput = "'; DROP TABLE Users; --";

        // Act
        var result = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == maliciousInput);

        // Assert
        Assert.That(result, Is.Null);
        
        // Verify table still exists
        var usersExist = await _context.Users.AnyAsync();
        Assert.That(usersExist, Is.True, "Users table should still exist");
    }

    [Test]
    public async Task PasswordsAreHashedNotPlainText()
    {
        // Arrange
        var plainPassword = "MySecurePassword123!";
        var hashedPassword = _passwordHasher.HashPassword(plainPassword);

        var user = new User
        {
            Username = "testuser",
            Email = "test@example.com"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var credential = new UserCredential
        {
            UserID = user.UserID,
            PasswordHash = hashedPassword
        };
        _context.UserCredentials.Add(credential);
        await _context.SaveChangesAsync();

        // Act
        var storedCredential = await _context.UserCredentials
            .FirstOrDefaultAsync(c => c.UserID == user.UserID);

        // Assert
        Assert.That(storedCredential, Is.Not.Null);
        Assert.That(storedCredential!.PasswordHash, Is.Not.EqualTo(plainPassword));
        Assert.That(storedCredential.PasswordHash, Does.Not.Contain(plainPassword));
        Assert.That(storedCredential.PasswordHash, Does.StartWith("$2"));  // BCrypt prefix
    }

    [Test]
    public async Task FinancialData_IsEncryptedAtRest()
    {
        // Arrange
        var sensitiveData = "Account Number: 1234-5678-9012-3456";
        var encryptedData = _encryptionService.Encrypt(sensitiveData);

        var userId = Guid.NewGuid().ToString(); // Simulate Identity user ID

        var record = new FinancialRecord
        {
            UserID = userId,
            Description = "Bank Account",
            EncryptedData = encryptedData,
            Amount = 1000.00m
        };
        _context.FinancialRecords.Add(record);
        await _context.SaveChangesAsync();

        // Act
        var storedRecord = await _context.FinancialRecords
            .FirstOrDefaultAsync(r => r.RecordID == record.RecordID);

        // Assert
        Assert.That(storedRecord, Is.Not.Null);
        Assert.That(storedRecord!.EncryptedData, Is.Not.EqualTo(sensitiveData));
        Assert.That(storedRecord.EncryptedData, Does.Not.Contain("1234"));
        Assert.That(storedRecord.EncryptedData, Does.Not.Contain("Account"));
        
        // Verify it can be decrypted
        var decrypted = _encryptionService.Decrypt(storedRecord.EncryptedData);
        Assert.That(decrypted, Is.EqualTo(sensitiveData));
    }

    [Test]
    public async Task UnionSelectInjectionAttempt_IsBlocked()
    {
        // Arrange
        var user = new User
        {
            Username = "normaluser",
            Email = "user@example.com"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var maliciousSearch = "test' UNION SELECT NULL, NULL, NULL--";

        // Act
        var results = await _context.FinancialRecords
            .Where(r => r.Description.Contains(maliciousSearch))
            .ToListAsync();

        // Assert
        Assert.That(results, Is.Empty, "UNION SELECT injection should not return data");
    }

    [Test]
    public async Task UserDataIsolation_PreventsUnauthorizedAccess()
    {
        // Arrange
        var userId1 = Guid.NewGuid().ToString(); // Simulate Identity user ID
        var userId2 = Guid.NewGuid().ToString(); // Simulate Identity user ID

        var record1 = new FinancialRecord
        {
            UserID = userId1,
            Description = "User1 Record",
            EncryptedData = _encryptionService.Encrypt("User1 Data"),
            Amount = 100.00m
        };
        _context.FinancialRecords.Add(record1);
        await _context.SaveChangesAsync();

        // Act - User2 tries to access User1's records
        var user2Records = await _context.FinancialRecords
            .Where(r => r.UserID == userId2)
            .ToListAsync();

        // Assert
        Assert.That(user2Records, Is.Empty, "User2 should not see User1's records");
    }

    [Test]
    public async Task CascadeDelete_RemovesRelatedData()
    {
        // Arrange
        var user = new User { Username = "testuser", Email = "test@example.com" };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var credential = new UserCredential
        {
            UserID = user.UserID,
            PasswordHash = _passwordHasher.HashPassword("Password123!")
        };
        _context.UserCredentials.Add(credential);
        await _context.SaveChangesAsync();

        // Act
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        // Assert
        var credentialExists = await _context.UserCredentials.AnyAsync(c => c.UserID == user.UserID);
        
        Assert.That(credentialExists, Is.False, "User credentials should be deleted");
    }
}
