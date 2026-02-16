using NUnit.Framework;
using Microsoft.Extensions.Configuration;
using SafeVault.Web.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestEncryption
{
    private IEncryptionService _encryptionService = null!;

    [SetUp]
    public void Setup()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Encryption:Key", "ThisIsATestKeyForAES256Encryption!" }
            })
            .Build();

        _encryptionService = new EncryptionService(configuration);
    }

    [Test]
    public void Encrypt_CreatesNonEmptyEncryptedString()
    {
        // Arrange
        var plainText = "Sensitive financial data";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);

        // Assert
        Assert.That(encrypted, Is.Not.Null);
        Assert.That(encrypted, Is.Not.Empty);
        Assert.That(encrypted, Is.Not.EqualTo(plainText));
    }

    [Test]
    public void Decrypt_ReturnsOriginalPlainText()
    {
        // Arrange
        var plainText = "Account Number: 1234-5678-9012";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);
        var decrypted = _encryptionService.Decrypt(encrypted);

        // Assert
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [Test]
    public void Encrypt_HandlesEmptyString()
    {
        // Arrange
        var plainText = "";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);
        var decrypted = _encryptionService.Decrypt(encrypted);

        // Assert
        Assert.That(encrypted, Is.Empty);
        Assert.That(decrypted, Is.Empty);
    }

    [Test]
    public void Encrypt_WorksWithSpecialCharacters()
    {
        // Arrange
        var plainText = "Special chars: !@#$%^&*()_+-={}[]|:;<>?,./";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);
        var decrypted = _encryptionService.Decrypt(encrypted);

        // Assert
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [Test]
    public void Encrypt_WorksWithNumbers()
    {
        // Arrange
        var plainText = "1234567890";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);
        var decrypted = _encryptionService.Decrypt(encrypted);

        // Assert
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [Test]
    public void Encrypt_WorksWithLongStrings()
    {
        // Arrange
        var plainText = new string('A', 1000);

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);
        var decrypted = _encryptionService.Decrypt(encrypted);

        // Assert
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [Test]
    public void Encrypt_ProducesDifferentOutputForDifferentInput()
    {
        // Arrange
        var plainText1 = "Account 123";
        var plainText2 = "Account 456";

        // Act
        var encrypted1 = _encryptionService.Encrypt(plainText1);
        var encrypted2 = _encryptionService.Encrypt(plainText2);

        // Assert
        Assert.That(encrypted1, Is.Not.EqualTo(encrypted2));
    }

    [Test]
    public void Encrypt_ProducesDifferentOutputForSameInput()
    {
        // Arrange
        var plainText = "Consistent data";

        // Act
        var encrypted1 = _encryptionService.Encrypt(plainText);
        var encrypted2 = _encryptionService.Encrypt(plainText);

        // Assert - With random IV, output should be different each time
        Assert.That(encrypted1, Is.Not.EqualTo(encrypted2));
        
        // But both should decrypt to the same value
        var decrypted1 = _encryptionService.Decrypt(encrypted1);
        var decrypted2 = _encryptionService.Decrypt(encrypted2);
        Assert.That(decrypted1, Is.EqualTo(plainText));
        Assert.That(decrypted2, Is.EqualTo(plainText));
    }

    [Test]
    public void Encrypt_DataIsNotStoredInPlainText()
    {
        // Arrange
        var plainText = "Sensitive Data 123";

        // Act
        var encrypted = _encryptionService.Encrypt(plainText);

        // Assert
        Assert.That(encrypted, Does.Not.Contain("Sensitive"));
        Assert.That(encrypted, Does.Not.Contain("Data"));
        Assert.That(encrypted, Does.Not.Contain("123"));
    }
}
