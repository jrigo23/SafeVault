using NUnit.Framework;
using SafeVault.Web.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestPasswordHashing
{
    private IPasswordHasher _passwordHasher = null!;

    [SetUp]
    public void Setup()
    {
        _passwordHasher = new PasswordHasher();
    }

    [Test]
    public void HashPassword_CreatesNonEmptyHash()
    {
        // Arrange
        var password = "Test@Password123";

        // Act
        var hash = _passwordHasher.HashPassword(password);

        // Assert
        Assert.That(hash, Is.Not.Null);
        Assert.That(hash, Is.Not.Empty);
        Assert.That(hash.Length, Is.GreaterThan(20));
    }

    [Test]
    public void HashPassword_CreatesDifferentHashesForSamePassword()
    {
        // Arrange
        var password = "Test@Password123";

        // Act
        var hash1 = _passwordHasher.HashPassword(password);
        var hash2 = _passwordHasher.HashPassword(password);

        // Assert - BCrypt adds salt, so hashes should be different
        Assert.That(hash1, Is.Not.EqualTo(hash2));
    }

    [Test]
    public void VerifyPassword_ReturnsTrueForCorrectPassword()
    {
        // Arrange
        var password = "Test@Password123";
        var hash = _passwordHasher.HashPassword(password);

        // Act
        var result = _passwordHasher.VerifyPassword(password, hash);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyPassword_ReturnsFalseForIncorrectPassword()
    {
        // Arrange
        var password = "Test@Password123";
        var wrongPassword = "Wrong@Password456";
        var hash = _passwordHasher.HashPassword(password);

        // Act
        var result = _passwordHasher.VerifyPassword(wrongPassword, hash);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyPassword_ReturnsFalseForEmptyPassword()
    {
        // Arrange
        var password = "Test@Password123";
        var hash = _passwordHasher.HashPassword(password);

        // Act
        var result = _passwordHasher.VerifyPassword("", hash);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HashPassword_ThrowsExceptionForEmptyPassword()
    {
        // Arrange
        var password = "";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _passwordHasher.HashPassword(password));
    }

    [Test]
    public void HashPassword_WorksWithSpecialCharacters()
    {
        // Arrange
        var password = "P@ssw0rd!#$%^&*()";

        // Act
        var hash = _passwordHasher.HashPassword(password);
        var isValid = _passwordHasher.VerifyPassword(password, hash);

        // Assert
        Assert.That(hash, Is.Not.Null);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void HashPassword_WorksWithLongPasswords()
    {
        // Arrange
        var password = "ThisIsAVeryLongPasswordWithLotsOfCharacters123!@#$%";

        // Act
        var hash = _passwordHasher.HashPassword(password);
        var isValid = _passwordHasher.VerifyPassword(password, hash);

        // Assert
        Assert.That(hash, Is.Not.Null);
        Assert.That(isValid, Is.True);
    }
}
