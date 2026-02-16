using NUnit.Framework;
using SafeVault.Web.Validators;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestForSQLInjection_DetectsSQLKeywords()
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());
        
        var maliciousInputs = new[]
        {
            "admin' or '1'='1",
            "1'; DROP TABLE Users--",
            "' union select NULL--",
            "admin'--",
            "1' or 1=1--",
            "'; exec sp_executesql--",
            "test/*comment*/data",
            "data' and 1=1--"
        };

        // Act & Assert
        foreach (var input in maliciousInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.Not.EqualTo(ValidationResult.Success), 
                $"SQL injection attempt should be detected: {input}");
        }
    }

    [Test]
    public void TestForSQLInjection_AllowsValidInput()
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());
        
        var validInputs = new[]
        {
            "john_doe",
            "user@example.com",
            "Valid Description",
            "123456",
            "Product Name ABC"
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.EqualTo(ValidationResult.Success), 
                $"Valid input should be accepted: {input}");
        }
    }

    [Test]
    public void TestForXSS_DetectsScriptTags()
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());
        
        var maliciousInputs = new[]
        {
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='malicious.com'>",
            "<body onload=alert('XSS')>",
            "eval('malicious code')",
            "<embed src='malicious'>",
            "<object data='malicious'>",
            "data:text/html,<script>alert('XSS')</script>"
        };

        // Act & Assert
        foreach (var input in maliciousInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.Not.EqualTo(ValidationResult.Success), 
                $"XSS attempt should be detected: {input}");
        }
    }

    [Test]
    public void TestForXSS_AllowsValidInput()
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());
        
        var validInputs = new[]
        {
            "Normal text",
            "Product description with numbers 123",
            "Email: user@example.com",
            "Price: $99.99",
            "Valid user input"
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.EqualTo(ValidationResult.Success), 
                $"Valid input should be accepted: {input}");
        }
    }

    [Test]
    public void TestNoMaliciousInput_DetectsDangerousCharacters()
    {
        // Arrange
        var validator = new NoMaliciousInputAttribute();
        var context = new ValidationContext(new object());
        
        var maliciousInputs = new[]
        {
            "<script>",
            "'; drop table--",
            "test<>test",
            "test\"quote\"",
            "'--comment"
        };

        // Act & Assert
        foreach (var input in maliciousInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.Not.EqualTo(ValidationResult.Success), 
                $"Malicious input should be detected: {input}");
        }
    }

    [Test]
    public void TestNoMaliciousInput_AllowsCleanInput()
    {
        // Arrange
        var validator = new NoMaliciousInputAttribute();
        var context = new ValidationContext(new object());
        
        var validInputs = new[]
        {
            "john_doe",
            "valid@email.com",
            "Product Name 123",
            "Description text",
            "User input"
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            var result = validator.GetValidationResult(input, context);
            Assert.That(result, Is.EqualTo(ValidationResult.Success), 
                $"Valid input should be accepted: {input}");
        }
    }

    [Test]
    public void TestSQLInjection_CommonBypassAttempts()
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());
        
        var bypassAttempts = new[]
        {
            "admin' or '1'='1'--",
            "' or 1=1--",
            "admin'/*",
            "1' UNION ALL SELECT NULL,NULL,NULL--",
            "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'--"
        };

        // Act & Assert
        foreach (var attempt in bypassAttempts)
        {
            var result = validator.GetValidationResult(attempt, context);
            Assert.That(result, Is.Not.EqualTo(ValidationResult.Success), 
                $"SQL injection bypass attempt should be detected: {attempt}");
        }
    }

    [Test]
    public void TestXSS_EventHandlerInjection()
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());
        
        var eventHandlers = new[]
        {
            "onerror=alert('XSS')",
            "onload=malicious()",
            "onclick=hack()",
            "onmouseover=attack()",
            "onfocus=steal()"
        };

        // Act & Assert
        foreach (var handler in eventHandlers)
        {
            var result = validator.GetValidationResult(handler, context);
            Assert.That(result, Is.Not.EqualTo(ValidationResult.Success), 
                $"XSS event handler should be detected: {handler}");
        }
    }
}
