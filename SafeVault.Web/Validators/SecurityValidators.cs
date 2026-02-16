using System.ComponentModel.DataAnnotations;

namespace SafeVault.Web.Validators;

/// <summary>
/// Validates that input does not contain potentially malicious characters
/// </summary>
public class NoMaliciousInputAttribute : ValidationAttribute
{
    private static readonly char[] DangerousChars = { '<', '>', '\'', '"', ';' };
    private static readonly string[] DangerousPatterns = 
    { 
        "<script", "javascript:", "onerror=", "onload=", "onclick=",
        "'; drop", "'; delete", "'; insert", "'; update", 
        "'--", "' or ", "' and ", "/*", "*/"
    };

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString() ?? string.Empty;
        var lowerInput = input.ToLowerInvariant();

        // Check for dangerous characters
        foreach (var dangerousChar in DangerousChars)
        {
            if (input.Contains(dangerousChar))
            {
                return new ValidationResult($"Input contains potentially dangerous character: {dangerousChar}");
            }
        }

        // Check for dangerous patterns
        foreach (var pattern in DangerousPatterns)
        {
            if (lowerInput.Contains(pattern))
            {
                return new ValidationResult($"Input contains potentially dangerous pattern");
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that input is properly sanitized for SQL
/// </summary>
public class SqlInjectionSafeAttribute : ValidationAttribute
{
    private static readonly string[] SqlPatterns = 
    { 
        "'; ", "'--", "' or ", "' and ", "/*", "*/", "--",
        "union select", "drop table", "insert into", "delete from",
        "exec ", "execute ", "xp_", "sp_password", "information_schema"
    };

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString() ?? string.Empty;
        var lowerInput = input.ToLowerInvariant();

        foreach (var pattern in SqlPatterns)
        {
            if (lowerInput.Contains(pattern))
            {
                return new ValidationResult("Input contains potentially unsafe SQL patterns");
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that input is safe from XSS attacks
/// </summary>
public class XssSafeAttribute : ValidationAttribute
{
    private static readonly string[] XssPatterns = 
    { 
        "<script", "javascript:", "onerror=", "onload=", "onclick=", "onmouseover=",
        "onfocus=", "onblur=", "onchange=", "eval(", "expression(", "vbscript:",
        "data:text/html", "<iframe", "<embed", "<object"
    };

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString() ?? string.Empty;
        var lowerInput = input.ToLowerInvariant();

        // Check for script tags
        if (lowerInput.Contains("<script") || lowerInput.Contains("</script"))
        {
            return new ValidationResult("Input contains HTML/XML tags which are not allowed");
        }

        foreach (var pattern in XssPatterns)
        {
            if (lowerInput.Contains(pattern))
            {
                return new ValidationResult("Input contains potentially dangerous scripting patterns");
            }
        }

        return ValidationResult.Success;
    }
}
