using System.ComponentModel.DataAnnotations;
using SafeVault.Web.Validators;

namespace SafeVault.Web.Models;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 100 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    [NoMaliciousInput]
    [SqlInjectionSafe]
    [XssSafe]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    [StringLength(100)]
    [NoMaliciousInput]
    [XssSafe]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", 
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public class LoginViewModel
{
    [Required(ErrorMessage = "Username is required")]
    [NoMaliciousInput]
    [SqlInjectionSafe]
    [XssSafe]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}

public class FinancialRecordViewModel
{
    public int? RecordID { get; set; }

    [Required(ErrorMessage = "Description is required")]
    [StringLength(200, ErrorMessage = "Description cannot exceed 200 characters")]
    [NoMaliciousInput]
    [XssSafe]
    public string Description { get; set; } = string.Empty;

    [Required(ErrorMessage = "Sensitive data is required")]
    [StringLength(500, ErrorMessage = "Sensitive data cannot exceed 500 characters")]
    public string SensitiveData { get; set; } = string.Empty;

    [Required(ErrorMessage = "Amount is required")]
    [Range(0.01, double.MaxValue, ErrorMessage = "Amount must be greater than 0")]
    public decimal Amount { get; set; }
}

public class SearchViewModel
{
    [StringLength(100)]
    [NoMaliciousInput]
    [SqlInjectionSafe]
    [XssSafe]
    public string SearchTerm { get; set; } = string.Empty;
}
