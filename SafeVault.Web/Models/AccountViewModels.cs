using System.ComponentModel.DataAnnotations;

namespace SafeVault.Web.Models;

/// <summary>
/// ViewModel for email confirmation
/// </summary>
public class ConfirmEmailViewModel
{
    public string? UserId { get; set; }
    public string? Code { get; set; }
    public bool IsConfirmed { get; set; }
}

/// <summary>
/// ViewModel for forgot password request
/// </summary>
public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// ViewModel for password reset
/// </summary>
public class ResetPasswordViewModel
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string Code { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", 
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

/// <summary>
/// ViewModel for enabling 2FA
/// </summary>
public class Enable2faViewModel
{
    public string? SharedKey { get; set; }
    public string? AuthenticatorUri { get; set; }
    public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
    
    [Required]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Verification code must be 6 digits")]
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// ViewModel for 2FA login
/// </summary>
public class LoginWith2faViewModel
{
    [Required]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Verification code must be 6 digits")]
    public string TwoFactorCode { get; set; } = string.Empty;

    public bool RememberMachine { get; set; }
    public bool RememberMe { get; set; }
}

/// <summary>
/// ViewModel for recovery code login
/// </summary>
public class LoginWithRecoveryCodeViewModel
{
    [Required]
    public string RecoveryCode { get; set; } = string.Empty;
}
