using System.ComponentModel.DataAnnotations;

namespace SafeVault.Web.Models;

public class User
{
    [Key]
    public int UserID { get; set; }

    [Required(ErrorMessage = "Username is required")]
    [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 100 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [StringLength(100)]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual UserCredential? Credential { get; set; }
    public virtual ICollection<FinancialRecord> FinancialRecords { get; set; } = new List<FinancialRecord>();
}
