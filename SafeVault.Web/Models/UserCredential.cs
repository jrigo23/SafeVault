using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Web.Models;

public class UserCredential
{
    [Key]
    public int CredentialID { get; set; }

    [Required]
    public int UserID { get; set; }

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime LastPasswordChange { get; set; } = DateTime.UtcNow;

    public int FailedLoginAttempts { get; set; } = 0;

    public DateTime? LockoutEnd { get; set; }

    // Navigation property
    [ForeignKey("UserID")]
    public virtual User? User { get; set; }
}
