using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Web.Models;

public class FinancialRecord
{
    [Key]
    public int RecordID { get; set; }

    [Required]
    public string UserID { get; set; } = string.Empty;

    [Required(ErrorMessage = "Description is required")]
    [StringLength(200, ErrorMessage = "Description cannot exceed 200 characters")]
    public string Description { get; set; } = string.Empty;

    [Required]
    // Encrypted sensitive data (account number, card number, etc.)
    public string EncryptedData { get; set; } = string.Empty;

    [Required]
    [Range(0.01, double.MaxValue, ErrorMessage = "Amount must be greater than 0")]
    public decimal Amount { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Navigation property
    [ForeignKey("UserID")]
    public virtual ApplicationUser? User { get; set; }
}
