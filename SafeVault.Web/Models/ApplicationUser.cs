using Microsoft.AspNetCore.Identity;

namespace SafeVault.Web.Models;

/// <summary>
/// Custom Identity user that extends IdentityUser with SafeVault-specific properties
/// </summary>
public class ApplicationUser : IdentityUser
{
    /// <summary>
    /// Date when the user account was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Navigation property for financial records owned by this user
    /// </summary>
    public virtual ICollection<FinancialRecord> FinancialRecords { get; set; } = new List<FinancialRecord>();
    
    /// <summary>
    /// Legacy UserID for backward compatibility with existing FinancialRecords
    /// This will be populated from the Id property
    /// </summary>
    public int? LegacyUserId { get; set; }
}
