namespace SafeVault.Web.Services;

/// <summary>
/// Interface for sending emails (confirmation, password reset, 2FA codes)
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// Sends an email asynchronously
    /// </summary>
    /// <param name="email">Recipient email address</param>
    /// <param name="subject">Email subject</param>
    /// <param name="message">Email message body</param>
    Task SendEmailAsync(string email, string subject, string message);
}
