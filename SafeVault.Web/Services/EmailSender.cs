namespace SafeVault.Web.Services;

/// <summary>
/// Basic email sender implementation for SafeVault
/// In production, this should use a proper SMTP service or email API (SendGrid, AWS SES, etc.)
/// </summary>
public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(ILogger<EmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendEmailAsync(string email, string subject, string message)
    {
        // For development/testing, we'll just log the email
        // In production, integrate with an actual email service
        _logger.LogInformation(
            "Email would be sent to {Email}\nSubject: {Subject}\nMessage: {Message}", 
            email, subject, message);
        
        // TODO: In production, implement actual email sending using:
        // - SMTP client
        // - SendGrid API
        // - AWS SES
        // - Azure Communication Services
        // etc.
        
        return Task.CompletedTask;
    }
}
