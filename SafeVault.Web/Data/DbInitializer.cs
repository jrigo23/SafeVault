using Microsoft.AspNetCore.Identity;
using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

/// <summary>
/// Initializes the database with default roles and an admin user
/// </summary>
public static class DbInitializer
{
    public static async Task InitializeAsync(IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

        try
        {
            // Define roles
            string[] roles = { "Admin", "User", "Guest" };

            // Create roles if they don't exist
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    var result = await roleManager.CreateAsync(new IdentityRole(role));
                    if (result.Succeeded)
                    {
                        logger.LogInformation("Created role: {Role}", role);
                    }
                    else
                    {
                        logger.LogError("Failed to create role {Role}: {Errors}", 
                            role, string.Join(", ", result.Errors.Select(e => e.Description)));
                    }
                }
            }

            // Create default admin user if it doesn't exist
            var adminEmail = "admin@safevault.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = "admin",
                    Email = adminEmail,
                    EmailConfirmed = true, // Admin doesn't need email confirmation
                    CreatedAt = DateTime.UtcNow
                };

                var result = await userManager.CreateAsync(adminUser, "Admin@123456");
                
                if (result.Succeeded)
                {
                    logger.LogInformation("Created admin user: {Email}", adminEmail);
                    
                    // Assign Admin role
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    
                    // Add admin claims
                    await userManager.AddClaimsAsync(adminUser, new[]
                    {
                        new System.Security.Claims.Claim("CanManageFinancials", "true"),
                        new System.Security.Claims.Claim("CanViewReports", "true"),
                        new System.Security.Claims.Claim("CanManageUsers", "true")
                    });
                    
                    logger.LogInformation("Admin user configured with role and claims");
                }
                else
                {
                    logger.LogError("Failed to create admin user: {Errors}", 
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while seeding the database");
        }
    }
}
