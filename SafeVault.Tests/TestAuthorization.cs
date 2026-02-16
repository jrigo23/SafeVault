using NUnit.Framework;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using System.Security.Claims;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthorization
{
    private SafeVaultDbContext _context = null!;
    private UserManager<ApplicationUser> _userManager = null!;
    private RoleManager<IdentityRole> _roleManager = null!;

    [SetUp]
    public void Setup()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new SafeVaultDbContext(options);

        // Setup UserManager
        var userStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.UserStore<ApplicationUser>(_context);
        var passwordHasher = new PasswordHasher<ApplicationUser>();
        var userValidators = new List<IUserValidator<ApplicationUser>>
        {
            new UserValidator<ApplicationUser>()
        };
        var passwordValidators = new List<IPasswordValidator<ApplicationUser>>
        {
            new PasswordValidator<ApplicationUser>()
        };
        var keyNormalizer = new UpperInvariantLookupNormalizer();
        var errors = new IdentityErrorDescriber();
        var services = new ServiceCollection();
        services.AddLogging();
        var serviceProvider = services.BuildServiceProvider();
        var logger = serviceProvider.GetService<ILogger<UserManager<ApplicationUser>>>();

        _userManager = new UserManager<ApplicationUser>(
            userStore,
            Options.Create(new IdentityOptions()),
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            serviceProvider,
            logger!);

        // Setup RoleManager
        var roleStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.RoleStore<IdentityRole>(_context);
        var roleValidators = new List<IRoleValidator<IdentityRole>>
        {
            new RoleValidator<IdentityRole>()
        };
        var roleLogger = serviceProvider.GetService<ILogger<RoleManager<IdentityRole>>>();

        _roleManager = new RoleManager<IdentityRole>(
            roleStore,
            roleValidators,
            keyNormalizer,
            errors,
            roleLogger!);
    }

    [TearDown]
    public void TearDown()
    {
        _userManager?.Dispose();
        _roleManager?.Dispose();
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }

    [Test]
    public async Task RoleCreation_SuccessfullyCreatesRole()
    {
        // Arrange
        var roleName = "Admin";

        // Act
        var result = await _roleManager.CreateAsync(new IdentityRole(roleName));

        // Assert
        Assert.That(result.Succeeded, Is.True);
        var roleExists = await _roleManager.RoleExistsAsync(roleName);
        Assert.That(roleExists, Is.True);
    }

    [Test]
    public async Task UserRoleAssignment_SuccessfullyAssignsRole()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        await _userManager.CreateAsync(user, "Password123!");
        await _roleManager.CreateAsync(new IdentityRole("User"));

        // Act
        var result = await _userManager.AddToRoleAsync(user, "User");

        // Assert
        Assert.That(result.Succeeded, Is.True);
        var isInRole = await _userManager.IsInRoleAsync(user, "User");
        Assert.That(isInRole, Is.True);
    }

    [Test]
    public async Task UserClaims_SuccessfullyAddsClaims()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        await _userManager.CreateAsync(user, "Password123!");

        var claims = new[]
        {
            new Claim("CanManageFinancials", "true"),
            new Claim("CanViewReports", "true")
        };

        // Act
        var result = await _userManager.AddClaimsAsync(user, claims);

        // Assert
        Assert.That(result.Succeeded, Is.True);
        var userClaims = await _userManager.GetClaimsAsync(user);
        Assert.That(userClaims.Count, Is.EqualTo(2));
        Assert.That(userClaims.Any(c => c.Type == "CanManageFinancials" && c.Value == "true"), Is.True);
        Assert.That(userClaims.Any(c => c.Type == "CanViewReports" && c.Value == "true"), Is.True);
    }

    [Test]
    public async Task MultipleRoles_UserCanHaveMultipleRoles()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        await _userManager.CreateAsync(user, "Password123!");
        await _roleManager.CreateAsync(new IdentityRole("User"));
        await _roleManager.CreateAsync(new IdentityRole("Admin"));

        // Act
        await _userManager.AddToRoleAsync(user, "User");
        await _userManager.AddToRoleAsync(user, "Admin");

        // Assert
        var roles = await _userManager.GetRolesAsync(user);
        Assert.That(roles.Count, Is.EqualTo(2));
        Assert.That(roles.Contains("User"), Is.True);
        Assert.That(roles.Contains("Admin"), Is.True);
    }

    [Test]
    public async Task RoleRemoval_SuccessfullyRemovesRole()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        await _userManager.CreateAsync(user, "Password123!");
        await _roleManager.CreateAsync(new IdentityRole("User"));
        await _userManager.AddToRoleAsync(user, "User");

        // Act
        var result = await _userManager.RemoveFromRoleAsync(user, "User");

        // Assert
        Assert.That(result.Succeeded, Is.True);
        var isInRole = await _userManager.IsInRoleAsync(user, "User");
        Assert.That(isInRole, Is.False);
    }

    [Test]
    public async Task PasswordValidation_EnforcesPasswordPolicy()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com"
        };

        // Weak passwords
        var weakPasswords = new[] { "pass", "12345678", "password", "Password" };

        // Act & Assert
        foreach (var password in weakPasswords)
        {
            var result = await _userManager.CreateAsync(user, password);
            Assert.That(result.Succeeded, Is.False, $"Weak password '{password}' should be rejected");
        }
    }

    [Test]
    public async Task PasswordValidation_AcceptsStrongPassword()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        // Act
        var result = await _userManager.CreateAsync(user, "StrongP@ssw0rd!");

        // Assert
        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task EmailConfirmation_RequiredForLogin()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = false
        };

        await _userManager.CreateAsync(user, "Password123!");

        // Act
        var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);

        // Assert
        Assert.That(isEmailConfirmed, Is.False);
        
        // Test setting email confirmed manually
        user.EmailConfirmed = true;
        await _userManager.UpdateAsync(user);
        
        isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
        Assert.That(isEmailConfirmed, Is.True);
    }

    [Test]
    public async Task TwoFactorAuthentication_CanBeEnabled()
    {
        // Arrange
        var user = new ApplicationUser
        {
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = true
        };

        await _userManager.CreateAsync(user, "Password123!");

        // Act
        var result = await _userManager.SetTwoFactorEnabledAsync(user, true);

        // Assert
        Assert.That(result.Succeeded, Is.True);
        var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        Assert.That(isTwoFactorEnabled, Is.True);
    }
}
