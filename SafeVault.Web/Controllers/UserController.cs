using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Controllers;

public class UserController : Controller
{
    private readonly SafeVaultDbContext _context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<UserController> _logger;

    public UserController(
        SafeVaultDbContext context,
        IPasswordHasher passwordHasher,
        ILogger<UserController> logger)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            // Check if username already exists using parameterized query (EF Core)
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == model.Username);

            if (existingUser != null)
            {
                ModelState.AddModelError("Username", "Username already exists");
                return View(model);
            }

            // Check if email already exists
            var existingEmail = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == model.Email);

            if (existingEmail != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            // Create new user with hashed password
            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Create credentials with hashed password
            var credential = new UserCredential
            {
                UserID = user.UserID,
                PasswordHash = _passwordHasher.HashPassword(model.Password),
                LastPasswordChange = DateTime.UtcNow
            };

            _context.UserCredentials.Add(credential);
            await _context.SaveChangesAsync();

            _logger.LogInformation("New user registered: {Username}", model.Username);

            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            ModelState.AddModelError(string.Empty, "An error occurred during registration");
            return View(model);
        }
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            // Use parameterized query through EF Core
            var user = await _context.Users
                .Include(u => u.Credential)
                .FirstOrDefaultAsync(u => u.Username == model.Username);

            if (user?.Credential == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password");
                return View(model);
            }

            // Check for account lockout
            if (user.Credential.LockoutEnd.HasValue && user.Credential.LockoutEnd > DateTime.UtcNow)
            {
                ModelState.AddModelError(string.Empty, "Account is locked. Please try again later.");
                return View(model);
            }

            // Verify password
            if (!_passwordHasher.VerifyPassword(model.Password, user.Credential.PasswordHash))
            {
                // Increment failed login attempts
                user.Credential.FailedLoginAttempts++;
                
                if (user.Credential.FailedLoginAttempts >= 5)
                {
                    user.Credential.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                    _logger.LogWarning("Account locked due to failed login attempts: {Username}", model.Username);
                }

                await _context.SaveChangesAsync();

                ModelState.AddModelError(string.Empty, "Invalid username or password");
                return View(model);
            }

            // Reset failed login attempts on successful login
            user.Credential.FailedLoginAttempts = 0;
            user.Credential.LockoutEnd = null;
            await _context.SaveChangesAsync();

            // Set session/authentication
            HttpContext.Session.SetInt32("UserID", user.UserID);
            HttpContext.Session.SetString("Username", user.Username);

            _logger.LogInformation("User logged in: {Username}", model.Username);

            return RedirectToAction("Index", "Home");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login");
            ModelState.AddModelError(string.Empty, "An error occurred during login");
            return View(model);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }
}
