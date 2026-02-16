using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Web.Models;
using SafeVault.Web.Services;
using System.Security.Claims;

namespace SafeVault.Web.Controllers;

public class UserController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<UserController> _logger;

    public UserController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailSender emailSender,
        ILogger<UserController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailSender = emailSender;
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
            // Check if username already exists
            var existingUser = await _userManager.FindByNameAsync(model.Username);
            if (existingUser != null)
            {
                ModelState.AddModelError("Username", "Username already exists");
                return View(model);
            }

            // Check if email already exists
            var existingEmail = await _userManager.FindByEmailAsync(model.Email);
            if (existingEmail != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
                return View(model);
            }

            // Create new user
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("New user registered: {Username}", model.Username);

                // Assign default "User" role
                await _userManager.AddToRoleAsync(user, "User");
                
                // Add default claims
                await _userManager.AddClaimsAsync(user, new[]
                {
                    new Claim("CanManageFinancials", "true"),
                    new Claim("CanViewReports", "true")
                });

                // Generate email confirmation token
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = Url.Action(
                    "ConfirmEmail",
                    "User",
                    new { userId = user.Id, code = code },
                    protocol: Request.Scheme);

                // Send confirmation email
                await _emailSender.SendEmailAsync(
                    model.Email,
                    "Confirm your email",
                    $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>Confirm Email</a>");

                TempData["SuccessMessage"] = "Registration successful! Please check your email to confirm your account.";
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            ModelState.AddModelError(string.Empty, "An error occurred during registration");
        }

        return View(model);
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
            var user = await _userManager.FindByNameAsync(model.Username);
            
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password");
                return View(model);
            }

            // Check if email is confirmed
            if (!user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "You must confirm your email before logging in.");
                return View(model);
            }

            // Attempt sign in with lockout enabled
            var result = await _signInManager.PasswordSignInAsync(
                model.Username, 
                model.Password, 
                isPersistent: false, 
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in: {Username}", model.Username);
                return RedirectToAction("Index", "Home");
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("LoginWith2fa", new { RememberMe = false });
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out: {Username}", model.Username);
                ModelState.AddModelError(string.Empty, "Account is locked. Please try again later.");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "Invalid username or password");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login");
            ModelState.AddModelError(string.Empty, "An error occurred during login");
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
        {
            return View(new ConfirmEmailViewModel { IsConfirmed = false });
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return View(new ConfirmEmailViewModel { IsConfirmed = false });
        }

        var result = await _userManager.ConfirmEmailAsync(user, code);
        
        return View(new ConfirmEmailViewModel 
        { 
            IsConfirmed = result.Succeeded,
            UserId = userId,
            Code = code
        });
    }

    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult>ForgotPassword(ForgotPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
        {
            // Don't reveal that the user does not exist or is not confirmed
            return RedirectToAction("ForgotPasswordConfirmation");
        }

        var code = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.Action(
            "ResetPassword",
            "User",
            new { userId = user.Id, code = code },
            protocol: Request.Scheme);

        await _emailSender.SendEmailAsync(
            model.Email,
            "Reset Password",
            $"Please reset your password by clicking this link: <a href='{callbackUrl}'>Reset Password</a>");

        return RedirectToAction("ForgotPasswordConfirmation");
    }

    [HttpGet]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    public IActionResult ResetPassword(string userId, string code)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
        {
            return RedirectToAction("Login");
        }

        var model = new ResetPasswordViewModel
        {
            UserId = userId,
            Code = code
        };
        
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return RedirectToAction("ResetPasswordConfirmation");
        }

        var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
        
        if (result.Succeeded)
        {
            return RedirectToAction("ResetPasswordConfirmation");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpGet]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Enable2fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        var model = new Enable2faViewModel();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Enable2fa(Enable2faViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // For email-based 2FA, we'll use the token provider
        var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("User enabled 2FA: {Username}", user.UserName);
            TempData["SuccessMessage"] = "Two-factor authentication has been enabled.";
            return RedirectToAction("Index", "Home");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> LoginWith2fa(bool rememberMe)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        var model = new LoginWith2faViewModel { RememberMe = rememberMe };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        var result = await _signInManager.TwoFactorSignInAsync(
            "Email", 
            model.TwoFactorCode, 
            model.RememberMe, 
            model.RememberMachine);

        if (result.Succeeded)
        {
            _logger.LogInformation("User logged in with 2FA: {Username}", user.UserName);
            return RedirectToAction("Index", "Home");
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User account locked out: {Username}", user.UserName);
            ModelState.AddModelError(string.Empty, "Account is locked.");
            return View(model);
        }

        ModelState.AddModelError(string.Empty, "Invalid verification code.");
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out");
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }
}
