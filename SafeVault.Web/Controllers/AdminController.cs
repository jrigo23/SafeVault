using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Models;

namespace SafeVault.Web.Controllers;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ILogger<AdminController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var users = await _userManager.Users.ToListAsync();
        return View(users);
    }

    [HttpGet]
    public async Task<IActionResult> UserDetails(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return NotFound();
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var claims = await _userManager.GetClaimsAsync(user);
        
        ViewBag.Roles = roles;
        ViewBag.Claims = claims;
        ViewBag.IsLockedOut = await _userManager.IsLockedOutAsync(user);
        
        return View(user);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssignRole(string userId, string role)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        if (!await _roleManager.RoleExistsAsync(role))
        {
            TempData["ErrorMessage"] = "Role does not exist";
            return RedirectToAction("UserDetails", new { id = userId });
        }

        var result = await _userManager.AddToRoleAsync(user, role);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Admin assigned role {Role} to user {UserId}", role, userId);
            TempData["SuccessMessage"] = $"Role '{role}' assigned successfully";
        }
        else
        {
            TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
        }

        return RedirectToAction("UserDetails", new { id = userId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveRole(string userId, string role)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.RemoveFromRoleAsync(user, role);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Admin removed role {Role} from user {UserId}", role, userId);
            TempData["SuccessMessage"] = $"Role '{role}' removed successfully";
        }
        else
        {
            TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
        }

        return RedirectToAction("UserDetails", new { id = userId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        // Lock account for 30 days
        var result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddDays(30));
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Admin locked user account {UserId}", userId);
            TempData["SuccessMessage"] = "User account locked successfully";
        }
        else
        {
            TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
        }

        return RedirectToAction("UserDetails", new { id = userId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UnlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        
        if (result.Succeeded)
        {
            // Reset failed access attempts
            await _userManager.ResetAccessFailedCountAsync(user);
            
            _logger.LogInformation("Admin unlocked user account {UserId}", userId);
            TempData["SuccessMessage"] = "User account unlocked successfully";
        }
        else
        {
            TempData["ErrorMessage"] = string.Join(", ", result.Errors.Select(e => e.Description));
        }

        return RedirectToAction("UserDetails", new { id = userId });
    }
}
