using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;
using System.Security.Claims;

namespace SafeVault.Web.Controllers;

[Authorize] // Require authentication for all actions
public class FinancialController : Controller
{
    private readonly SafeVaultDbContext _context;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<FinancialController> _logger;
    private readonly IAuthorizationService _authorizationService;

    public FinancialController(
        SafeVaultDbContext context,
        IEncryptionService encryptionService,
        ILogger<FinancialController> logger,
        IAuthorizationService authorizationService)
    {
        _context = context;
        _encryptionService = encryptionService;
        _logger = logger;
        _authorizationService = authorizationService;
    }

    private string? GetCurrentUserId()
    {
        return User.FindFirstValue(ClaimTypes.NameIdentifier);
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }

        // Admins can see all records, users see only their own
        IQueryable<FinancialRecord> query = _context.FinancialRecords;
        
        if (!User.IsInRole("Admin"))
        {
            query = query.Where(r => r.UserID == userId);
        }

        var records = await query
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();

        return View(records);
    }

    [HttpGet]
    [Authorize(Policy = "ManageFinancials")]
    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManageFinancials")]
    public async Task<IActionResult> Create(FinancialRecordViewModel model)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            // Encrypt sensitive data
            var encryptedData = _encryptionService.Encrypt(model.SensitiveData);

            var record = new FinancialRecord
            {
                UserID = userId,
                Description = model.Description,
                EncryptedData = encryptedData,
                Amount = model.Amount,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.FinancialRecords.Add(record);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Financial record created for user {UserId}", userId);

            TempData["SuccessMessage"] = "Financial record created successfully";
            return RedirectToAction("Index");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating financial record");
            ModelState.AddModelError(string.Empty, "An error occurred while creating the record");
            return View(model);
        }
    }

    [HttpGet]
    public async Task<IActionResult> View(int id)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }

        // Use parameterized query through EF Core to prevent SQL injection
        var record = await _context.FinancialRecords
            .FirstOrDefaultAsync(r => r.RecordID == id);

        if (record == null)
        {
            return NotFound();
        }

        // Check authorization using resource-based authorization
        var authResult = await _authorizationService.AuthorizeAsync(
            User, record, Web.Authorization.Operations.Read);
        
        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        // Decrypt sensitive data for viewing
        var viewModel = new FinancialRecordViewModel
        {
            RecordID = record.RecordID,
            Description = record.Description,
            SensitiveData = _encryptionService.Decrypt(record.EncryptedData),
            Amount = record.Amount
        };

        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> Search(SearchViewModel model)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }

        if (!ModelState.IsValid || string.IsNullOrWhiteSpace(model.SearchTerm))
        {
            return RedirectToAction("Index");
        }

        // Use parameterized query through EF Core - SQL injection safe
        IQueryable<FinancialRecord> query = _context.FinancialRecords
            .Where(r => r.Description.Contains(model.SearchTerm));
        
        // Filter by user unless Admin
        if (!User.IsInRole("Admin"))
        {
            query = query.Where(r => r.UserID == userId);
        }

        var records = await query
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();

        ViewData["SearchTerm"] = model.SearchTerm;
        return View("Index", records);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "ManageFinancials")]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }

        try
        {
            // Use parameterized query through EF Core
            var record = await _context.FinancialRecords
                .FirstOrDefaultAsync(r => r.RecordID == id);

            if (record == null)
            {
                return NotFound();
            }

            // Check authorization using resource-based authorization
            var authResult = await _authorizationService.AuthorizeAsync(
                User, record, Web.Authorization.Operations.Delete);
            
            if (!authResult.Succeeded)
            {
                return Forbid();
            }

            _context.FinancialRecords.Remove(record);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Financial record {RecordId} deleted by user {UserId}", id, userId);

            TempData["SuccessMessage"] = "Record deleted successfully";
            return RedirectToAction("Index");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting financial record");
            TempData["ErrorMessage"] = "An error occurred while deleting the record";
            return RedirectToAction("Index");
        }
    }
}
