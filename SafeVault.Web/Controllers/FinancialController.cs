using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Controllers;

public class FinancialController : Controller
{
    private readonly SafeVaultDbContext _context;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<FinancialController> _logger;

    public FinancialController(
        SafeVaultDbContext context,
        IEncryptionService encryptionService,
        ILogger<FinancialController> logger)
    {
        _context = context;
        _encryptionService = encryptionService;
        _logger = logger;
    }

    private int? GetCurrentUserId()
    {
        return HttpContext.Session.GetInt32("UserID");
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
        {
            return RedirectToAction("Login", "User");
        }

        // Use parameterized query through EF Core
        var records = await _context.FinancialRecords
            .Where(r => r.UserID == userId.Value)
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();

        return View(records);
    }

    [HttpGet]
    public IActionResult Create()
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
        {
            return RedirectToAction("Login", "User");
        }

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(FinancialRecordViewModel model)
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
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
                UserID = userId.Value,
                Description = model.Description,
                EncryptedData = encryptedData,
                Amount = model.Amount,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.FinancialRecords.Add(record);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Financial record created for user {UserId}", userId.Value);

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
        if (!userId.HasValue)
        {
            return RedirectToAction("Login", "User");
        }

        // Use parameterized query through EF Core to prevent SQL injection
        var record = await _context.FinancialRecords
            .FirstOrDefaultAsync(r => r.RecordID == id && r.UserID == userId.Value);

        if (record == null)
        {
            return NotFound();
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
        if (!userId.HasValue)
        {
            return RedirectToAction("Login", "User");
        }

        if (!ModelState.IsValid || string.IsNullOrWhiteSpace(model.SearchTerm))
        {
            return RedirectToAction("Index");
        }

        // Use parameterized query through EF Core - SQL injection safe
        var records = await _context.FinancialRecords
            .Where(r => r.UserID == userId.Value && 
                       r.Description.Contains(model.SearchTerm))
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();

        ViewData["SearchTerm"] = model.SearchTerm;
        return View("Index", records);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
        {
            return RedirectToAction("Login", "User");
        }

        try
        {
            // Use parameterized query through EF Core
            var record = await _context.FinancialRecords
                .FirstOrDefaultAsync(r => r.RecordID == id && r.UserID == userId.Value);

            if (record == null)
            {
                return NotFound();
            }

            _context.FinancialRecords.Remove(record);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Financial record {RecordId} deleted by user {UserId}", id, userId.Value);

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
