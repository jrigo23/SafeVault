using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Web.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
