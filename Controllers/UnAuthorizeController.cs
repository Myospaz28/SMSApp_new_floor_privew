using Microsoft.AspNetCore.Mvc;

namespace SMSApp.Controllers
{
    public class UnAuthorizeController : Controller
    {
        public IActionResult Index()
        {
            return View("UnAuthorizeForm");
        }
    }
}
