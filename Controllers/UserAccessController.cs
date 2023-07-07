using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SMSApp.Models;
using SMSApp.Models.SC;
using System.Diagnostics;
using System.Security.Claims;
using WebTemplate.Models.BLL;
using System.Data;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace SMSApp.Controllers
{
    [Authorize]
    public class UserAccessController : Controller
    {
        private readonly ILogger<UserAccessController> _logger;
        private IConfiguration Configuration;

        public UserAccessController(ILogger<UserAccessController> logger, IConfiguration _configuration)
        {
            _logger = logger;
            Configuration = _configuration;
        }

        public IActionResult Privacy()
        {
            return View();
        }

        // All User Access List
        [HttpGet]
        public ActionResult Index()
        {
            return View("UserAccessList");
        }

        // Redirect to new User Access Page
        [HttpGet]
        public ActionResult New()
        {
            this.FillUsersList();

            UserAccessSC mUserAccessSC = new UserAccessSC();
            mUserAccessSC.IsActive = "1";

            return View("UserAccessForm", mUserAccessSC);
        }

        // GEt All Users List
        public void FillUsersList()
        {
            SelectList mSelectList = null;
            Select2DropDown mSelect2DropDown = null;
            IList<Select2DropDown> mSelect2DropDownLst = null;

            mSelect2DropDownLst = new List<Select2DropDown>();
            mSelect2DropDown = new Select2DropDown();

            mSelectList = new SelectList(mSelect2DropDownLst.ToArray(), "Value", "Text");

            ViewData["UsersList"] = mSelectList;
        }

        // Save User Access 
        [HttpPost]
        public IActionResult SaveUserAccess(UserAccessSC vUserAccessSC)
        {
            if (vUserAccessSC.FloorId == null)
            {
                return Json(new
                {
                    IsSuccess = "N",
                    ErrorMessage = "The 'フロア' Field is required"
                });
            }

            UserAccessBLL mUserAccessBLL = null;

            mUserAccessBLL = new UserAccessBLL();

            vUserAccessSC.IsEdit = vUserAccessSC.UserAccessId == null ? "N" : "Y";
            vUserAccessSC.CurrUserId = User.GetUserId();

            mUserAccessBLL.SaveUserAccess(vUserAccessSC, Configuration);

            return Json(new
            {
                IsSuccess = "Y"
            });
        }

        // View User Access List
        [HttpPost]
        public IActionResult ViewUserAccessList()
        {
            UserAccessBLL mUserAccessBLL = null;
            DataSet mDset = null;

            mUserAccessBLL = new UserAccessBLL();

            mDset = mUserAccessBLL.ViewUserAccessList(User.GetUserId().ToString(), Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // Edit User Access List
        [HttpGet]
        public ActionResult Edit(String id)
        {
            UserAccessBLL mUserAccessBLL = null;
            UserAccessSC mUserAccessSC = null;
            string mUserId = string.Empty;
            string mIsSuccess = string.Empty;

            mUserAccessBLL = new UserAccessBLL();
            mUserAccessSC = new UserAccessSC();

            mUserId = User.GetUserId();

            // Controller Validation
            mIsSuccess = mUserAccessBLL.UserAccessGetByIdValidate(id, mUserId, Configuration);

            if (mIsSuccess == "0")
            {
                return RedirectToAction("Index", "UnAuthorize");
            }

            mUserAccessSC = mUserAccessBLL.UserAccessGetById(id, Configuration);

            return View("UserAccessForm", mUserAccessSC);
        }

        // Get All User List on page
        [HttpPost]
        public IActionResult GetAllUsersList()
        {
            UserAccessBLL mUserAccessBLL = null;
            DataSet mDset = null;

            mUserAccessBLL = new UserAccessBLL();

            mDset = mUserAccessBLL.GetAllUsersList(Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // Get ALl Floor List on page
        [HttpPost]
        public IActionResult GetAllFloorList(string vType)
        {
            UserAccessBLL mUserAccessBLL = null;
            DataSet mDset = null;
            string mUserId = string.Empty;

            mUserAccessBLL = new UserAccessBLL();

            mUserId = User.GetUserId();

            mDset = mUserAccessBLL.GetAllFloorList(mUserId, vType, Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // Get All Floor
        [HttpPost]
        public IActionResult GetAllFloor()
        {
            FloorBLL mFloorBLL = null;
            DataSet mDset = null;
            string vCurrUsrId = string.Empty;

            mFloorBLL = new FloorBLL();
            vCurrUsrId = User.GetUserId();

            mDset = mFloorBLL.GetAllFloor(Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}