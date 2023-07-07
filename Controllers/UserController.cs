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
using SMSApp.Models.DAL;

namespace SMSApp.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private IConfiguration Configuration;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public UserController(ILogger<UserController> logger, IConfiguration _configuration, IWebHostEnvironment? webHostEnvironment)
        {
            _logger = logger;
            Configuration = _configuration;
            _webHostEnvironment = webHostEnvironment;
        }

        public IActionResult Privacy()
        {
            return View();
        }


        // All User List
        [HttpGet]
        public ActionResult Index()
        {
            return View("UsersList");
        }

        // Redirect to New Users Page
        [HttpGet]
        public ActionResult New()
        {
            UserSC mUserSC = new UserSC();
            mUserSC.Status = "1";
            mUserSC.PageType = "User";

            return View("AddUser", mUserSC);
        }

        // Save and Update new Users
        [HttpPost]
        public IActionResult SaveUser(UserSC vUserSC)
        {
            UserBLL mUserBLL = null;
            ImageSC mImageSC = null;
            ImageDAL mImageDAL = null;

            mUserBLL = new UserBLL();
            mImageSC = new ImageSC();

            mImageDAL = new ImageDAL(Configuration);

            vUserSC.IsEdit = vUserSC.UserId == null ? "N" : "Y";

            vUserSC.CurrUserId = User.GetUserId();
            vUserSC.UserDisplayName = String.IsNullOrEmpty(vUserSC.UserDisplayName) ? vUserSC.LNKanji : vUserSC.UserDisplayName;

            vUserSC.RoleId = "2";

            if (vUserSC.ProfilePhoto != null)
            {
                mImageSC.IsEdit = vUserSC.IsEdit;
                mImageSC.ImageName = Path.GetFileName(vUserSC.ProfilePhoto.FileName);
                mImageSC.CurrUserId = User.GetUserId();
                mImageSC.OrgImagepath = Path.Combine(_webHostEnvironment.WebRootPath, "Uploads", "ProfileImage");
                mImageSC.ImgId = vUserSC.ImgId != null ? Convert.ToInt32(vUserSC.ImgId) : null;
            }

            mUserBLL.SaveUser(mImageSC, vUserSC, Configuration);

            return Json(new
            {
                IsSuccess = "Y",
                PageType = vUserSC.PageType
            });
        }

        // View Users List
        [HttpPost]
        public IActionResult ViewUserList()
        {
            UserBLL mUserBLL = null;
            DataSet mDset = null;
            string vUserId = string.Empty;

            mUserBLL = new UserBLL();
            vUserId = User.GetUserId();

            mDset = mUserBLL.ViewUserList(vUserId, Configuration);

            //if (mDset != null && mDset.Tables.Count > 0)
            //{
            //    foreach (DataRow mDrow in mDset.Tables[0].Rows)
            //    {
            //        mDrow["UserEncId"] = Helper.Encrypt(mDrow["UserId"].ToString());
            //    }
            //}

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // Redirect to Edit User Page
        [HttpGet]
        public ActionResult Edit(String id, string PageType)
        {
            UserBLL mUserBLL = null;
            UserSC mUserSC = null;
            string mUserId = string.Empty;
            string mIsSuccess = string.Empty;

            mUserBLL = new UserBLL();
            mUserSC = new UserSC();

            // User Validation
            mUserId = User.GetUserId();
            if (PageType != "Prof")
            {

                mIsSuccess = mUserBLL.UserGetByIdValidate(id, mUserId, Configuration);

                if (mIsSuccess == "0")
                {
                    return RedirectToAction("Index", "UnAuthorize");
                }
            }

            mUserSC = mUserBLL.UserGetById(id, Configuration);
            mUserSC.PageType = PageType;

            return View("AddUser", mUserSC);
        }

        // Get All Roles List on User page
        [HttpPost]
        public IActionResult GetAllRoles()
        {
            UserBLL mUserBLL = null;
            DataSet mDset = null;

            mUserBLL = new UserBLL();

            mDset = mUserBLL.GetAllRoles(Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }


        // Get All Department List on User page
        [HttpPost]
        public IActionResult GetAllDepartment()
        {
            UserBLL mUserBLL = null;
            DataSet mDset = null;

            mUserBLL = new UserBLL();

            mDset = mUserBLL.GetAllDepartment(Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // Get All Floor List on User page
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

        // Get All Home Map Floor
        [HttpPost]
        public IActionResult GetAllMapFloor(string vUserId)
        {
            UserBLL mUserBLL = null;
            DataSet mDset = null;
            string vCurrUsrId = string.Empty;

            mUserBLL = new UserBLL();
            vCurrUsrId = User.GetUserId();

            if (User.GetRoleCode() == "SystemAdm")
            {
                vCurrUsrId = vUserId;
            }

            //vCurrUsrId = Helper.Decrypt(vCurrUsrId);

            mDset = mUserBLL.GetAllMapFloor(vCurrUsrId, Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}