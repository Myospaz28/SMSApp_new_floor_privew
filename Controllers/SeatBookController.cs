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
using SMSApp.Models.DAL;
using Microsoft.AspNetCore.Authorization;

namespace SMSApp.Controllers
{
    [Authorize]
    public class SeatBookController : Controller
    {
        private readonly ILogger<SeatBookController> _logger;
        private IConfiguration Configuration;

        public SeatBookController(ILogger<SeatBookController> logger, IConfiguration _configuration)
        {
            _logger = logger;
            Configuration = _configuration;
        }

        public IActionResult Privacy()
        {
            return View();
        }

        // Get All Seat List
        [HttpGet]
        public ActionResult Index()
        {
            SeatBookSC mSeatBookSC = new SeatBookSC();
            DataSet mDset = new DataSet();
            FloorBLL mFloorBLL = new FloorBLL();

            mSeatBookSC.IsWFH = "0";

            mDset = mFloorBLL.IsUserWFH(User.GetUserId().ToString(), Configuration);

            if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
            {
                mSeatBookSC.IsWFH = mDset.Tables[0].Rows[0]["IsWFH"].ToString();
            }

            return View("SeatBookList", mSeatBookSC);
        }

        // Open Seat Search Page
        [HttpGet]
        public ActionResult Search()
        {
            return View("SeatBookSearch");
        }

        // Save WFH Users
        [HttpPost]
        public IActionResult SaveWFH(string IsWFH)
        {
            FloorBLL mFloorBLL = null;
            FloorMapSC mFloorMapSC = null;

            mFloorBLL = new FloorBLL();
            mFloorMapSC = new FloorMapSC();

            mFloorMapSC.IsEdit = mFloorMapSC.Id == null ? "N" : "Y";

            mFloorMapSC.FloorId = null;
            mFloorMapSC.UserId = Convert.ToInt32(User.GetUserId());
            mFloorMapSC.FloorMapId = null;
            mFloorMapSC.CurrUserId = User.GetUserId();
            mFloorMapSC.IsWFH = IsWFH;

            mFloorBLL.BookSeat(mFloorMapSC, Configuration);

            return Json(new
            {
                IsSuccess = "Y"
            });
        }

        // Checkout functionality
        [HttpPost]
        public IActionResult CheckOut()
        {
            FloorBLL mFloorBLL = null;
            string mCurrUsrId = string.Empty;

            mFloorBLL = new FloorBLL();
            mCurrUsrId = User.GetUserId();

            mFloorBLL.CheckOut(mCurrUsrId, Configuration);

            return Json(new
            {
                IsSuccess = "Y"
            });
        }

        // Seat Book Checkright for IsWFH or not
        [HttpPost]
        public IActionResult SeatBookCheckRights()
        {
            FloorBLL mFloorBLL = null;
            string mCurrUsrId = string.Empty;
            DataSet mDset = new DataSet();

            mFloorBLL = new FloorBLL();
            mCurrUsrId = User.GetUserId();

            mDset = mFloorBLL.SeatBookCheckRights(mCurrUsrId, Configuration);

            return Json(new
            {
                IsSuccess = "Y",
                ReturnVal = JsonConvert.SerializeObject(mDset)
            });
        }

        // Get All Seat Search List
        [HttpPost]
        public IActionResult SeatSearchList(string vLastName, string vFirstName, string vFloorId, string vDeptId,string vSrchType)
        {
            FloorBLL mFloorBLL = null;
            DataSet mDset = null;
            String vCurrUsrId = string.Empty;

            mFloorBLL = new FloorBLL();

            vCurrUsrId = User.GetUserId();

            if (vSrchType == "Name")
            {
                vFloorId = string.Empty;
                vDeptId = string.Empty;
            }
            else if (vSrchType == "FLR")
            {
                vLastName = string.Empty;
                vFirstName = string.Empty;
                vDeptId = string.Empty;
            }
            else if (vSrchType == "DPT")
            {
                vLastName = string.Empty;
                vFirstName = string.Empty;
                vFloorId = string.Empty;
            }

            if (!string.IsNullOrEmpty(vFloorId))
                vFloorId = vFloorId.Replace("number:", "");

            mDset = mFloorBLL.SeatSearchList(vLastName, vFirstName, vFloorId, vDeptId, vCurrUsrId, Configuration);

            return Json(JsonConvert.SerializeObject(mDset));
        }

        // View  SeatBook List
        [HttpPost]
        public IActionResult ViewSeatBookList()
        {
            FloorBLL mFloorBLL = null;
            string mCurrUsrId = string.Empty;
            DataSet mDset = new DataSet();

            mFloorBLL = new FloorBLL();
            mCurrUsrId = User.GetUserId();

            mDset = mFloorBLL.ViewSeatBookList(mCurrUsrId, Configuration);

            return Json(new
            {
                IsSuccess = "Y",
                ReturnVal = JsonConvert.SerializeObject(mDset)
            });
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}