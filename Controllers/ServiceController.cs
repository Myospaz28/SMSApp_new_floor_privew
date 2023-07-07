using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using SMSApp.Models.DAL;

namespace SMSApp.Controllers
{
    public class ServiceController : Controller
    {
        private IConfiguration Configuration;

        public ServiceController(IConfiguration _configuration)
        {
            Configuration = _configuration;
        }

        public void Index()
        {
            try
            {
                SeatResetDAL mSeatResetDAL = new SeatResetDAL(Configuration);
                string? mId = string.Empty;

                mId = mSeatResetDAL.ResetSPLog("0", "N");

                mSeatResetDAL.ResetSeatLogToday();

                mSeatResetDAL.ResetSPLog(mId, "Y");
            }
            catch (Exception ex)
            {
                string? mServiceLogPath = Configuration.GetValue<string>("AppSettings:ServiceLogPath").ToString();

                System.IO.File.AppendAllText(mServiceLogPath + "LogTest.txt", ex.Message.ToString() + Environment.NewLine);
                System.IO.File.AppendAllText(mServiceLogPath + "LogTest.txt", ex.StackTrace.ToString() + Environment.NewLine);
            }
        }
    }
}
