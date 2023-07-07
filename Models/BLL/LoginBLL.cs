using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Transactions;
using System.Web;
using Newtonsoft.Json;
using SMSApp.Models;
using SMSApp.Models.DAL;
using SMSApp.Models.SC;

namespace WebTemplate.Models.BLL
{
    public class LoginBLL
    {
        // User Authentication
        public DataSet UserAuthenticate(string vUsername, string vPassword, IConfiguration _configuration)
        {
            LoginDAL mLoginDAL = null;
            DataSet mDset = null;

            mLoginDAL = new LoginDAL(_configuration);

            mDset = mLoginDAL.UserAuthenticate(vUsername, vPassword);

            return mDset;
        }
    }
}