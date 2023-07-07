using Microsoft.Practices.EnterpriseLibrary.Data;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Web;
using SMSApp.Models.SC;
using Microsoft.Extensions.Configuration;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using Microsoft.AspNetCore.Identity;
using System.Data.SqlClient;
using Newtonsoft.Json;

namespace SMSApp.Models.DAL
{
    public class LoginDAL
    {
        static Database CurrentDataBase = null;

        public LoginDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }
        
        // User Authentication
        public DataSet UserAuthenticate(string vUsername,string vPassword)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_Authenticate);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUsername", DbType.String, vUsername);
                CurrentDataBase.AddInParameter(mDbCommand, "@vPassword", DbType.String, vPassword);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }
    }
}

