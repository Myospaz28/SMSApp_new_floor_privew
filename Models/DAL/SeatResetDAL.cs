using Microsoft.Practices.EnterpriseLibrary.Data;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Web;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Data.SqlClient;
using System.Configuration;

namespace SMSApp.Models.DAL
{
    public class SeatResetDAL
    {
        static Database CurrentDataBase = null;

        public SeatResetDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        // Seat Reset Today
        public void ResetSeatLogToday()
        {
            DbCommand mDbCommand = null;

            mDbCommand = CurrentDataBase.GetStoredProcCommand("spr_ResetSeatLogToday");

            CurrentDataBase.ExecuteDataSet(mDbCommand);
        }

        // Seat Reset Log
        public string? ResetSPLog(string? vId, string vIsType)
        {
            DbCommand mDbCommand = null;
            string? mId = string.Empty;

            mDbCommand = CurrentDataBase.GetStoredProcCommand("spr_ResetSPLog");

            CurrentDataBase.AddInParameter(mDbCommand, "@vId", DbType.String, vId);
            CurrentDataBase.AddInParameter(mDbCommand, "@vIsType", DbType.String, vIsType);

            mId = CurrentDataBase.ExecuteScalar(mDbCommand).ToString();

            return mId;
        }
    }
}

