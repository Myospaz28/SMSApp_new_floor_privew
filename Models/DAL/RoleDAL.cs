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
//using Microsoft.EntityFrameworkCore.Storage;

namespace SMSApp.Models.DAL
{
    public class RoleDAL
    {
        static Database CurrentDataBase = null;

        public RoleDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        // Save Roles
        public void SaveRoles(RolesSC vRolesSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Role_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vRoleId", DbType.String, vRolesSC.RoleId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vRoleName", DbType.String, vRolesSC.RoleName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vRolesSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vRolesSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        // Get ALl Roles List
        public DataSet RoleViewList(String vCurrUserId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Roles_GetList);

                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Role Get by Id
        public RolesSC RoleGetById(String vRoleId)
        {
            DataSet mDset = null;
            RolesSC mRolesSC = null;
            try
            {
                DbCommand mDbCommand = null;

                mRolesSC = new RolesSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand("");

                CurrentDataBase.AddInParameter(mDbCommand, "@vRoleId", DbType.String, vRoleId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    mRolesSC.RoleId = Convert.ToInt32(mDset.Tables[0].Rows[0]["RoleId"]);
                    mRolesSC.RoleCode = mDset.Tables[0].Rows[0]["RoleCode"].ToString();
                    mRolesSC.RoleName = mDset.Tables[0].Rows[0]["RoleName"].ToString();
                    mRolesSC.Status = mDset.Tables[0].Rows[0]["OrgStatus"].ToString();
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mRolesSC;
        }
    }
}