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
//using Microsoft.EntityFrameworkCore.Storage;

namespace SMSApp.Models.DAL
{
    public class UserDAL
    {
        static Database CurrentDataBase = null;

        public UserDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        // Save Users
        public string SaveUser(UserSC vUserSC)
        {
            string? vUserId = string.Empty;
            DbCommand? mDbCommand = null;

            try
            {
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vUserSC.UserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFNKanji", DbType.String, vUserSC.FNKanji);
                CurrentDataBase.AddInParameter(mDbCommand, "@vLNKanji", DbType.String, vUserSC.LNKanji);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFNFurigana", DbType.String, vUserSC.FNFurigana);
                CurrentDataBase.AddInParameter(mDbCommand, "@vLNFurigana", DbType.String, vUserSC.LNFurigana);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFNRomaji", DbType.String, vUserSC.FNRomaji);
                CurrentDataBase.AddInParameter(mDbCommand, "@vLNRomaji", DbType.String, vUserSC.LNRomaji);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsActive", DbType.String, vUserSC.Status);
                CurrentDataBase.AddInParameter(mDbCommand, "@vRoleId", DbType.String, vUserSC.RoleId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vDeptId", DbType.String, vUserSC.DeptId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vUserSC.FloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUsername", DbType.String, vUserSC.Username);
                CurrentDataBase.AddInParameter(mDbCommand, "@vPassword", DbType.String, vUserSC.Password);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUserDisp", DbType.String, vUserSC.UserDisplayName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUserTitle", DbType.String, vUserSC.UserTitle);
                CurrentDataBase.AddInParameter(mDbCommand, "@vHomeMapId", DbType.String, vUserSC.HomeMapId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vUserSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vUserSC.CurrUserId);

                vUserId = CurrentDataBase.ExecuteScalar(mDbCommand).ToString();
            }
            catch (Exception ex)
            {
                throw;
            }
            return vUserId;
        }

        // Save User Floor Map
        public void SaveUserFloorMap(UserSC vUserSC)
        {
            string vUserId = string.Empty;
            DbCommand mDbCommand = null;

            try
            {
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_FloorMap);

                SqlParameter param = new SqlParameter("@vUserFloorListUT", vUserSC.FloorSelectDT);
                param.SqlDbType = SqlDbType.Structured;

                mDbCommand.Parameters.Add(param);

                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vUserSC.UserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vUserSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vUserSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        // View User List
        public DataSet ViewUserList(String vCurrUserId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_GetUserList);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);


            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        

        // User Get by Id
        public UserSC UserGetById(string vUserId)
        {
            DataSet mDset = null;
            UserSC mUserSC = null;

            try
            {
                DbCommand mDbCommand = null;

                mUserSC = new UserSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_GetUserById);

                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    mUserSC.UserId = Convert.ToInt32(mDset.Tables[0].Rows[0]["UserId"]);
                    mUserSC.Username = mDset.Tables[0].Rows[0]["Username"].ToString();

                    mUserSC.Password = Helper.Decrypt(mDset.Tables[0].Rows[0]["Password"].ToString());

                    mUserSC.FNKanji = mDset.Tables[0].Rows[0]["FNKanji"].ToString();
                    mUserSC.LNKanji = mDset.Tables[0].Rows[0]["LNKanji"].ToString();
                    mUserSC.FNFurigana = mDset.Tables[0].Rows[0]["FNFurigana"].ToString();
                    mUserSC.LNFurigana = mDset.Tables[0].Rows[0]["LNFurigana"].ToString();
                    mUserSC.FNRomaji = mDset.Tables[0].Rows[0]["FNRomaji"].ToString();
                    mUserSC.LNRomaji = mDset.Tables[0].Rows[0]["LNRomaji"].ToString();
                    mUserSC.RoleId = mDset.Tables[0].Rows[0]["RoleId"].ToString();
                    mUserSC.DeptId = mDset.Tables[0].Rows[0]["DeptId"].ToString();
                    mUserSC.FloorId = mDset.Tables[0].Rows[0]["FloorId"].ToString();
                    mUserSC.Status = mDset.Tables[0].Rows[0]["Status"].ToString();
                    mUserSC.UserDisplayName = mDset.Tables[0].Rows[0]["UserDisplay"].ToString();
                    mUserSC.UserTitle = mDset.Tables[0].Rows[0]["UserTitle"].ToString();
                    mUserSC.HomeMapId = mDset.Tables[0].Rows[0]["HomeMapId"].ToString();

                    mUserSC.ProfilePhotoName = mDset.Tables[0].Rows[0]["ProfilePhoto"].ToString();
                    mUserSC.ProfilePhotoPath = mDset.Tables[0].Rows[0]["ProfilePhotoPath"].ToString();
                    mUserSC.ImgId = mDset.Tables[0].Rows[0]["ImgId"].ToString();
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mUserSC;
        }

        public string UserGetByIdValidate(string vUserId, string vCurrUserId)
        {
            DataSet mDset = null;
            FloorSC mFloorSC = null;
            string? IsSuccess = string.Empty;

            try
            {
                DbCommand mDbCommand = null;

                mFloorSC = new FloorSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_Validation);

                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vUserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vCurrUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    IsSuccess = mDset.Tables[0].Rows[0]["IsSuccess"].ToString();
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return IsSuccess;
        }

        // Get All Roles
        public DataSet GetAllRoles()
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetAllRoles);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Get ALl Department
        public DataSet GetAllDepartment()
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetAllDepartment);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Get All Map Floor
        public DataSet GetAllMapFloor(string vCurrUsrId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_UserAccess_GetAllMapFloor);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vCurrUsrId);

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

