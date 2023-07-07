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
//using Microsoft.EntityFrameworkCore.Storage;

namespace SMSApp.Models.DAL
{
    public class ImageDAL
    {
        static Database CurrentDataBase = null;

        public ImageDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        // Save Image
        public void SaveImage(ImageSC vImageSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Image_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vImgId", DbType.String, vImageSC.ImgId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vPId", DbType.String, vImageSC.PId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vImageName", DbType.String, vImageSC.ImageName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vOrgImageName", DbType.String, vImageSC.OrgImageName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vImageDesc", DbType.String, "");
                CurrentDataBase.AddInParameter(mDbCommand, "@vImagePath", DbType.String, vImageSC.ImagePath);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vImageSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vImageSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        // Profile Image Save
        public void ProfPicImageSave(ImageSC vImageSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_User_ProfPicImage_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vImgId", DbType.String, vImageSC.ImgId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vPId", DbType.String, vImageSC.PId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vImageName", DbType.String, vImageSC.ImageName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vOrgImageName", DbType.String, vImageSC.OrgImageName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vImageDesc", DbType.String, "");
                CurrentDataBase.AddInParameter(mDbCommand, "@vImagePath", DbType.String, vImageSC.ImagePath);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vImageSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vImageSC.CurrUserId);

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

                    mUserSC.FNKanji = mDset.Tables[0].Rows[0]["FNKanji"].ToString();
                    mUserSC.LNKanji = mDset.Tables[0].Rows[0]["LNKanji"].ToString();
                    mUserSC.FNFurigana = mDset.Tables[0].Rows[0]["FNFurigana"].ToString();
                    mUserSC.LNFurigana = mDset.Tables[0].Rows[0]["LNFurigana"].ToString();
                    mUserSC.FNRomaji = mDset.Tables[0].Rows[0]["FNRomaji"].ToString();
                    mUserSC.LNRomaji = mDset.Tables[0].Rows[0]["LNRomaji"].ToString();

                    mUserSC.RoleId = mDset.Tables[0].Rows[0]["RoleId"].ToString();

                    mUserSC.Status = mDset.Tables[0].Rows[0]["Status"].ToString();
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mUserSC;
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
    }
}

