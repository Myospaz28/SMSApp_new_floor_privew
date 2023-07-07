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
    public class UserBLL
    {
        // Save and Update new Users
        public void SaveUser(ImageSC vImageSC, UserSC vUserSC, IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            ImageDAL mImageDAL = null;
            TransactionScope mTransactionScope = null;

            string vUserId = string.Empty;
            string mOrgFilePath = string.Empty;
            string mFilePath = string.Empty;

            mTransactionScope = new TransactionScope();
            mUserDAL = new UserDAL(_configuration);
            mImageDAL = new ImageDAL(_configuration);

            using (mTransactionScope)
            {
                if (vUserSC.Password != null)
                    vUserSC.Password = Helper.Encrypt(vUserSC.Password);

                vUserId = mUserDAL.SaveUser(vUserSC);

                if (vUserSC.ProfilePhoto != null)
                {
                    vImageSC.PId = Convert.ToInt32(vUserId);
                    mOrgFilePath = vImageSC.PId + Path.GetExtension(vUserSC.ProfilePhoto.FileName);
                    mFilePath = vImageSC.OrgImagepath + "\\" + mOrgFilePath;

                    using (var stream = System.IO.File.Create(mFilePath))
                    {
                        vUserSC.ProfilePhoto.CopyTo(stream);
                    }

                    vImageSC.OrgImageName = mOrgFilePath;
                    vImageSC.ImagePath = "~/Uploads/ProfileImage/" + mOrgFilePath;
                    mImageDAL.ProfPicImageSave(vImageSC);
                }

                mTransactionScope.Complete();
            }

            mTransactionScope.Dispose();
        }

        // View User List
        public DataSet ViewUserList(String vCurrUserId, IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            DataSet mDset = null;

            mUserDAL = new UserDAL(_configuration);

            mDset = mUserDAL.ViewUserList(vCurrUserId);

            return mDset;
        }

        // Get User by Id
        public UserSC UserGetById(String vRoleId, IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            UserSC mUserSC = null;

            mUserDAL = new UserDAL(_configuration);
            mUserSC = new UserSC();

            mUserSC = mUserDAL.UserGetById(vRoleId);

            return mUserSC;
        }

        public string UserGetByIdValidate(string vUserId, string vCurrUserId, IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            UserSC mUserSC = null;
            string mIsSuccess = string.Empty;

            mUserDAL = new UserDAL(_configuration);
            mUserSC = new UserSC();

            mIsSuccess = mUserDAL.UserGetByIdValidate(vUserId,vCurrUserId);

            return mIsSuccess;
        }

        // Get All Roles
        public DataSet GetAllRoles(IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            DataSet mDset = null;

            mUserDAL = new UserDAL(_configuration);

            mDset = mUserDAL.GetAllRoles();

            return mDset;
        }

        // Get All Department
        public DataSet GetAllDepartment(IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            DataSet mDset = null;

            mUserDAL = new UserDAL(_configuration);

            mDset = mUserDAL.GetAllDepartment();

            return mDset;
        }

        // Get ALl Map Floor
        public DataSet GetAllMapFloor(string vCurrUsrId,IConfiguration _configuration)
        {
            UserDAL mUserDAL = null;
            DataSet mDset = null;

            mUserDAL = new UserDAL(_configuration);

            mDset = mUserDAL.GetAllMapFloor(vCurrUsrId);

            return mDset;
        }

    }
}
