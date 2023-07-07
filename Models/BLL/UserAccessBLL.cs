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
    public class UserAccessBLL
    {
        // Save User Access
        public void SaveUserAccess(UserAccessSC vUserAccessSC, IConfiguration _configuration)
        {
            UserAccessDAL mUserAccessDAL = null;
            string vUserAccessId = string.Empty;
            TransactionScope mTransactionScope = null;

            mUserAccessDAL = new UserAccessDAL(_configuration);
            mTransactionScope = new TransactionScope();

            using (mTransactionScope)
            {
                vUserAccessSC.UserAccessId = Convert.ToInt32(mUserAccessDAL.SaveUserAccess(vUserAccessSC));

                if (!string.IsNullOrEmpty(vUserAccessSC.UserJSON))
                {
                    vUserAccessSC.UserDT = JsonConvert.DeserializeObject<DataTable>(vUserAccessSC.UserJSON);

                    if (vUserAccessSC.UserDT != null)
                    {
                        if (vUserAccessSC.UserDT.Columns.Contains("$$hashKey"))
                            vUserAccessSC.UserDT.Columns.Remove("$$hashKey");

                        if (vUserAccessSC.UserDT.Columns.Contains("UserName"))
                            vUserAccessSC.UserDT.Columns.Remove("UserName");

                        if (vUserAccessSC.UserDT.Columns.Contains("IsActive"))
                            vUserAccessSC.UserDT.Columns.Remove("IsActive");

                        if (vUserAccessSC.UserDT.Columns.Contains("ActionDate"))
                            vUserAccessSC.UserDT.Columns.Remove("ActionDate");
                    }

                    if (vUserAccessSC.UserDT != null && vUserAccessSC.UserDT.Rows.Count > 0)
                    {
                        if (!string.IsNullOrEmpty(vUserAccessSC.UserAccessId.ToString()))
                        {
                            mUserAccessDAL.SaveUserAccessUsers(vUserAccessSC);
                        }
                    }
                }

                mTransactionScope.Complete();
            }

            mTransactionScope.Dispose();
        }

        // View All User Access
        public DataSet ViewUserAccessList(String vCurrUserId, IConfiguration _configuration)
        {
            UserAccessDAL mUserAccessDAL = null;
            DataSet mDset = null;

            mUserAccessDAL = new UserAccessDAL(_configuration);

            mDset = mUserAccessDAL.ViewUserAccessList(vCurrUserId);

            return mDset;
        }

        // User Access Get by Id
        public UserAccessSC UserAccessGetById(String vUserAccessId, IConfiguration _configuration)
        {
            UserAccessDAL mUserAccessDAL = null;
            UserAccessSC mUserAccessSC = null;

            mUserAccessDAL = new UserAccessDAL(_configuration);
            mUserAccessSC = new UserAccessSC();

            mUserAccessSC = mUserAccessDAL.UserAccessGetById(vUserAccessId);

            return mUserAccessSC;
        }

        public string UserAccessGetByIdValidate(string vUserAccessId, string vCurrUserId, IConfiguration _configuration)
        {
            UserAccessDAL mUserAccessDAL = null;
            UserSC mUserSC = null;
            string mIsSuccess = string.Empty;

            mUserAccessDAL = new UserAccessDAL(_configuration);
            mUserSC = new UserSC();

            mIsSuccess = mUserAccessDAL.UserAccessGetByIdValidate(vUserAccessId, vCurrUserId);

            return mIsSuccess;
        }

        // Get All User List
        public DataSet GetAllUsersList(IConfiguration _configuration)
        {
            UserAccessDAL mUserAccessDAL = null;
            DataSet mDset = null;

            mUserAccessDAL = new UserAccessDAL(_configuration);

            mDset = mUserAccessDAL.GetAllUsersList();

            return mDset;
        }

        // Get All Floor List
        public DataSet GetAllFloorList(string vUserId, string vType, IConfiguration _configuration)
        {
            UserAccessDAL? mUserAccessDAL = null;
            DataSet? mDset = null;

            mUserAccessDAL = new UserAccessDAL(_configuration);

            mDset = mUserAccessDAL.GetAllFloorList(vUserId, vType);

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
    }
}
