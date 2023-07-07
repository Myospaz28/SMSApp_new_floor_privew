using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;
using SMSApp.Models.DAL;
using SMSApp.Models.SC;

namespace WebTemplate.Models.BLL
{
    public class RoleBLL
	{
		// Save Roles
        public void SaveRoles(RolesSC vRolesSC,IConfiguration _configuration)
        {
            RoleDAL mRoleDAL = null;

			mRoleDAL = new RoleDAL(_configuration);

			mRoleDAL.SaveRoles(vRolesSC);
        }

		// Get All Roles List
		public DataSet RoleViewList(String vCurrUserId, IConfiguration _configuration)
		{
			RoleDAL mRoleDAL = null;
			DataSet mDset = null;

			mRoleDAL = new RoleDAL(_configuration);

			mDset = mRoleDAL.RoleViewList(vCurrUserId);

			return mDset;
		}

		// Role get by id
		public RolesSC RoleGetById(String vRoleId, IConfiguration _configuration)
		{
			RoleDAL mRoleDAL = null;
			RolesSC mRolesSC = null;

			mRoleDAL = new RoleDAL(_configuration);
			mRolesSC = new RolesSC();

			mRolesSC = mRoleDAL.RoleGetById(vRoleId);

			return mRolesSC;
		}
	}
}
