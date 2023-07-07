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
    public class ControllerMapDAL
    {
        static Database CurrentDataBase = null;

        public ControllerMapDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        //For new Controller Mapping
        public void SaveControllerMap(ControllerMapSC vControllerMapSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_ControllerMap_Save);

                SqlParameter param = new SqlParameter("@vFloorListUT", vControllerMapSC.FloorList);
                param.SqlDbType = SqlDbType.Structured;

                mDbCommand.Parameters.Add(param);

                CurrentDataBase.AddInParameter(mDbCommand, "@vControllerId", DbType.String, vControllerMapSC.ControllerMapId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vControllerName", DbType.String, vControllerMapSC.ControllerName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vControllerDesc", DbType.String, vControllerMapSC.ControllerDesc);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vControllerMapSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vControllerMapSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        //View Controller Mapping
        public DataSet ViewControllerMapList(String vCurrUserId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_ControllerMap_GetList);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        //Edit Controller Mapping
        public ControllerMapSC ControllerMapGetById(string vControllerMapId)
        {
            DataSet? mDset = null;
            ControllerMapSC? mControllerMapSC = null;

            try
            {
                DbCommand mDbCommand = null;

                mControllerMapSC = new ControllerMapSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_ControllerMap_GetById);

                CurrentDataBase.AddInParameter(mDbCommand, "@vControllerMapId", DbType.String, vControllerMapId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    mControllerMapSC.ControllerMapId = Convert.ToInt32(mDset.Tables[0].Rows[0]["ControllerId"]);
                    mControllerMapSC.ControllerName = mDset.Tables[0].Rows[0]["ControllerName"].ToString();
                    mControllerMapSC.ControllerDesc = mDset.Tables[0].Rows[0]["ControllerDesc"].ToString();

                    mControllerMapSC.Status = mDset.Tables[0].Rows[0]["Status"].ToString();

                    mControllerMapSC.CreatedBy = mDset.Tables[0].Rows[0]["CreatedBy"].ToString();
                    mControllerMapSC.CreatedOn = mDset.Tables[0].Rows[0]["CreatedOn"].ToString();

                    mControllerMapSC.FloorListJson = JsonConvert.SerializeObject(mDset.Tables[1]);
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mControllerMapSC;
        }

        public string ControllerMapGetByIdValidate(string vControllerId, string vCurrUserId)
        {
            DataSet mDset = null;
            FloorSC mFloorSC = null;
            string? IsSuccess = string.Empty;

            try
            {
                DbCommand mDbCommand = null;

                mFloorSC = new FloorSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Controller_Validation);

                CurrentDataBase.AddInParameter(mDbCommand, "@vControllerId", DbType.String, vControllerId);
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

        //Get All Floor List
        public DataSet GetAllFloor(string vCurrUsrID)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetAllFloor);

                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUsrID);

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

