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
    public class SeatBookDAL
    {
        static Database CurrentDataBase = null;

        public SeatBookDAL(IConfiguration _configuration)
        {
            CurrentDataBase = new SqlDatabase(_configuration.GetConnectionString("DBConn"));
        }

        // Save Floor
        public string SaveFloor(FloorSC vUserSC)
        {
            string? mFloorId = string.Empty;

            try
            {
                DbCommand? mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vUserSC.FloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorCode", DbType.String, vUserSC.FloorCode);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorSrNO", DbType.String, vUserSC.FloorSrNO);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorName", DbType.String, vUserSC.FloorName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorDesc", DbType.String, vUserSC.FloorDesc);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorImageId", DbType.String, vUserSC.FloorImageId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vRevNo", DbType.String, vUserSC.RevNO);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vUserSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vUserSC.CurrUserId);

                mFloorId = CurrentDataBase.ExecuteScalar(mDbCommand).ToString();
            }
            catch (Exception ex)
            {
                throw;
            }

            return mFloorId;
        }

        // Save Floor Map
        public string SaveFloorMap(FloorMapSC vFloorMapSC)
        {
            string? mFloorId = string.Empty;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_FloorMap_Save);

                CurrentDataBase.AddInParameter(mDbCommand, "@vId", DbType.String, vFloorMapSC.Id);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorMapSC.FloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vWidth", DbType.String, vFloorMapSC.width);
                CurrentDataBase.AddInParameter(mDbCommand, "@vheight", DbType.String, vFloorMapSC.height);
                CurrentDataBase.AddInParameter(mDbCommand, "@vDeptId", DbType.String, vFloorMapSC.DeptId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vSeatId", DbType.String, vFloorMapSC.SeatID);
                CurrentDataBase.AddInParameter(mDbCommand, "@vSeatDetails", DbType.String, vFloorMapSC.SeatDetails);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrentX", DbType.String, vFloorMapSC.CurrentX);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrentY", DbType.String, vFloorMapSC.CurrentY);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsActive", DbType.String, vFloorMapSC.IsActive);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vFloorMapSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vFloorMapSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mFloorId;
        }

        // View All Seat List
        public DataSet ViewSeatList(String vCurrUserId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_SeatBook_GetList);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vCurrUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Floor Get by Id
        public FloorSC FloorGetById(string vFloorId)
        {
            DataSet mDset = null;
            FloorSC mFloorSC = null;

            try
            {
                DbCommand mDbCommand = null;

                mFloorSC = new FloorSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_GetById);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    mFloorSC.FloorId = Convert.ToInt32(mDset.Tables[0].Rows[0]["FloorId"]);
                    mFloorSC.FloorCode = mDset.Tables[0].Rows[0]["FloorCode"].ToString();
                    mFloorSC.FloorSrNO = mDset.Tables[0].Rows[0]["FloorSrNO"].ToString();
                    mFloorSC.FloorName = mDset.Tables[0].Rows[0]["FloorName"].ToString();
                    mFloorSC.FloorDesc = mDset.Tables[0].Rows[0]["FloorDesc"].ToString();
                    mFloorSC.RevNO = mDset.Tables[0].Rows[0]["RevNo"].ToString();

                    mFloorSC.CreatedBy = mDset.Tables[0].Rows[0]["CreatedBy"].ToString();
                    mFloorSC.ImgId = mDset.Tables[0].Rows[0]["ImgId"].ToString();
                    mFloorSC.ImageName = mDset.Tables[0].Rows[0]["ImageName"].ToString();
                    mFloorSC.ImageDesc = mDset.Tables[0].Rows[0]["ImageDesc"].ToString();
                    mFloorSC.ImagePath = mDset.Tables[0].Rows[0]["ImagePath"].ToString();
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mFloorSC;
        }
        
        // Get Floor Map Get by Id
        public IList<FloorMapSC> FloorMapGetById(string vFloorId, string vId)
        {
            DataSet mDset = null;
            FloorMapSC mFloorMapSC = null;
            IList<FloorMapSC> mFloorMapSCList = null;

            try
            {
                DbCommand mDbCommand = null;

                mFloorMapSCList = new List<FloorMapSC>();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetFloorMapDtls);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vId", DbType.String, vId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    foreach (DataRow mDrow in mDset.Tables[0].Rows)
                    {
                        mFloorMapSC = new FloorMapSC();

                        mFloorMapSC.Id = Convert.ToInt32(mDrow["Id"]);
                        mFloorMapSC.FloorId = Convert.ToInt32(mDrow["FloorId"]);
                        mFloorMapSC.width = mDrow["Width"].ToString();
                        mFloorMapSC.height = mDrow["Height"].ToString();
                        mFloorMapSC.DeptId = mDrow["DeptId"].ToString();
                        mFloorMapSC.SeatID = mDrow["SeatId"].ToString();
                        mFloorMapSC.SeatDetails = mDrow["SeatDetails"].ToString();
                        mFloorMapSC.CurrentX = mDrow["CurrentX"].ToString();
                        mFloorMapSC.CurrentY = mDrow["CurrentY"].ToString();
                        mFloorMapSC.IsActive = mDrow["Status"].ToString();
                        mFloorMapSC.CreatedBy = mDrow["CreatedBy"].ToString();
                        mFloorMapSC.CreatedOn = mDrow["CreatedOn"].ToString();
                        mFloorMapSCList.Add(mFloorMapSC);
                    }

                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return mFloorMapSCList;
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

        // Get All Floor List
        public DataSet GetAllFloorList()
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetAllFloorList);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Get All Floor Admin List
        public DataSet GetAllFloorAdminList()
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_FloorAdmin_List);

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

