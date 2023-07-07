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
using Microsoft.EntityFrameworkCore;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Reflection.Metadata;
//using Microsoft.EntityFrameworkCore.Storage;

namespace SMSApp.Models.DAL
{
    public class FloorDAL
    {
        static Database CurrentDataBase = null;

        public FloorDAL(IConfiguration _configuration)
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
                CurrentDataBase.AddInParameter(mDbCommand, "@vUsernameFontsize", DbType.String, vUserSC.UsernameFontsize);
                CurrentDataBase.AddInParameter(mDbCommand, "@vHeight", DbType.String, vUserSC.Height);
                CurrentDataBase.AddInParameter(mDbCommand, "@vWidth", DbType.String, vUserSC.Width);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsEdit", DbType.String, vUserSC.IsEdit);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vUserSC.CurrUserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsActive", DbType.String, vUserSC.Status);

                mFloorId = CurrentDataBase.ExecuteScalar(mDbCommand).ToString();
            }
            catch (Exception ex)
            {
                throw;
            }

            return mFloorId;
        }

        //Save Floor Mapping
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

        // Book Seat
        public void BookSeat(FloorMapSC vFloorMapSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_BookSeat);

                CurrentDataBase.AddInParameter(mDbCommand, "@vId", DbType.String, vFloorMapSC.Id);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorMapSC.FloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vFloorMapSC.UserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorMapId", DbType.String, vFloorMapSC.FloorMapId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsBook", DbType.String, vFloorMapSC.IsBook);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vFloorMapSC.CurrUserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsWFH", DbType.String, vFloorMapSC.IsWFH);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        // Seat Book Checkright for IsWFH or not
        public DataSet SeatBookCheckRights(string vCurrUsrId)
        {
            DataSet mDset = new DataSet();

            try
            {
                DbCommand mDbCommand = null;


                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_SeatBook_CheckRights);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vCurrUsrId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        public void CheckOut(string vCurrUsrId)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_SeatBook_CheckOut);

                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUsrId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        // Release Seat
        public void ReleaseSeat(FloorMapSC vFloorMapSC)
        {
            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_ReleaseSeat);

                CurrentDataBase.AddInParameter(mDbCommand, "@vId", DbType.String, vFloorMapSC.FloorMapId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vFloorMapSC.CurrUserId);

                CurrentDataBase.ExecuteNonQuery(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        //View Floor List
        public DataSet ViewFloorList(String vCurrUserId, string vIsActive)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_GetList);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUserId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vIsActive", DbType.String, vIsActive);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Floor Get by Id
        public FloorSC FloorGetById(string vFloorId, string vUserId)
        {
            DataSet mDset = null;
            FloorSC mFloorSC = null;

            try
            {
                DbCommand mDbCommand = null;

                mFloorSC = new FloorSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_GetById);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    //mFloorSC.ControllerId = mDset.Tables[0].Rows[0]["ControllerId"].ToString();

                    mFloorSC.FloorId = Convert.ToInt32(mDset.Tables[0].Rows[0]["FloorId"]);
                    mFloorSC.FloorCode = mDset.Tables[0].Rows[0]["FloorCode"].ToString();
                    mFloorSC.FloorSrNO = mDset.Tables[0].Rows[0]["FloorSrNO"].ToString();
                    mFloorSC.FloorName = mDset.Tables[0].Rows[0]["FloorName"].ToString();
                    mFloorSC.FloorDesc = mDset.Tables[0].Rows[0]["FloorDesc"].ToString();
                    mFloorSC.RevNO = mDset.Tables[0].Rows[0]["RevNo"].ToString();
                    mFloorSC.UsernameFontsize = mDset.Tables[0].Rows[0]["UsernameFontsize"].ToString();
                    mFloorSC.ControllerName = mDset.Tables[0].Rows[0]["ControllerName"].ToString();
                    mFloorSC.Status = mDset.Tables[0].Rows[0]["IsActive"].ToString();

                    mFloorSC.Height = mDset.Tables[0].Rows[0]["Height"].ToString();
                    mFloorSC.Width = mDset.Tables[0].Rows[0]["Width"].ToString();

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

        // Floor Validate
        public string FloorGetByIdValidate(string vFloorId, string vUserId)
        {
            DataSet mDset = null;
            FloorSC mFloorSC = null;
            string? IsSuccess = string.Empty;

            try
            {
                DbCommand mDbCommand = null;

                mFloorSC = new FloorSC();
                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_Validation);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUsrId", DbType.String, vUserId);

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

        // Floor Map Get by Id
        public IList<FloorMapSC> FloorMapGetById(string? vFloorId, string vId, string vType)
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
                CurrentDataBase.AddInParameter(mDbCommand, "@vType", DbType.String, vType);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);

                if (mDset != null && mDset.Tables.Count > 0 && mDset.Tables[0].Rows.Count > 0)
                {
                    foreach (DataRow mDrow in mDset.Tables[0].Rows)
                    {
                        mFloorMapSC = new FloorMapSC();

                        mFloorMapSC.Id = Convert.ToInt32(mDrow["Id"]);
                        mFloorMapSC.FloorId = Convert.ToInt32(mDrow["FloorId"]);
                        mFloorMapSC.FloorMapId = Convert.ToInt32(mDrow["FloorMapId"]);
                        mFloorMapSC.FNKanji = mDrow["FNName"].ToString();
                        mFloorMapSC.LNKanji = mDrow["LNName"].ToString();
                        mFloorMapSC.width = mDrow["Width"].ToString();
                        mFloorMapSC.height = mDrow["Height"].ToString();
                        mFloorMapSC.SeatID = mDrow["SeatId"].ToString();
                        mFloorMapSC.SeatDetails = mDrow["SeatDetails"].ToString();
                        mFloorMapSC.CurrentX = mDrow["CurrentX"].ToString();
                        mFloorMapSC.CurrentY = mDrow["CurrentY"].ToString();
                        mFloorMapSC.IsActive = mDrow["Status"].ToString();
                        mFloorMapSC.CreatedBy = mDrow["CreatedBy"].ToString();
                        mFloorMapSC.CreatedOn = mDrow["UsageStartTime"].ToString();
                        mFloorMapSC.BGColor = mDrow["BGColor"].ToString();
                        mFloorMapSC.IsBooked = mDrow["IsBooked"].ToString();

                        mFloorMapSC.DeptName = mDrow["DeptName"].ToString();

                        mFloorMapSC.UserDisplay = mDrow["UserDisplay"].ToString();
                        mFloorMapSC.UserTitle = mDrow["UserTitle"].ToString();
                        mFloorMapSC.ProfilePhotoPath = mDrow["ProfilePhotoPath"].ToString();
                        mFloorMapSC.UsernameFontsize = mDrow["UsernameFontsize"].ToString();

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

        // Get Floor List
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

        // Get All Controller List
        public DataSet GetAllControllerList()
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_GetAllControllerList);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Is User WFH
        public DataSet IsUserWFH(string vUserId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_IsUserWFH);
                CurrentDataBase.AddInParameter(mDbCommand, "@vUserId", DbType.String, vUserId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Seat Search List
        public DataSet SeatSearchList(string vLastName, string vFirstName, string vFloorId, string vDeptId, string vCurrUsrId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Seat_Search);
                CurrentDataBase.AddInParameter(mDbCommand, "@vLastName", DbType.String, vLastName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFirstName", DbType.String, vFirstName);
                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vDeptId", DbType.String, vDeptId);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUsrId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // View Seat Book List
        public DataSet ViewSeatBookList(string vCurrUsrId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_SeatBook_GetList);
                CurrentDataBase.AddInParameter(mDbCommand, "@vCurrUserId", DbType.String, vCurrUsrId);

                mDset = CurrentDataBase.ExecuteDataSet(mDbCommand);
            }
            catch (Exception ex)
            {
                throw;
            }

            return mDset;
        }

        // Show All WFH User Under Home Map
        public DataSet ShowAllWFHUserUnderHM(string vFloorId, string vCurrUsrId)
        {
            DataSet mDset = null;

            try
            {
                DbCommand mDbCommand = null;

                mDbCommand = CurrentDataBase.GetStoredProcCommand(StoredProcedures.spr_Floor_ShowAllWFHUserUnderHM);

                CurrentDataBase.AddInParameter(mDbCommand, "@vFloorId", DbType.String, vFloorId);
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

