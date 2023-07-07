using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Transactions;
using System.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Formatters;
using SMSApp.Models.DAL;
using SMSApp.Models.SC;

namespace WebTemplate.Models.BLL
{
    public class FloorBLL
    {
        // Save Floor
        public void SaveFloor(ImageSC vImageSC, FloorSC vFloorSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            ImageDAL mImageDAL = null;

            string mFloorId = string.Empty;
            string mOrgFilePath = string.Empty;
            string mFilePath = string.Empty;
            TransactionScope mTransactionScope = null;
            mTransactionScope = new TransactionScope();

            mFloorDAL = new FloorDAL(_configuration);
            mImageDAL = new ImageDAL(_configuration);

            using (mTransactionScope)
            {
                vFloorSC.FloorImageId = 0;
                mFloorId = mFloorDAL.SaveFloor(vFloorSC);

                if (vFloorSC.FloorImage != null)
                {
                    vImageSC.PId = Convert.ToInt32(mFloorId);
                    mOrgFilePath = vImageSC.PId + Path.GetExtension(vFloorSC.FloorImage.FileName);
                    mFilePath = vImageSC.OrgImagepath + "\\" + mOrgFilePath;

                    using (var stream = System.IO.File.Create(mFilePath))
                    {
                        vFloorSC.FloorImage.CopyTo(stream);
                    }

                    vImageSC.OrgImageName = mOrgFilePath;
                    vImageSC.ImagePath = "~/Uploads/FloorImage/" + mOrgFilePath;
                    mImageDAL.SaveImage(vImageSC);
                }

                mTransactionScope.Complete();
            }

            mTransactionScope.Dispose();
        }

        //Save Floor Mapping
        public void SaveFloorMap(FloorMapSC vFloorMapSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            string mFloorId = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);

            mFloorDAL.SaveFloorMap(vFloorMapSC);
        }

        // Book Seat
        public void BookSeat(FloorMapSC vFloorMapSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            string mFloorId = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);

            mFloorDAL.BookSeat(vFloorMapSC);
        }

        // Seat Book Checkright for IsWFH or not
        public DataSet SeatBookCheckRights(string vCurrUsrId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = new DataSet();

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.SeatBookCheckRights(vCurrUsrId);

            return mDset;
        }

        public DataSet ViewSeatBookList(string vCurrUsrId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = new DataSet();

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.ViewSeatBookList(vCurrUsrId);

            return mDset;
        }

        public void CheckOut(string vCurrUsrId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            string mFloorId = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);

            mFloorDAL.CheckOut(vCurrUsrId);
        }

        // Release Seat
        public void ReleaseSeat(FloorMapSC vFloorMapSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            string mFloorId = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);

            mFloorDAL.ReleaseSeat(vFloorMapSC);
        }

        //View Floor List
        public DataSet ViewFloorList(String vCurrUserId, string vIsActive, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.ViewFloorList(vCurrUserId, vIsActive);

            return mDset;
        }

        public DataSet SeatSearchList(string vLastName, string vFirstName, string vFloorId, string vDeptId, string vCurrUsrId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.SeatSearchList(vLastName, vFirstName, vFloorId, vDeptId, vCurrUsrId);

            return mDset;
        }

        // Floor Get by Id
        public FloorSC FloorGetById(String vFloorId, string vUserId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            FloorSC mFloorSC = null;

            mFloorDAL = new FloorDAL(_configuration);
            mFloorSC = new FloorSC();

            mFloorSC = mFloorDAL.FloorGetById(vFloorId, vUserId);

            return mFloorSC;
        }

        public string  FloorGetByIdValidate(String vFloorId, string vUserId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            FloorSC mFloorSC = null;
            string mIsSuccess = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);
            mFloorSC = new FloorSC();

            mIsSuccess = mFloorDAL.FloorGetByIdValidate(vFloorId, vUserId);

            return mIsSuccess;
        }

        //Edit Floor Map Details by Id
        public IList<FloorMapSC> FloorMapGetById(string? vFloorId, string vId, string vType, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            IList<FloorMapSC> mFloorMapSCList = null;

            mFloorDAL = new FloorDAL(_configuration);
            mFloorMapSCList = new List<FloorMapSC>();

            mFloorMapSCList = mFloorDAL.FloorMapGetById(vFloorId, vId, vType);

            return mFloorMapSCList;
        }

        // Get All Floor
        public DataSet GetAllFloor(IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.GetAllFloorList();

            return mDset;
        }

        // Get All Floor Admin List
        public DataSet GetAllFloorAdminList(IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.GetAllFloorAdminList();

            return mDset;
        }

        // Get All Controller List
        public DataSet GetAllControllerList(IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.GetAllControllerList();

            return mDset;
        }

        // Is User WFH
        public DataSet IsUserWFH(string vUserId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.IsUserWFH(vUserId);

            return mDset;
        }

        // Show All WFH User
        public DataSet ShowAllWFHUserUnderHM(string vFloorId,string vCurrUsrId, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            DataSet mDset = null;

            mFloorDAL = new FloorDAL(_configuration);

            mDset = mFloorDAL.ShowAllWFHUserUnderHM(vFloorId,vCurrUsrId);

            return mDset;
        }

    }
}