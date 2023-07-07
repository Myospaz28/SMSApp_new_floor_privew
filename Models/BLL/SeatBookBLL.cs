using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using Microsoft.AspNetCore.Mvc.Formatters;
using SMSApp.Models.DAL;
using SMSApp.Models.SC;

namespace WebTemplate.Models.BLL
{
    public class SeatBookBLL
    {
        // Save Floor Data
        public void SaveFloor(ImageSC vImageSC, FloorSC vFloorSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            ImageDAL mImageDAL = null;

            string mFloorId = string.Empty;
            string mOrgFilePath = string.Empty;
            string mFilePath = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);
            mImageDAL = new ImageDAL(_configuration);

            vFloorSC.FloorImageId = 0;
            mFloorId = mFloorDAL.SaveFloor(vFloorSC);

            if (vFloorSC.FloorImage != null)
            {
                vImageSC.PId = Convert.ToInt32(mFloorId);
                mOrgFilePath = vImageSC.PId + Path.GetExtension(vFloorSC.FloorImage.FileName);
                mFilePath = _configuration.GetValue<string>("AppSettings:FilePath").ToString() + mOrgFilePath;

                using (var stream = System.IO.File.Create(mFilePath))
                {
                    vFloorSC.FloorImage.CopyTo(stream);
                }

                vImageSC.OrgImageName = mOrgFilePath;
                vImageSC.ImagePath = "~/Uploads/FloorImage/" + mOrgFilePath;
                mImageDAL.SaveImage(vImageSC);
            }
        }

        // Save Floor Map data
        public void SaveFloorMap(FloorMapSC vFloorMapSC, IConfiguration _configuration)
        {
            FloorDAL mFloorDAL = null;
            string mFloorId = string.Empty;

            mFloorDAL = new FloorDAL(_configuration);

            mFloorDAL.SaveFloorMap(vFloorMapSC);
        }

        // View Seat List
        public DataSet ViewSeatList(String vCurrUserId, IConfiguration _configuration)
        {
            SeatBookDAL mSeatBookDAL = null;
            DataSet mDset = null;

            mSeatBookDAL = new SeatBookDAL(_configuration);

            mDset = mSeatBookDAL.ViewSeatList(vCurrUserId);

            return mDset;
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
    }
}