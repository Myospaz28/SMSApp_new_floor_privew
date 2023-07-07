using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SMSApp.Models.SC
{
	[Serializable]
	public class SeatSearchSC
    {
		public Int32? FloorId { get; set; }
		public String? FloorName { get; set; }
        public string? FloorDesc { get; set; }
        public IFormFile? FloorImage { get; set; }
        public int FloorImageId { get; set; }
        public string? RevNO { get; set; }
        public string? FloorCode { get; set; }
        public string? FloorSrNO { get; set; }
        public string? FloorAdmId { get; set; }
        public String? CurrUserId { get; set; }
		public String? IsEdit { get; set; }
        public String? ImgId { get; set; }
        public String? CreatedBy { get; set; }
        public String? ImageName { get; set; }
        public String? ImageDesc { get; set; }
        public String? ImagePath { get; set; }
        public String? UsernameFontsize { get; set; }
        public String? Search { get; set; }


    }
}