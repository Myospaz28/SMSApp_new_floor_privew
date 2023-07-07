using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SMSApp.Models.SC
{
	[Serializable]
	public class ImageSC
    {
		public Int32? ImgId { get; set; }
        public Int32? PId { get; set; }
        public String ImageName { get; set; }
        public String OrgImageName { get; set; }
        public string? ImageDesc { get; set; }
        public string? ImagePath { get; set; }
		public String CurrUserId { get; set; }
		public String? IsEdit { get; set; }
        public String? OrgImagepath { get; set; }
        public String? TestPath { get; set; }
    }
}