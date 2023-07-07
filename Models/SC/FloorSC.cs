using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using System.Xml.Linq;

namespace SMSApp.Models.SC
{
    [Serializable]
    public class FloorSC
    {
        public Int32? FloorId { get; set; }

        //[Required]
        [Display(Name = "フロア名")]
        public String? FloorName { get; set; }

        public string? FloorDesc { get; set; }

        //[Required]
        [Display(Name = "詳細")]
        public IFormFile? FloorImage { get; set; }
        public int FloorImageId { get; set; }
        public string? RevNO { get; set; }
        public string? FloorCode { get; set; }
        public string? FloorSrNO { get; set; }
        public string? ControllerId { get; set; }
        public string? FloorAdmId { get; set; }
        public String? CurrUserId { get; set; }
        public String? IsEdit { get; set; }
        public String? ImgId { get; set; }
        public String? CreatedBy { get; set; }
        public String? ImageName { get; set; }
        public String? ImageDesc { get; set; }
        public String? ImagePath { get; set; }
        public String? UsernameFontsize { get; set; }
        public String? ControllerName { get; set; }
        public String? Status { get; set; }
        public String? Height { get; set; }
        public String? Width { get; set; }

    }
}