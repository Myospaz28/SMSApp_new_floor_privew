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
    public class FloorMapSC
    {
        public Int32? Id { get; set; }
        public Int32? FloorId { get; set; }
        public string? FloorName { get; set; }
        public Int32? FloorMapId { get; set; }
        public string? FloorAdmId { get; set; }
        public Int32? UserId { get; set; }
        public string? ImagePath { get; set; }

        [Required]
        [Display(Name = "幅")]
        public string? width { get; set; }

        [Required]
        [Display(Name = "縦")]
        public string? height { get; set; }
        public string? DeptId { get; set; }
        public string? DeptName { get; set; }

        [Required]
        [Display(Name = "座席ID")]
        public string? SeatID { get; set; }

        //[Required]
        [Display(Name = "備考")]
        public string? SeatDetails { get; set; }

        public string? CurrentX { get; set; }
        public string? CurrentY { get; set; }
        public string? IsActive { get; set; }
        public string? IsBook { get; set; }
        public string? IsRelease { get; set; }
        public String CurrUserId { get; set; }
        public String IsEdit { get; set; }
        public String? CreatedBy { get; set; }
        public String? CreatedOn { get; set; }
        public String? BGColor { get; set; }
        public String? IsBooked { get; set; }
        public IList<FloorMapSC> FloorMapLst { get; set; }
        public string FloorMapJSON { get; set; }
        public string? FNKanji { get; set; }
        public string? LNKanji { get; set; }
        public string? IsWFH { get; set; }

        public string? UserDisplay { get; set; }
        public string? UserTitle { get; set; }
        public string? ProfilePhotoPath { get; set; }
        public string? UsernameFontsize { get; set; }
        public string? ActWidth { get; set; }
        public string? ActHeight { get; set; }

    }
}