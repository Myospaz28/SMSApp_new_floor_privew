using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Linq;
using System.Web;
using System.Xml.Linq;

namespace SMSApp.Models.SC
{
    [Serializable]
    public class UserSC
    {
        public Int32? UserId { get; set; }
        public String EmpCode { get; set; }

        [Required]
        [Display(Name = "名（漢字")]
        public string? FNKanji { get; set; }

        [Required]
        [Display(Name = "姓（漢字")]
        public string? LNKanji { get; set; }

        public string? FNFurigana { get; set; }
        public string? LNFurigana { get; set; }
        public string? FNRomaji { get; set; }
        public string? LNRomaji { get; set; }
        public String EmpName { get; set; }
        public String? RoleId { get; set; }
        public String? HomeMapId { get; set; }
        public String? FloorId { get; set; }
        public String? DeptId { get; set; }
        public String RoleName { get; set; }
        public String EmailId { get; set; }
        public String MobNo { get; set; }

        [Required]
        [Display(Name = "ユーザID")]
        public String? Username { get; set; }

        [Required]
        [Display(Name = "Password")]
        public String? Password { get; set; }

        public String? Status { get; set; }
        public String CurrUserId { get; set; }
        public String IsEdit { get; set; }
        public String FloorSelect { get; set; }
        public IList<FloorSelect>? FloorSelectLst { get; set; }
        public DataTable? FloorSelectDT { get; set; }
        public String? UserDisplayName { get; set; }
        public String? UserTitle { get; set; }
        public IFormFile? ProfilePhoto { get; set; }
        public string? ProfilePhotoName { get; set; }
        public String? ProfilePhotoPath { get; set; }
        public String? ImgId { get; set; }
        public String? PageType { get; set; }
        public String? HomeMap { get; set; }
    }

    public class FloorSelect
    {
        public String RowId { get; set; }
        public String FloorId { get; set; }
        public String FloorName { get; set; }
        public String Select { get; set; }
        public String IsType { get; set; }
    }
}