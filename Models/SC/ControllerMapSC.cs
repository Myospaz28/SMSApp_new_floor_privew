using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Web;
using System.Xml.Linq;

namespace SMSApp.Models.SC
{
    [Serializable]
    public class ControllerMapSC
    {
        public Int32? ControllerMapId { get; set; }

        [Required]
        [Display(Name = "管理部門名")]
        public String? ControllerName { get; set; }

        [Required]
        [Display(Name = "管理部門詳細")]
        public String? ControllerDesc { get; set; }

        public String FloorListJson { get; set; }
        public DataTable? FloorList { get; set; }

        public String? Status { get; set; }
        public String CurrUserId { get; set; }
        public String IsEdit { get; set; }

        public String? CreatedBy { get; set; }
        public String? CreatedOn { get; set; }
    }

    public class FloorList
    {
        public string FloorId { get; set; }
        public string FloorName { get; set; }
    }
}