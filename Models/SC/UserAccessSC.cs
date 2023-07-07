using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;

namespace SMSApp.Models.SC
{
    [Serializable]
    public class UserAccessSC
    {
        public Int32? UserAccessId { get; set; }
        public String? FloorId { get; set; }
        public String? FloorName { get; set; }
        public string? FloorDesc { get; set; }
        public string? User { get; set; }
        public DataTable? UserDT { get; set; }
        public String? UserJSON { get; set; }
        public String? IsActive { get; set; }
        public String CurrUserId { get; set; }
        public String IsEdit { get; set; }

    }
}