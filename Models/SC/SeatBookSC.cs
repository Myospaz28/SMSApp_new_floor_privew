using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;

namespace SMSApp.Models.SC
{
    [Serializable]
    public class SeatBookSC
    {
        public String? IsWFH { get; set; }
        public String CurrUserId { get; set; }

    }
}