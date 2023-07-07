using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SMSApp.Models.SC
{
	public class RolesSC
	{
		public Int32? RoleId { get; set; }
		public String RoleCode { get; set; }
		public String RoleName { get; set; }
		public String Status { get; set; }
		public String CurrUserId { get; set; }
		public String IsEdit { get; set; }
	}
}