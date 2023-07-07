using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SMSApp.Controllers
{
    public static class ModelStateHelper
    {
        public static IEnumerable Errors(this ModelStateDictionary modelState)
        {
            if (!modelState.IsValid)
            {
                return modelState.ToDictionary(kvp => kvp.Key,
                    kvp => kvp.Value.Errors
                                    .Select(e => e.ErrorMessage).ToArray())
                                    .Where(m =>		m.Value.Count() > 0);
            }
            return null;
        }
    }
}