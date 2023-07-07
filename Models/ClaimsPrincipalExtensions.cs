using System.Security.Claims;

namespace SMSApp.Models
{
    internal static class ClaimsPrincipalExtensions
    {
        internal static string GetEmail(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.Email);
        internal static string GetFirstName(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.Name);
        internal static string GetLastName(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.Surname);
        internal static string GetPhoneNumber(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.MobilePhone);
        internal static string GetUserId(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
        internal static string GetRoleCode(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.PrimarySid);
        internal static string GetRoleName(this ClaimsPrincipal claimsPrincipal) => claimsPrincipal.FindFirstValue(ClaimTypes.Role);
    }
}
