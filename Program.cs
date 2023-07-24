using AspNetCore.Unobtrusive.Ajax;
using Microsoft.AspNetCore.Authentication.Cookies;
//using System.Web.Services.Description;

using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login/Index";
    });

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();
//.AddCookie(options =>
//{
//    options.LoginPath = "/Login/Index";
//});

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});
builder.Services.AddHttpContextAccessor();
//builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15);
});
builder.Services.AddControllersWithViews(option =>
{
    var policy = new AuthorizationPolicyBuilder(CookieAuthenticationDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();
    option.Filters.Add(new AuthorizeFilter(policy));
}).AddRazorRuntimeCompilation();

//builder.Services.Configure<IISOptions>(options =>
//{
//    options.AutomaticAuthentication = false;
//});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.UseUnobtrusiveAjax();

//app.UseSession();

//var services = app.Services.GetService<ISomeService>();
//services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();