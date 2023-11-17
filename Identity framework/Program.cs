using Identity_framework.Data;
using Identity_framework.Interfaces;
using Identity_framework.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace Identity_framework
{
    public class Program
	{
		public static void Main(string[] args)
		{
			var builder = WebApplication.CreateBuilder(args);

			// Add services to the container.
			builder.Services.AddTransient<IEmailService,EmailService>();
			builder.Services.AddDbContext<IdentityContext>(e => e.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

			builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<IdentityContext>().AddDefaultTokenProviders();

			builder.Services.AddControllersWithViews();

			builder.Services.Configure<IdentityOptions>(opt =>
				{
					opt.Password.RequiredLength = 5;
					opt.Password.RequireUppercase = true;
					opt.Password.RequireLowercase = true;
					opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(10);
					opt.Lockout.MaxFailedAccessAttempts = 5;
					opt.SignIn.RequireConfirmedAccount = true;
				}
			);

			var app = builder.Build();

			// Configure the HTTP request pipeline.
			if (!app.Environment.IsDevelopment())
			{
				app.UseExceptionHandler("/Home/Error");
				// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
				app.UseHsts();
			}

			app.UseHttpsRedirection();
			app.UseStaticFiles();

			app.UseRouting();

			app.UseAuthorization();

			app.MapControllerRoute(
				name: "default",
				pattern: "{controller=Home}/{action=Index}/{id?}");

			app.Run();
		}
	}
}