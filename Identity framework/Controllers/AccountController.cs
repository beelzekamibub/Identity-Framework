using Identity_framework.Interfaces;
using Identity_framework.Models;
using Identity_framework.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity_framework.Controllers
{
    public class AccountController : Controller
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly SignInManager<IdentityUser> _signInManager;
		private readonly IEmailService _emailService;
		private readonly RoleManager<IdentityRole> _roleManager;
		public AccountController(RoleManager<IdentityRole> roleManager,UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,IEmailService emailService)
		{
			_roleManager = roleManager;
			_emailService = emailService;
			_userManager = userManager;
			_signInManager = signInManager;
		}
		public IActionResult Index()
		{
			return View();
		}
		[HttpGet]
		public IActionResult Login(string? returnUrl=null)
		{
			LoginViewModel loginViewModel = new LoginViewModel();
			loginViewModel.ReturnUrl = returnUrl ?? Url.Content("~/");
            return View(loginViewModel);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Login(LoginViewModel loginViewModel, string returnUrl)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                
                if (user != null)
				{
                    if (!user.EmailConfirmed)
                    {
                        TempData["error"] = "Email not confirmed cant login right now";
                        return View(loginViewModel);
                    }
                    if (await _userManager.IsLockedOutAsync(user))
					{
						ModelState.AddModelError(string.Empty, "Account locked out due to multiple failed login attempts. Try again later.");
						return View(loginViewModel);
					}
					var result = await _signInManager.PasswordSignInAsync(user.UserName, loginViewModel.Password, loginViewModel.RememberMe, lockoutOnFailure: true);
					if (result.Succeeded)
					{
						await _userManager.ResetAccessFailedCountAsync(user);
						return RedirectToAction("Index", "Home");
					}
					else
					{
						if (result.RequiresTwoFactor)
						{
							return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = loginViewModel.RememberMe });
						}
						if (result.IsLockedOut)
						{
							await _userManager.AccessFailedAsync(user);
							ModelState.AddModelError(string.Empty, "Invalid login attempt. Account locked out. Try again later.");
							return View(loginViewModel);
						}
						else
						{
							ModelState.AddModelError(string.Empty, "Invalid login attempt.");
						}
					}
				}
				else
				{
					ModelState.AddModelError("UserName", "Incorrect UserName");
				}
			}
			return View(loginViewModel);
		}
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public IActionResult ExternalLogin(string provider, string returnUrl)
		{
			var redirect = Url.Action("ExternalLoginCallback","Account",new {ReturnUrl=returnUrl});
			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirect);
			return Challenge(properties, provider);
		}
		[HttpGet]
		public async Task<IActionResult> ExternalLoginCallback(string returnurl=null,string remoteError=null)
		{
			if (remoteError != null)
			{
				ModelState.AddModelError("", "Remote error from external login provider");
				return View("Login");
			}
			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				return RedirectToAction("Login");
			}
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,isPersistent:false);
			if (result.Succeeded)
			{
				await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
				return LocalRedirect(returnurl);
			}
			else
			{
				ViewData["returnUrl"] = returnurl;
				ViewData["providerDisplayName"] = info.ProviderDisplayName;
				var email=info.Principal.FindFirstValue(ClaimTypes.Email);
				return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email=email});
			}
		}
		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model,string? returnurl=null)
		{
			returnurl = returnurl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("Error");
				}
				var user = new AppUserModel { UserName = model.Name, Email = model.Email };
				await _signInManager.SignInAsync(user, isPersistent: false);
				await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
				return LocalRedirect(returnurl);
			}
                ViewData["returnUrl"] = returnurl;
			return View(model);
		}

        [HttpGet]
		public IActionResult ForgotPassword()
		{
			return View();
		}

		[HttpPost]
		public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
		{
			if (ModelState.IsValid)
			{
				var user=await _userManager.FindByEmailAsync(forgotPasswordViewModel.Email);
				if (user == null)
				{
					ModelState.AddModelError("Email", "No User with this email address exists");
					return View(forgotPasswordViewModel);
				}
				var code=await _userManager.GeneratePasswordResetTokenAsync(user);
				var reseturl=Url.Action("ResetPassword","Account", new {userId=user.Id,code=code}, Request.Scheme);
				await _emailService.Send("Reset your password", reseturl, forgotPasswordViewModel.Email);
				ModelState.AddModelError("", "reset email sent");
				return View(forgotPasswordViewModel);
			}
			ModelState.AddModelError("Email", "Incorrect email");
			return View(forgotPasswordViewModel);
		}
		[HttpGet]
		public IActionResult ResetPassword(string userId,string code)
		{
			if(code==null)
				return View("Error");
			ResetViewModel resetViewModel = new ResetViewModel { code = code ,UserId=userId};	
			return View(resetViewModel);
		}
        
        [HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(ResetViewModel resetViewModel)
		{
			if (ModelState.IsValid)
			{
				var user=await _userManager.FindByIdAsync(resetViewModel.UserId);
				if (user == null)
				{
					ModelState.AddModelError("", "User not found");
					return View(resetViewModel);
				}
				var result=await _userManager.ResetPasswordAsync(user, resetViewModel.code, resetViewModel.Password);

                return RedirectToAction("Login","Account");
            }
			else
			{
				ModelState.AddModelError("Password", "Passwords do not satisfy criterion");
				return View(resetViewModel);
			}
			
		}

        [HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Logout()
		{
			await _signInManager.SignOutAsync();
			return RedirectToAction("Index", "Home");
		}

		public async Task<IActionResult> Register(string? returnUrl = null)
		{
			//returnUrl to redirect to the page they came from, if they come from from the landing page redirect to home dashboard
			RegisterViewModel registerViewModel = new RegisterViewModel();
			registerViewModel.ReturnUrl = returnUrl;
			return View(registerViewModel);
		}

		[HttpPost]
		public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string? returnUrl=null)
		{
			if(!await _roleManager.RoleExistsAsync("Pokemon"))
			{
				await _roleManager.CreateAsync(new IdentityRole() { Name = "Pokemon" });
                await _roleManager.CreateAsync(new IdentityRole() { Name = "Trainer" });
            }
			registerViewModel.ReturnUrl = returnUrl;
			returnUrl = returnUrl ?? Url.Content("~/");
            //The tilde (~) character in ASP.NET represents the root directory of the application. 
            //if the application is hosted at http://example.com/myapp/, the Url.Content("~/") will resolve to http://example.com/myapp/.
            if (ModelState.IsValid)
			{
				AppUserModel appUser = new AppUserModel { Email=registerViewModel.Email,UserName=registerViewModel.UserName };
				var result = await _userManager.CreateAsync(appUser,registerViewModel.Password);
				if (result.Succeeded)
				{
					var token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
					var Id = appUser.Id;
					var confirmationLink = Url.Action("ConfirmEmail", "Account", new { userId = Id, token = token, returnurl = returnUrl }, Request.Scheme);
					await _emailService.Send("Confirm your email address",confirmationLink, appUser.Email);
					return RedirectToAction("Login", new { returnurl = returnUrl});
				}
				foreach (var error in result.Errors)
				{
					ModelState.AddModelError("", error.Description);
				}
				return View(registerViewModel);
			}
			ModelState.AddModelError("", "Invalid details.");
			return View(registerViewModel);
		}
		[AllowAnonymous]
		[HttpGet]
		public async Task<IActionResult> ConfirmEmail(string userId, string token)
		{
			if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
			{
				TempData["error"] = "Email was not confirmed.";
				return RedirectToAction("Index", "Home");
			}
			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				TempData["error"] = "No User exists with this token/email Id.";
				return RedirectToAction("Index", "Home");
			}
			var res = await _userManager.ConfirmEmailAsync(user, token);
			if (res.Succeeded)
			{
				//await _signInManager.SignInAsync(user, isPersistent: false);
				TempData["success"] = "Email verfied. You can login now.";
				return RedirectToAction("Login", "Account");
			}
			else
			{
				TempData["success"] = "Email confirmation failed. Cant register with this email.";
				return RedirectToAction("Register", "Account");
			}
		}
	}
}
