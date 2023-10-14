using Identity_framework.Models;
using Identity_framework.ViewModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity_framework.Controllers
{
	public class AccountController : Controller
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly SignInManager<IdentityUser> _signInManager;
		public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
		{
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
				var result = await _signInManager.PasswordSignInAsync(loginViewModel.UserName,loginViewModel.Password,loginViewModel.RememberMe,lockoutOnFailure:false);
				if (result.Succeeded)
				{
					return RedirectToAction("Index", "Home");
				}
				else
				{
					ModelState.AddModelError("","Login failed for the provided credentials.");
					return View(loginViewModel);
				}
			}
			return View(loginViewModel);
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
					await _signInManager.SignInAsync(appUser, isPersistent: false);//if set to true gives us a persistent cookie beyond the browser session
					return LocalRedirect(returnUrl);
				}
				ModelState.AddModelError("Email","User with this email already exists.");
			}
			return View(registerViewModel);
		}
	}
}
