using System.ComponentModel.DataAnnotations;

namespace Identity_framework.ViewModel
{
	public class RegisterViewModel
	{
		[Required]
		[EmailAddress]
		[Display(Name ="Email")]
		public string Email { get; set; }

		[Required]
		[StringLength(100,ErrorMessage ="The {0} must be between {2} and 100 characters long.", MinimumLength =6)]
		[DataType(DataType.Password)]// it indicates to the view engine that the associated input field should be rendered as an HTML input element of type password.
		[Display(Name ="Password")]
		public string Password { get; set; }

		[Required]
		[Compare("Password", ErrorMessage = "The passwords dont match.")]
		[DataType(DataType.Password)] // it indicates to the view engine that the associated input field should be rendered as an HTML input element of type password.
		[Display(Name = "Confirm Password")]
		public string ConfirmPassword { get; set; }

		public string? ReturnUrl { get; set; }

		[Required]
		[Display(Name ="UserName")]
		public string UserName { get; set; }

	}
}
