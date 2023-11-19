using System.ComponentModel.DataAnnotations;

namespace Identity_framework.ViewModel
{
    public class LoginViewModel
    {
/*        [Required]
        [EmailAddress]
        public string Email { get; set; }*/

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name ="Remember Me?")]
        public bool RememberMe { get; set; }
        public string? ReturnUrl { get; set; }
    }
}
