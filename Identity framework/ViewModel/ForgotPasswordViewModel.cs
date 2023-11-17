using System.ComponentModel.DataAnnotations;

namespace Identity_framework.ViewModel
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
