using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Identity_framework.ViewModel
{
    public class ResetViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string  Password { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "The passwords dont match.")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }
        public string UserId { get; set; }
        public string code { get; set; }
    }
}
