using System.ComponentModel.DataAnnotations;

namespace Identity_framework.ViewModel
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public string? Name { get; set; }
    }
}
