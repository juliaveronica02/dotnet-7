using System.ComponentModel.DataAnnotations;

namespace WebApplication1.DTO
{
	public class AuthDTO
	{
		[Required]
		public string? Username { get; set; }
		[Required]
		public long? Phone { get; set; }
		[Required(ErrorMessage = "Email is required")]
		[EmailAddress(ErrorMessage = "Invalid email address")]
		public string? Email { get; set; }
		[Required(ErrorMessage = "Password is required")]
		[MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
		[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
		ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")]
		public string? Password { get; set; }
		[Required]
		public string? PasswordConfirm { get; set; }
	}
}
