using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.DTO;
using WebApplication1.Entities;
using System.Security.Cryptography;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace WebApplication1.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly DotnetAuthenticationContext _DBContext;
		private readonly IConfiguration _configuration;

		public AuthController(DotnetAuthenticationContext dbContext, IConfiguration configuration)
		{
			_DBContext = dbContext;
			_configuration = configuration;
		}

		// create user (register function).
		[HttpPost("create")]
		public async Task<IActionResult> CreateUser(AuthDTO request)
		{
			// find existing email. if email already exists will send message.
			var existingUser = await _DBContext.Auths.FirstOrDefaultAsync(e => e.Email == request.Email);
			if (existingUser != null)
			{
				return BadRequest(new { email = "Email already exists!" });
			}

			// find user by phone number.
			var existingUserByPhone = await _DBContext.Auths.FirstOrDefaultAsync(p => p.Phone == request.Phone);
			if (existingUserByPhone != null)
			{
				return BadRequest(new { phone = "Phone Number already exists" });
			}

			// create new user (register).
			var newUser = new Auth
			{
				Username = request.Username,
				Phone = (long)request.Phone,
				Email = request.Email,
				Password = request.Password
			};

			// check password is match or not.
			if (request.Password != request.PasswordConfirm)
			{
				return BadRequest("Password confirmation does not match!");
			}

			newUser.Password = HashPassword(newUser.Password);

			await _DBContext.Auths.AddAsync(newUser);
			await _DBContext.SaveChangesAsync();

			return Ok(newUser);
		}

		// hashing password function.
		private string HashPassword(string password)
		{
			using (SHA256 sha256 = SHA256.Create())
			{
				byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
				StringBuilder builder = new StringBuilder();
				foreach (byte b in hashedBytes)
				{
					builder.Append(b.ToString("x2"));
				}
				return builder.ToString();
			}
		}

		// user login.
		[HttpPost("Login")]
		public async Task<IActionResult> LoginAuthentication(LoginRequest request)
		{
			string email = request.Email;
			long phone = (long)request.Phone;
			string password = request.Password;

			// email and phone condition for login user account. choose one.
			object conditions;
			if (!string.IsNullOrEmpty(email))
			{
				conditions = new { Email = email };
			}
			else
			{
				conditions = new { Phone = phone };
			}

			var user = await _DBContext.Auths.FirstOrDefaultAsync(u => u.Email == email || u.Phone == phone);
			if (user == null)
			{
				return NotFound(new { emailOrPhoneNotFound = "Email or Phone not found!" });
			}

			// Check password
			bool isPasswordCorrect = VerifyPassword(password, user.Password);
			if (!isPasswordCorrect)
			{
				return BadRequest(new { passwordIncorrect = "Password incorrect" });
			}

			// Create JWT Payload
			var payload = new
			{
				id = user.Id,
				email = user.Email
			};

			// Sign token
			var token = GenerateJwtToken(payload);

			return Ok(new
			{
				access_token = token
			});
		}

		// verify password.
		private bool VerifyPassword(string password, string hashedPassword)
		{
			using (SHA256 sha256 = SHA256.Create())
			{
				byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
				StringBuilder builder = new StringBuilder();
				foreach (byte b in hashedBytes)
				{
					builder.Append(b.ToString("x2"));
				}
				return builder.ToString() == hashedPassword;
			}
		}

		private string GenerateJwtToken(object payload)
		{
			var keyGenerator = RandomNumberGenerator.Create();
			var keyBytes = new byte[32]; // 256 bits = 32 bytes
			keyGenerator.GetBytes(keyBytes);

			var key = new SymmetricSecurityKey(keyBytes);

			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			var expires = DateTime.UtcNow.AddDays(7); // Token expiration time

			var token = new JwtSecurityToken(
				issuer: _configuration["Jwt:Issuer"],
				audience: _configuration["Jwt:Audience"],
				expires: expires,
				signingCredentials: credentials,
				claims: new[]
				{
					new Claim("payload", JsonConvert.SerializeObject(payload), ClaimValueTypes.String)
				}
			);

			var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
			return encodedToken;
		}

		public class LoginRequest
		{
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
		}
	}
}