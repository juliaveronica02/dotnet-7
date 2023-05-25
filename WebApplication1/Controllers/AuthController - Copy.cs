/*using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.DTO;
using WebApplication1.Entities;
using System.Security.Cryptography; // same with bcrypt to hash password.
using System;
using BCrypt.Net;

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
			using var sha256 = SHA256.Create();
			var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
			return Encoding.UTF8.GetString(hashedBytes);
		}

		// user login.
		[HttpPost("Login")]
		public async Task<IActionResult> LoginAuthentication(LoginRequest request)
		{
			string email = request.Email;
			long phone;
			if (!long.TryParse(request.Phone, out phone))
			{
				return BadRequest(new { phone = "Invalid phone number format" });
			}
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
				success = "Auth Session",
				token,
				id = user.Id,
				email = user.Email,
				username = user.Username
			});
		}

		private bool VerifyPassword(string password, string hashedPassword)
		{
			using var sha256 = SHA256.Create();
			var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
			var hashedPasswordFromInput = Encoding.UTF8.GetString(hashedBytes);

			return hashedPassword == hashedPasswordFromInput;
		}

		private string GenerateJwtToken(object payload)
		{
			var key = Encoding.ASCII.GetBytes(_configuration["Jwt:SecretKey"]);
			var tokenHandler = new JwtSecurityTokenHandler();

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(new[]
				{
			new Claim(ClaimTypes.NameIdentifier, ((dynamic)payload).id.ToString()),
			new Claim(ClaimTypes.Email, ((dynamic)payload).email.ToString()),
		}),
				Expires = DateTime.UtcNow.AddHours(1),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);
		}

		public class LoginRequest
		{
			public string Email { get; set; }
			public string Phone { get; set; }
			public string Password { get; set; }
		}
	
	}
}
*/