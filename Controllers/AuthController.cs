using Microsoft.AspNetCore.Mvc; 
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Configuration;

namespace Auth.Controllers
{
    public class AuthController : ControllerBase 
    {   
        //Variables
        private readonly IConfiguration _configuration;
        public static User user = new User();
        
        //Contructor 
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register( UserDto request) {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Username = request.Username;
            user.Password = request.Password;
            user.PasswordHash = passwordHash; 
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }
        [HttpPost("Login")] 
        public async Task<ActionResult<string>> Login (UserDto request) {
            if (request.Username != user.Username){
                return BadRequest("User Not Found !");
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)){
                return BadRequest("Wrong Password !");
            }
            string token = CreateToken(user);
            return Ok("Token: " + token);
        }
        private string CreateToken(User user) {
            List<Claim> claims = new List<Claim> 
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            
            //set token that will expires in 1 day.
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePasswordHash (string password, out byte[] passwordHash, out byte[] passwordSalt ){
            using (var hmac = new HMACSHA512()) {
                passwordSalt = hmac.Key; 
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        public bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt) {
            using (var hmac = new HMACSHA512(user.PasswordSalt)) {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
       }
    } 

}