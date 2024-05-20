using AuthDemo_Dev_Empower_.DTO;
using AuthDemo_Dev_Empower_.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthDemo_Dev_Empower_.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthController(UserManager<IdentityUser> userManager,
                              RoleManager<IdentityRole> roleManager,
                              IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }

        //Route for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync("ADMIN");
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);

            if (isAdminRoleExists && isUserRoleExists && isOwnerRoleExists)
            {
                return Ok("Roles already exists");
            }

            await _roleManager.CreateAsync(new IdentityRole("ADMIN"));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            return Ok("Role seeding Done successfully");
        }

        //Route for registering a new user
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExistsUser != null)
                return BadRequest("Username Already exists");

            IdentityUser newUser = new IdentityUser()
            {
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerDto.UserName,
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation failed because: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "#" + error.Description;
                }
                return BadRequest(errorString);
            }

            //Add default User role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User created successfully!");
        }

        //Route for login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user is null)
                return Unauthorized("Invalid Credentials");

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
                return Unauthorized("Invalid Credentials");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);

        }

        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                 issuer: _config["JWT:ValidIssuer"],
                 audience: _config["JWT:ValidAudience"],
                 expires: DateTime.Now.AddHours(3),
                 claims: claims,
                 signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256Signature)
            );

            var token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }
    }
}

