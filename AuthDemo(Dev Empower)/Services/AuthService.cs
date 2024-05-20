using AuthDemo_Dev_Empower_.DTO;
using AuthDemo_Dev_Empower_.Entities;
using AuthDemo_Dev_Empower_.Interfaces;
using AuthDemo_Dev_Empower_.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthDemo_Dev_Empower_.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthService(UserManager<ApplicationUser> userManager,
                              RoleManager<IdentityRole> roleManager,
                              IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }
        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "User not found"
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Password Incorrect"
                };

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("LastName", user.LastName),
                new Claim("FirstName", user.FirstName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = token
            };
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

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto 
                { 
                    isSucceed = false,
                    Message = "User not found" 
                };

            var isUserAlreadyAdmin = await _userManager.IsInRoleAsync(user, StaticUserRoles.ADMIN);
            if (isUserAlreadyAdmin)
            {
                return new AuthServiceResponseDto 
                { 
                    isSucceed = false,
                    Message = "User already Admin" 
                };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return new AuthServiceResponseDto 
            { 
                isSucceed = true,
                Message = "User converted successfully" 
            };
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "User not found"
                };

            var isUserAlreadyOwner = await _userManager.IsInRoleAsync(user, "OWNER");
            if (isUserAlreadyOwner)
            {
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "User is already owner"
                };
            }

            await _userManager.AddToRoleAsync(user, "OWNER");
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "User converted succssfully"
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExistsUser != null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Username Already exists"
                };

            var newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
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
                return new AuthServiceResponseDto { 
                    isSucceed = false,
                    Message = errorString 
                };
            }

            //Add default User role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = ("User registration successful.")
            };
        }

        public async Task<AuthServiceResponseDto> SeedRoleAsync()
        {
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync("ADMIN");

            if (isAdminRoleExists && isUserRoleExists && isOwnerRoleExists)
            {
                return new AuthServiceResponseDto 
                { 
                    isSucceed = true,
                    Message = "Roles already exists"
                };
            }

            await _roleManager.CreateAsync(new IdentityRole("ADMIN"));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "Roles seeding done successfully."
            };
        }
    }
}
