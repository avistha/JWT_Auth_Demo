using AuthDemo_Dev_Empower_.DTO;
using AuthDemo_Dev_Empower_.Entities;
using AuthDemo_Dev_Empower_.Interfaces;
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
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }


        //Route for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRoleAsync();
            return Ok(seedRoles);
        }

        //Route for registering a new user
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);
            if(registerResult.isSucceed)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }

        //Route for login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);

            if(loginResult.isSucceed)
                return Ok(loginResult);

            return Unauthorized(loginResult);
        }

        //Route to convert user to admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var result = await _authService.MakeAdminAsync(updatePermissionDto);
            if(result.isSucceed)
                return Ok(result);

            return BadRequest(result);
        }

        //Route to convert user to owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var result = await _authService.MakeOwnerAsync(updatePermissionDto);
            if (result.isSucceed)
                return Ok(result);

            return BadRequest(result);
        }
    }
}

