using AuthDemo_Dev_Empower_.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthDemo_Dev_Empower_.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        [HttpGet]
        [Route("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }

        [HttpGet]
        [Route("GetUsersRole")]
        [Authorize(Roles = StaticUserRoles.USER)]
        public IActionResult GetUsersRole()
        {
            return Ok("User logged In" + Summaries);
        }

        [HttpGet]
        [Route("GetAdminRole")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public IActionResult GetAdminRole()
        {
            return Ok("Admin Logged In" + Summaries);
        }

        [HttpGet]
        [Route("GetOwnerRole")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public IActionResult GetOwnerRole()
        {
            return Ok("Owner Logged In" + Summaries);
        }
    }
}
