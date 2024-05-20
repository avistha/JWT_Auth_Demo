using Microsoft.AspNetCore.Identity;

namespace AuthDemo_Dev_Empower_.Entities
{
    public class ApplicationUser : IdentityUser
    {

        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
