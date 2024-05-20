using System.ComponentModel.DataAnnotations;

namespace AuthDemo_Dev_Empower_.DTO
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }
    }
}
