

using AuthDemo_Dev_Empower_.DTO;

namespace AuthDemo_Dev_Empower_.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRoleAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);
    }
}
