using EventChain.Auth.Service.Models;

namespace EventChain.Auth.Service.Services;

public interface IJwtService
{
    string GenerateToken(UserInfo user);
    string GenerateRefreshToken();
}