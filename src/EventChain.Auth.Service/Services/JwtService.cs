using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using EventChain.Auth.Service.Models;
using Microsoft.IdentityModel.Tokens;

namespace EventChain.Auth.Service.Services;

public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;

    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateToken(UserInfo user)
    {
        // Try environment variable first, then fallback to configuration
        var secretKey = _configuration["JWT_SECRET_KEY"]
                       ?? _configuration["Authentication:Jwt:SecretKey"]
                       ?? throw new InvalidOperationException("JWT SecretKey not configured");

        var issuer = _configuration["JWT_ISSUER"]
                    ?? _configuration["Authentication:Jwt:Issuer"]
                    ?? "EventChain.Auth.Service";

        var audience = _configuration["JWT_AUDIENCE"]
                      ?? _configuration["Authentication:Jwt:Audience"]
                      ?? "EventChain";

        var expirationMinutes = int.Parse(
            _configuration["JWT_EXPIRATION_MINUTES"]
            ?? _configuration["Authentication:Jwt:ExpirationMinutes"]
            ?? "60"
        );

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}