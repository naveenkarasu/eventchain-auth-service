using EventChain.Auth.Service.Models;
using EventChain.Auth.Service.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;

namespace EventChain.Auth.Service.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IJwtService jwtService,
        IConfiguration configuration,
        ILogger<AuthController> logger)
    {
        _jwtService = jwtService;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Initiates Google OAuth login
    /// </summary>
    [HttpGet("google")]
    public IActionResult GoogleLogin()
    {
        // Use HTTPS for callback - required for secure cookies with SameSite=None
        // This matches the HTTPS endpoint where the app runs (https://localhost:7024)
        var callbackUrl = "https://localhost:7024/api/Auth/google/callback";
        
        _logger.LogInformation("Initiating Google OAuth login. Callback URL: {CallbackUrl}", callbackUrl);
        _logger.LogInformation("Request URL: {RequestUrl}, Scheme: {Scheme}, Host: {Host}", 
            $"{Request.Scheme}://{Request.Host}{Request.Path}{Request.QueryString}", 
            Request.Scheme, Request.Host);
        
        // Log all cookies that will be set
        _logger.LogInformation("Current cookies count: {Count}", Request.Cookies.Count);
        
        var properties = new AuthenticationProperties
        {
            RedirectUri = callbackUrl,
            AllowRefresh = true
        };

        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Handles Google OAuth callback
    /// </summary>
    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        _logger.LogInformation("=== Google OAuth Callback ===");
        _logger.LogInformation("Request URL: {RequestUrl}", $"{Request.Scheme}://{Request.Host}{Request.Path}{Request.QueryString}");
        _logger.LogInformation("Request Scheme: {Scheme}, Host: {Host}", Request.Scheme, Request.Host);
        _logger.LogInformation("IsHttps: {IsHttps}", Request.IsHttps);
        
        // Log ALL cookies in the request
        _logger.LogInformation("Total cookies in request: {Count}", Request.Cookies.Count);
        foreach (var cookie in Request.Cookies)
        {
            _logger.LogInformation("Cookie: {Key} = {Value}", cookie.Key, cookie.Value?.Substring(0, Math.Min(100, cookie.Value?.Length ?? 0)));
        }
        
        // Log correlation cookies specifically
        var correlationCookies = Request.Cookies.Where(c => c.Key.Contains("Correlation", StringComparison.OrdinalIgnoreCase)).ToList();
        _logger.LogInformation("Correlation cookies found: {Count}", correlationCookies.Count);
        if (correlationCookies.Count == 0)
        {
            _logger.LogError("❌ CRITICAL: NO CORRELATION COOKIES FOUND!");
            _logger.LogError("This will cause 'oauth state was missing or invalid' error.");
            _logger.LogError("");
            _logger.LogError("=== TROUBLESHOOTING STEPS ===");
            _logger.LogError("1. CHECK BROWSER COOKIES:");
            _logger.LogError("   - Open DevTools (F12) → Application → Cookies → localhost:7024");
            _logger.LogError("   - Look for cookies starting with '.AspNetCore.Correlation.'");
            _logger.LogError("   - If missing, browser blocked it");
            _logger.LogError("");
            _logger.LogError("2. BROWSER SETTINGS (Chrome/Edge) - REQUIRED FOR SameSite=None:");
            _logger.LogError("   ⚠️  SAME-SITE=NONE REQUIRES BROWSER TO ALLOW THIRD-PARTY COOKIES");
            _logger.LogError("   Steps:");
            _logger.LogError("   a. Open: chrome://settings/cookies or edge://settings/cookies");
            _logger.LogError("   b. Select: 'Allow all cookies' (temporarily for testing)");
            _logger.LogError("   c. OR: 'Add' button → Add 'localhost' to always allow cookies");
            _logger.LogError("   d. Restart browser completely");
            _logger.LogError("   e. Clear cookies for localhost:7024");
            _logger.LogError("   f. Try OAuth flow again");
            _logger.LogError("");
            _logger.LogError("3. TRY DIFFERENT BROWSER:");
            _logger.LogError("   - Test in Firefox (less strict cookie blocking)");
            _logger.LogError("   - Or use Incognito/Private mode with cookies enabled");
            _logger.LogError("");
            _logger.LogError("4. CLEAR ALL COOKIES:");
            _logger.LogError("   - Delete all cookies for localhost:7024");
            _logger.LogError("   - Restart browser");
            _logger.LogError("");
            _logger.LogError("5. VERIFY COOKIE WAS SET:");
            _logger.LogError("   - Check logs above for '✓ CORRELATION COOKIE DETECTED'");
            _logger.LogError("   - Cookie should have: SameSite=Lax; Secure; Path=/");
        }
        else
        {
            foreach (var cookie in correlationCookies)
            {
                _logger.LogInformation("✓ Correlation Cookie: {Key} = {Value}", cookie.Key, cookie.Value?.Substring(0, Math.Min(100, cookie.Value?.Length ?? 0)));
            }
        }
        
        var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!result.Succeeded)
        {
            _logger.LogWarning("Google authentication failed. Error: {Error}", result.Failure?.Message);
            if (result.Failure != null)
            {
                _logger.LogError(result.Failure, "Authentication failure details");
            }
            return RedirectToFrontend("/login?error=authentication_failed");
        }

        var claims = result.Principal?.Claims.ToList() ?? new List<Claim>();

        var user = new UserInfo
        {
            Id = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
                 ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value
                 ?? string.Empty,
            Email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "email")?.Value
                    ?? string.Empty,
            Name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value
                   ?? claims.FirstOrDefault(c => c.Type == "name")?.Value
                   ?? string.Empty,
            Picture = claims.FirstOrDefault(c => c.Type == "picture")?.Value
        };

        if (string.IsNullOrEmpty(user.Id) || string.IsNullOrEmpty(user.Email))
        {
            _logger.LogError("Failed to extract user information from Google claims");
            return RedirectToFrontend("/login?error=invalid_user_data");
        }

        var token = _jwtService.GenerateToken(user);
        var refreshToken = _jwtService.GenerateRefreshToken();

        // TODO: Store refresh token in database/Redis for validation

        var loginResponse = new LoginResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60),
            User = user
        };

        // Redirect to frontend with token
        var frontendUrl = _configuration["FRONTEND_BASE_URL"]
                         ?? _configuration["Frontend:BaseUrl"]
                         ?? "http://localhost:3001";
        var redirectUrl = $"{frontendUrl}/auth/callback?token={Uri.EscapeDataString(token)}&refreshToken={Uri.EscapeDataString(refreshToken)}";

        return Redirect(redirectUrl);
    }

    /// <summary>
    /// Validates and returns user info from JWT token
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var name = User.FindFirst(ClaimTypes.Name)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var user = new UserInfo
        {
            Id = userId,
            Email = email ?? string.Empty,
            Name = name ?? string.Empty
        };

        return Ok(user);
    }

    private IActionResult RedirectToFrontend(string path)
    {
        var frontendUrl = _configuration["FRONTEND_BASE_URL"]
                         ?? _configuration["Frontend:BaseUrl"]
                         ?? "http://localhost:3001";
        return Redirect($"{frontendUrl}{path}");
    }
}