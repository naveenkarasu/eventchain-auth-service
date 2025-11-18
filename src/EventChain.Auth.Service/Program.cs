using DotNetEnv;
using EventChain.Auth.Service.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

// Load .env file from project root
var envPath = Path.Combine(Directory.GetCurrentDirectory(), ".env");
if (File.Exists(envPath))
{
    Env.Load(envPath);
}
else
{
    // Try loading from project root (one level up from bin/Debug/net8.0)
    var projectRoot = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", ".env");
    if (File.Exists(projectRoot))
    {
        Env.Load(projectRoot);
    }
}

// Create builder with explicit environment if not set
var webAppOptions = new WebApplicationOptions
{
    Args = args,
    EnvironmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development"
};

var builder = WebApplication.CreateBuilder(webAppOptions);

// Override configuration with environment variables from .env
builder.Configuration.AddEnvironmentVariables();

// Explicitly set URLs to match launchSettings.json if not already set
if (string.IsNullOrEmpty(builder.Configuration["Urls"]) && 
    string.IsNullOrEmpty(builder.Configuration["applicationUrl"]))
{
    builder.WebHost.UseUrls("http://localhost:5247", "https://localhost:7024");
}

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure CORS for frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        var frontendUrl = builder.Configuration["FRONTEND_BASE_URL"]
                         ?? builder.Configuration["Frontend:BaseUrl"]
                         ?? "http://localhost:3001";
        policy.WithOrigins(frontendUrl)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials()
              .SetIsOriginAllowedToAllowWildcardSubdomains(); // Allow localhost variations
    });
});

// Configure Google Authentication
var googleClientId = builder.Configuration["GOOGLE_CLIENT_ID"]
                    ?? builder.Configuration["Authentication:Google:ClientId"];
var googleClientSecret = builder.Configuration["GOOGLE_CLIENT_SECRET"]
                        ?? builder.Configuration["Authentication:Google:ClientSecret"];

if (!string.IsNullOrEmpty(googleClientId) && !string.IsNullOrEmpty(googleClientSecret))
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.SameSite = SameSiteMode.Lax;
        // In development, allow cookies over HTTP to avoid correlation issues
        if (builder.Environment.IsDevelopment())
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.None;
        }
        else
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        }
        options.Cookie.HttpOnly = true;
        options.Cookie.Name = ".AspNetCore.Cookies";
    })
    .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = googleClientId;
        options.ClientSecret = googleClientSecret;
        // CallbackPath must match the actual route - note casing: /api/Auth/google/callback (capital A from controller name)
        options.CallbackPath = "/api/Auth/google/callback";
        options.SaveTokens = true;
        
        // Configure correlation cookie for OAuth state validation
        // This cookie is used to prevent CSRF attacks during OAuth flow
        // CRITICAL: Chrome/Edge blocks SameSite=None cookies in cross-site scenarios
        // SOLUTION: Use SameSite=Lax for localhost - it works for top-level navigations (OAuth redirects)
        // Path must be "/" so cookie is available when Google redirects back
        // The framework uses pattern: .AspNetCore.Correlation.{scheme}.{randomId}
        
        // CRITICAL FIX: Chrome/Edge blocks cookies during OAuth redirects
        // Try SameSite=None with Secure=true - this SHOULD work but requires browser settings
        // Alternative: Use SameSite=Unspecified to let browser decide (some browsers treat as Lax)
        if (builder.Environment.IsDevelopment())
        {
            // Development: Try both approaches
            // First try: SameSite=None (standard for cross-site OAuth)
            // Note: Requires Chrome to allow third-party cookies or use Firefox
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS required
            options.CorrelationCookie.SameSite = SameSiteMode.None; // Standard for cross-site OAuth
            options.CorrelationCookie.Path = "/";
            options.CorrelationCookie.HttpOnly = true;
            options.CorrelationCookie.MaxAge = TimeSpan.FromMinutes(15);
            options.CorrelationCookie.Domain = null; // Don't set domain - let browser use host
            
            // IMPORTANT: For SameSite=None to work, user must:
            // 1. Enable third-party cookies in Chrome: chrome://settings/cookies → Allow all cookies
            // 2. Or use Firefox which is less strict
            // 3. Or disable cookie blocking for localhost specifically
        }
        else
        {
            // Production: Use SameSite=None for cross-site scenarios
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.CorrelationCookie.SameSite = SameSiteMode.None;
            options.CorrelationCookie.Path = "/";
            options.CorrelationCookie.HttpOnly = true;
            options.CorrelationCookie.MaxAge = TimeSpan.FromMinutes(15);
        }
    });
}
else
{
    builder.Services.AddAuthentication();
}

// Configure JWT Authentication
var jwtSecretKey = builder.Configuration["JWT_SECRET_KEY"]
                  ?? builder.Configuration["Authentication:Jwt:SecretKey"];
if (!string.IsNullOrEmpty(jwtSecretKey))
{
    builder.Services.AddAuthentication()
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = builder.Configuration["JWT_ISSUER"]
                             ?? builder.Configuration["Authentication:Jwt:Issuer"]
                             ?? "EventChain.Auth.Service",
                ValidAudience = builder.Configuration["JWT_AUDIENCE"]
                               ?? builder.Configuration["Authentication:Jwt:Audience"]
                               ?? "EventChain",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey))
            };
        });
}

// Configure DataProtection for cookie encryption (ensures cookies work across requests)
builder.Services.AddDataProtection()
    .SetApplicationName("EventChain.Auth.Service")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "DataProtection-Keys")));

// Add distributed memory cache for OAuth correlation state
// This bypasses cookie issues by storing correlation state server-side
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15);
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Register services
builder.Services.AddScoped<IJwtService, JwtService>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Always use HTTPS redirection for OAuth to work properly with secure cookies
app.UseHttpsRedirection();

// Enable CORS
app.UseCors("AllowFrontend");

app.UseSession(); // Must be before UseAuthentication
app.UseAuthentication();
app.UseAuthorization();

// Add middleware to log cookie settings for debugging (development only)
// Must be AFTER authentication to see cookies in responses
if (app.Environment.IsDevelopment())
{
    app.Use(async (context, next) =>
    {
        // Log request info before processing
        if (context.Request.Path.StartsWithSegments("/api/Auth"))
        {
            var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("=== Auth Request: {Path} ===", context.Request.Path);
            logger.LogInformation("Scheme: {Scheme}, IsHttps: {IsHttps}, Host: {Host}", 
                context.Request.Scheme, context.Request.IsHttps, context.Request.Host);
        }
        
        await next();
        
        // Log Set-Cookie headers after response
        if (context.Response.Headers.ContainsKey("Set-Cookie"))
        {
            var setCookies = context.Response.Headers["Set-Cookie"].ToList();
            var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("✓ Set-Cookie headers in response: {Count}", setCookies.Count);
            foreach (var cookie in setCookies)
            {
                logger.LogInformation("  Setting: {Cookie}", cookie);
                
                // Check for correlation cookies and validate attributes
                if (cookie.Contains("Correlation", StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogInformation("  ✓ CORRELATION COOKIE DETECTED");
                    if (cookie.Contains("SameSite=None", StringComparison.OrdinalIgnoreCase) && 
                        cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogInformation("  ✓ Cookie has correct attributes: SameSite=None + Secure");
                    }
                    else if (cookie.Contains("SameSite=None", StringComparison.OrdinalIgnoreCase) && 
                             !cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogError("  ❌ PROBLEM: Cookie has SameSite=None but MISSING Secure flag! Browser will reject it!");
                    }
                }
            }
        }
    });
}

app.MapControllers();

app.Run();