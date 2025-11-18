# EventChain Auth Service

## Running the Service

### In Visual Studio:
1. Right-click on the project in Solution Explorer
2. Select "Properties" or press Alt+Enter
3. Go to "Debug" → "General" tab
4. In the "Launch profiles" dropdown, select **"https"** (this runs on both HTTP and HTTPS)
5. Press F5 to run

**OR**

1. In Visual Studio, look at the top toolbar
2. Find the dropdown that shows the launch profile (might say "IIS Express" or "EventChain.Auth.Service")
3. Click the dropdown and select **"https"** profile
4. Press F5 to run

### From Command Line:
```bash
cd src/EventChain.Auth.Service
dotnet run --launch-profile https
```

## Expected Ports:
- HTTP: http://localhost:5247
- HTTPS: https://localhost:7024

## Environment Variables:
Make sure `.env` file exists in the project root with:
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- JWT_SECRET_KEY
- FRONTEND_BASE_URL

