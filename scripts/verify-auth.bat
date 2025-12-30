@echo off
echo.
echo Checking Authentication Configuration...
echo.

if not exist .env.local (
    echo ERROR: .env.local file not found!
    exit /b 1
)

echo Checking required environment variables in .env.local:
echo.

findstr /C:"NEXTAUTH_SECRET" .env.local >nul && echo [OK] NEXTAUTH_SECRET is set || echo [MISSING] NEXTAUTH_SECRET
findstr /C:"NEXTAUTH_URL" .env.local >nul && echo [OK] NEXTAUTH_URL is set || echo [MISSING] NEXTAUTH_URL
findstr /C:"MONGODB_URI" .env.local >nul && echo [OK] MONGODB_URI is set || echo [MISSING] MONGODB_URI
findstr /C:"GOOGLE_CLIENT_ID" .env.local >nul && echo [OK] GOOGLE_CLIENT_ID is set || echo [MISSING] GOOGLE_CLIENT_ID
findstr /C:"GOOGLE_CLIENT_SECRET" .env.local >nul && echo [OK] GOOGLE_CLIENT_SECRET is set || echo [MISSING] GOOGLE_CLIENT_SECRET
findstr /C:"NODE_ENV" .env.local >nul && echo [OK] NODE_ENV is set || echo [MISSING] NODE_ENV

echo.
echo Google Cloud Console Configuration:
echo.
echo Add these Authorized Redirect URIs:
findstr /C:"NEXTAUTH_URL" .env.local
echo /api/auth/callback/google
echo    http://localhost:3000/api/auth/callback/google
echo.
echo Add these Authorized JavaScript Origins:
findstr /C:"NEXTAUTH_URL" .env.local
echo    http://localhost:3000
echo.
echo Configuration check complete!
echo.

pause
