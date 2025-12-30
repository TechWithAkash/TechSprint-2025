# scripts/verify-auth.ps1
# PowerShell script to verify authentication configuration

Write-Host "`n🔍 Verifying Authentication Configuration...`n" -ForegroundColor Cyan

# Load .env.local file
$envFile = ".env.local"
if (Test-Path $envFile) {
    Write-Host "📂 Loading $envFile...`n" -ForegroundColor Green
    
    $envVars = @{}
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^([^#][^=]+)=(.+)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            $envVars[$name] = $value
        }
    }
    
    # Check required variables
    $required = @(
        'NEXTAUTH_SECRET',
        'NEXTAUTH_URL',
        'MONGODB_URI',
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'NODE_ENV'
    )
    
    $hasErrors = $false
    
    Write-Host "📋 Environment Variables Check:`n" -ForegroundColor Yellow
    
    foreach ($var in $required) {
        if ($envVars.ContainsKey($var) -and $envVars[$var]) {
            $value = $envVars[$var]
            
            # Mask sensitive values
            if ($var -match 'SECRET|URI|PASSWORD') {
                $displayValue = $value.Substring(0, [Math]::Min(10, $value.Length)) + "..." + 
                               $value.Substring([Math]::Max(0, $value.Length - 5))
            } else {
                $displayValue = $value
            }
            
            Write-Host "✅ $var`: $displayValue" -ForegroundColor Green
        } else {
            Write-Host "❌ $var`: MISSING" -ForegroundColor Red
            $hasErrors = $true
        }
    }
    
    # Validate NEXTAUTH_URL
    if ($envVars.ContainsKey('NEXTAUTH_URL')) {
        Write-Host "`n🌐 NEXTAUTH_URL Validation:`n" -ForegroundColor Yellow
        
        $url = $envVars['NEXTAUTH_URL']
        
        if ($url -notmatch '^https?://') {
            Write-Host "❌ NEXTAUTH_URL must start with http:// or https://" -ForegroundColor Red
            $hasErrors = $true
        } else {
            Write-Host "✅ Protocol: $($url -replace '://.*', '')" -ForegroundColor Green
        }
        
        if ($url.EndsWith('/')) {
            Write-Host "⚠️  NEXTAUTH_URL should not end with a trailing slash" -ForegroundColor Yellow
            Write-Host "   Current: $url" -ForegroundColor Gray
            Write-Host "   Should be: $($url.TrimEnd('/'))" -ForegroundColor Gray
        } else {
            Write-Host "✅ No trailing slash" -ForegroundColor Green
        }
        
        if ($envVars['NODE_ENV'] -eq 'production' -and $url -notmatch '^https://') {
            Write-Host "❌ Production NEXTAUTH_URL must use HTTPS" -ForegroundColor Red
            $hasErrors = $true
        } elseif ($envVars['NODE_ENV'] -eq 'production') {
            Write-Host "✅ Using HTTPS in production" -ForegroundColor Green
        }
    }
    
    # Google OAuth Configuration
    Write-Host "`n🔐 Google OAuth Configuration:`n" -ForegroundColor Yellow
    
    if ($envVars.ContainsKey('GOOGLE_CLIENT_ID')) {
        $clientId = $envVars['GOOGLE_CLIENT_ID']
        if ($clientId.EndsWith('.apps.googleusercontent.com')) {
            Write-Host "✅ Google Client ID format is correct" -ForegroundColor Green
        } else {
            Write-Host "❌ Google Client ID format appears incorrect" -ForegroundColor Red
            Write-Host "   Should end with: .apps.googleusercontent.com" -ForegroundColor Gray
            $hasErrors = $true
        }
    }
    
    if ($envVars.ContainsKey('GOOGLE_CLIENT_SECRET')) {
        $secret = $envVars['GOOGLE_CLIENT_SECRET']
        if ($secret.StartsWith('GOCSPX-')) {
            Write-Host "✅ Google Client Secret format is correct" -ForegroundColor Green
        } else {
            Write-Host "❌ Google Client Secret format appears incorrect" -ForegroundColor Red
            Write-Host "   Should start with: GOCSPX-" -ForegroundColor Gray
            $hasErrors = $true
        }
    }
    
    # MongoDB URI Validation
    Write-Host "`n🗄️  MongoDB Configuration:`n" -ForegroundColor Yellow
    
    if ($envVars.ContainsKey('MONGODB_URI')) {
        $mongoUri = $envVars['MONGODB_URI']
        
        if ($mongoUri -match '^mongodb(\+srv)?://') {
            Write-Host "✅ MongoDB URI protocol is correct" -ForegroundColor Green
        } else {
            Write-Host "❌ MongoDB URI must start with mongodb:// or mongodb+srv://" -ForegroundColor Red
            $hasErrors = $true
        }
        
        if ($mongoUri -match '@') {
            Write-Host "✅ MongoDB URI includes credentials" -ForegroundColor Green
        } else {
            Write-Host "⚠️  MongoDB URI may be missing credentials" -ForegroundColor Yellow
        }
    }
    
    # NextAuth Secret Validation
    Write-Host "`n🔑 NextAuth Secret Validation:`n" -ForegroundColor Yellow
    
    if ($envVars.ContainsKey('NEXTAUTH_SECRET')) {
        $secret = $envVars['NEXTAUTH_SECRET']
        
        if ($secret.Length -lt 32) {
            Write-Host "❌ NEXTAUTH_SECRET is too short (should be at least 32 characters)" -ForegroundColor Red
            $hasErrors = $true
        } else {
            Write-Host "✅ NEXTAUTH_SECRET length: $($secret.Length) characters" -ForegroundColor Green
        }
        
        if ($secret -match 'your-secret-key|change-me') {
            Write-Host "❌ NEXTAUTH_SECRET is using a default/insecure value" -ForegroundColor Red
            $hasErrors = $true
        } else {
            Write-Host "✅ NEXTAUTH_SECRET appears to be a custom value" -ForegroundColor Green
        }
    }
    
    # Required URLs for Google Console
    Write-Host "`n📝 Google Cloud Console Configuration:`n" -ForegroundColor Yellow
    Write-Host "Add these Authorized Redirect URIs:" -ForegroundColor White
    Write-Host "   $($envVars['NEXTAUTH_URL'])/api/auth/callback/google" -ForegroundColor Cyan
    Write-Host "   http://localhost:3000/api/auth/callback/google" -ForegroundColor Cyan
    
    Write-Host "`nAdd these Authorized JavaScript Origins:" -ForegroundColor White
    Write-Host "   $($envVars['NEXTAUTH_URL'])" -ForegroundColor Cyan
    Write-Host "   http://localhost:3000" -ForegroundColor Cyan
    
    # Summary
    Write-Host "`n$('=' * 60)`n" -ForegroundColor Gray
    
    if ($hasErrors) {
        Write-Host "❌ Configuration has ERRORS - Please fix the issues above`n" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "✅ All configuration checks PASSED!`n" -ForegroundColor Green
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "1. Verify Google Cloud Console redirect URIs" -ForegroundColor White
        Write-Host "2. Clear browser cache and cookies" -ForegroundColor White
        Write-Host "3. Test the authentication flow" -ForegroundColor White
        Write-Host "4. Monitor server logs for any runtime errors`n" -ForegroundColor White
        exit 0
    }
    
} else {
    Write-Host "❌ $envFile not found!`n" -ForegroundColor Red
    exit 1
}
