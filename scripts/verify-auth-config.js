// scripts/verify-auth-config.js
// Run this script to verify your authentication configuration

// Load environment variables
import { config } from 'dotenv'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// Try loading .env.local first, then .env
config({ path: resolve(__dirname, '../.env.local') })
config({ path: resolve(__dirname, '../.env') })

console.log('\n🔍 Verifying Authentication Configuration...\n')

// Check environment variables
const requiredEnvVars = {
    'NEXTAUTH_SECRET': process.env.NEXTAUTH_SECRET,
    'NEXTAUTH_URL': process.env.NEXTAUTH_URL,
    'MONGODB_URI': process.env.MONGODB_URI,
    'GOOGLE_CLIENT_ID': process.env.GOOGLE_CLIENT_ID,
    'GOOGLE_CLIENT_SECRET': process.env.GOOGLE_CLIENT_SECRET,
    'NODE_ENV': process.env.NODE_ENV
}

let hasErrors = false

console.log('📋 Environment Variables Check:\n')

for (const [key, value] of Object.entries(requiredEnvVars)) {
    if (!value) {
        console.error(`❌ ${key}: MISSING`)
        hasErrors = true
    } else {
        // Show partial value for security
        const displayValue = key.includes('SECRET') || key.includes('URI') || key.includes('PASSWORD')
            ? value.substring(0, 10) + '...' + value.substring(value.length - 5)
            : value
        console.log(`✅ ${key}: ${displayValue}`)
    }
}

// Verify NEXTAUTH_URL format
if (requiredEnvVars.NEXTAUTH_URL) {
    console.log('\n🌐 NEXTAUTH_URL Validation:\n')

    const url = requiredEnvVars.NEXTAUTH_URL

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        console.error('❌ NEXTAUTH_URL must start with http:// or https://')
        hasErrors = true
    } else {
        console.log(`✅ Protocol: ${url.split('://')[0]}`)
    }

    if (url.endsWith('/')) {
        console.warn('⚠️  NEXTAUTH_URL should not end with a trailing slash')
        console.log(`   Current: ${url}`)
        console.log(`   Should be: ${url.slice(0, -1)}`)
    } else {
        console.log('✅ No trailing slash')
    }

    if (requiredEnvVars.NODE_ENV === 'production' && !url.startsWith('https://')) {
        console.error('❌ Production NEXTAUTH_URL must use HTTPS')
        hasErrors = true
    } else if (requiredEnvVars.NODE_ENV === 'production') {
        console.log('✅ Using HTTPS in production')
    }
}

// Google OAuth Configuration
console.log('\n🔐 Google OAuth Configuration:\n')

if (requiredEnvVars.GOOGLE_CLIENT_ID) {
    const clientId = requiredEnvVars.GOOGLE_CLIENT_ID
    if (clientId.endsWith('.apps.googleusercontent.com')) {
        console.log('✅ Google Client ID format is correct')
    } else {
        console.error('❌ Google Client ID format appears incorrect')
        console.log('   Should end with: .apps.googleusercontent.com')
        hasErrors = true
    }
}

if (requiredEnvVars.GOOGLE_CLIENT_SECRET) {
    const secret = requiredEnvVars.GOOGLE_CLIENT_SECRET
    if (secret.startsWith('GOCSPX-')) {
        console.log('✅ Google Client Secret format is correct')
    } else {
        console.error('❌ Google Client Secret format appears incorrect')
        console.log('   Should start with: GOCSPX-')
        hasErrors = true
    }
}

// MongoDB URI Validation
console.log('\n🗄️  MongoDB Configuration:\n')

if (requiredEnvVars.MONGODB_URI) {
    const mongoUri = requiredEnvVars.MONGODB_URI

    if (mongoUri.startsWith('mongodb://') || mongoUri.startsWith('mongodb+srv://')) {
        console.log('✅ MongoDB URI protocol is correct')
    } else {
        console.error('❌ MongoDB URI must start with mongodb:// or mongodb+srv://')
        hasErrors = true
    }

    if (mongoUri.includes('@')) {
        console.log('✅ MongoDB URI includes credentials')
    } else {
        console.warn('⚠️  MongoDB URI may be missing credentials')
    }
}

// NextAuth Secret Validation
console.log('\n🔑 NextAuth Secret Validation:\n')

if (requiredEnvVars.NEXTAUTH_SECRET) {
    const secret = requiredEnvVars.NEXTAUTH_SECRET

    if (secret.length < 32) {
        console.error('❌ NEXTAUTH_SECRET is too short (should be at least 32 characters)')
        hasErrors = true
    } else {
        console.log(`✅ NEXTAUTH_SECRET length: ${secret.length} characters`)
    }

    if (secret === 'your-secret-key-here' || secret === 'change-me') {
        console.error('❌ NEXTAUTH_SECRET is using a default/insecure value')
        hasErrors = true
    } else {
        console.log('✅ NEXTAUTH_SECRET appears to be a custom value')
    }
} else {
    console.error('❌ NEXTAUTH_SECRET is not set')
    console.log('\n   Generate a secure secret with:')
    console.log('   node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"')
    hasErrors = true
}

// Required URLs for Google Console
console.log('\n📝 Google Cloud Console Configuration:\n')
console.log('Add these Authorized Redirect URIs in Google Cloud Console:')
console.log(`   ${requiredEnvVars.NEXTAUTH_URL}/api/auth/callback/google`)
console.log(`   http://localhost:3000/api/auth/callback/google`)

console.log('\nAdd these Authorized JavaScript Origins:')
console.log(`   ${requiredEnvVars.NEXTAUTH_URL}`)
console.log(`   http://localhost:3000`)

// Summary
console.log('\n' + '='.repeat(60) + '\n')

if (hasErrors) {
    console.error('❌ Configuration has ERRORS - Please fix the issues above\n')
    process.exit(1)
} else {
    console.log('✅ All configuration checks PASSED!\n')
    console.log('Next steps:')
    console.log('1. Verify Google Cloud Console redirect URIs')
    console.log('2. Clear browser cache and cookies')
    console.log('3. Test the authentication flow')
    console.log('4. Monitor server logs for any runtime errors\n')
    process.exit(0)
}
