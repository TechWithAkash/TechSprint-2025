// app/api/test-auth-config/route.js
// This endpoint helps verify your auth configuration

export async function GET() {
    const config = {
        AUTH_URL: process.env.AUTH_URL || 'MISSING',
        NEXTAUTH_URL: process.env.NEXTAUTH_URL || 'MISSING',
        NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET ? 'SET (hidden)' : 'MISSING',
        GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ? `SET (${process.env.GOOGLE_CLIENT_ID.substring(0, 20)}...)` : 'MISSING',
        GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ? 'SET (hidden)' : 'MISSING',
        MONGODB_URI: process.env.MONGODB_URI ? 'SET (hidden)' : 'MISSING',
        NODE_ENV: process.env.NODE_ENV,
        VERCEL: process.env.VERCEL || 'Not on Vercel',
        VERCEL_ENV: process.env.VERCEL_ENV || 'Not on Vercel',
    }

    const missingVars = Object.entries(config)
        .filter(([key, value]) => value === 'MISSING' && !key.includes('VERCEL'))
        .map(([key]) => key)

    return Response.json({
        status: missingVars.length === 0 ? 'OK' : 'INCOMPLETE',
        missingVariables: missingVars,
        configuration: config,
        message: missingVars.length === 0
            ? '✅ All required environment variables are set!'
            : `❌ Missing variables: ${missingVars.join(', ')}`,
        timestamp: new Date().toISOString()
    }, {
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache, must-revalidate'
        }
    })
}
