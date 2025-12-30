// app/api/health-check/route.js
// Health check endpoint to verify environment configuration

import { NextResponse } from 'next/server'

export async function GET() {
    try {
        // Check required environment variables
        const envCheck = {
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV,
            vercelEnv: process.env.VERCEL_ENV || 'not-vercel',
            vercel: !!process.env.VERCEL,

            // Check critical variables (don't expose values)
            variables: {
                NEXTAUTH_URL: !!process.env.NEXTAUTH_URL ? 'SET' : 'MISSING',
                AUTH_URL: !!process.env.AUTH_URL ? 'SET' : 'MISSING',
                NEXTAUTH_SECRET: !!process.env.NEXTAUTH_SECRET ? 'SET' : 'MISSING',
                MONGODB_URI: !!process.env.MONGODB_URI ? 'SET' : 'MISSING',
                GOOGLE_CLIENT_ID: !!process.env.GOOGLE_CLIENT_ID ? 'SET' : 'MISSING',
                GOOGLE_CLIENT_SECRET: !!process.env.GOOGLE_CLIENT_SECRET ? 'SET' : 'MISSING',
                GEMINI_API_KEY: !!process.env.GEMINI_API_KEY ? 'SET' : 'MISSING',
                ENCRYPTION_SECRET: !!process.env.ENCRYPTION_SECRET ? 'SET' : 'MISSING',
            },

            // Show first 20 chars of URLs (safe to expose)
            urls: {
                nextAuthUrl: process.env.NEXTAUTH_URL?.substring(0, 30) + '...' || 'NOT SET',
                authUrl: process.env.AUTH_URL?.substring(0, 30) + '...' || 'NOT SET',
            }
        }

        // Check if all critical variables are set
        const missingVars = Object.entries(envCheck.variables)
            .filter(([key, value]) => value === 'MISSING')
            .map(([key]) => key)

        const status = missingVars.length === 0 ? 'HEALTHY' : 'UNHEALTHY'

        return NextResponse.json({
            status,
            message: status === 'HEALTHY'
                ? 'All environment variables are configured correctly'
                : `Missing variables: ${missingVars.join(', ')}`,
            ...envCheck,
            missingVariables: missingVars
        }, {
            status: status === 'HEALTHY' ? 200 : 500
        })

    } catch (error) {
        return NextResponse.json({
            status: 'ERROR',
            message: 'Health check failed',
            error: error.message
        }, {
            status: 500
        })
    }
}
