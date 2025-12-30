/**
 * Environment Configuration
 * Centralized environment variable management
 */

export const env = {
  // App
  NODE_ENV: process.env.NODE_ENV || 'development',
  APP_URL: process.env.NEXTAUTH_URL || 'http://localhost:3000',

  // Database
  MONGODB_URI: process.env.MONGODB_URI,

  // Authentication
  NEXTAUTH_URL: process.env.NEXTAUTH_URL,
  NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,

  // OAuth
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,

  // AI
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,

  // Voice
  OMNIDIM_SECRET_KEY: process.env.OMNIDIM_SECRET_KEY,

  // Email (if configured)
  EMAIL_SERVER: process.env.EMAIL_SERVER,
  EMAIL_FROM: process.env.EMAIL_FROM,
}

// Validate required environment variables
export function validateEnv() {
  const required = [
    'MONGODB_URI',
    'NEXTAUTH_SECRET',
    'GEMINI_API_KEY'
  ]

  const missing = required.filter(key => !process.env[key])

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`
    )
  }
}

// Check if we're in production
export const isProd = env.NODE_ENV === 'production'
export const isDev = env.NODE_ENV === 'development'
