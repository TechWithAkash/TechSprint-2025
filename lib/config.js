// Application configuration with validation
import { z } from 'zod'

// Environment schema validation
const envSchema = z.object({
  // Database
  MONGODB_URI: z.string().min(1, 'MongoDB URI is required'),
  
  // Authentication
  NEXTAUTH_URL: z.string().url('Invalid NextAuth URL'),
  NEXTAUTH_SECRET: z.string().min(32, 'NextAuth secret must be at least 32 characters'),
  
  // OAuth
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  
  // Email
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.string().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  
  // App
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
})

// Validate environment variables
let env
try {
  env = envSchema.parse(process.env)
} catch (error) {
  console.error('❌ Invalid environment variables:', error.flatten().fieldErrors)
  throw new Error('Invalid environment configuration')
}

// App configuration
export const config = {
  app: {
    name: 'WealthWise ',
    version: '1.0.0',
    url: env.NEXTAUTH_URL,
    env: env.NODE_ENV,
    isDevelopment: env.NODE_ENV === 'development',
    isProduction: env.NODE_ENV === 'production',
  },
  
  database: {
    uri: env.MONGODB_URI,
    options: {
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 30000, // Increased to 30 seconds for serverless
      socketTimeoutMS: 45000,
      connectTimeoutMS: 30000, // 30 seconds
      family: 4,
      retryWrites: true,
      retryReads: true,
      w: 'majority',
    },
  },
  
  auth: {
    secret: env.NEXTAUTH_SECRET,
    sessionMaxAge: 30 * 24 * 60 * 60, // 30 days
    sessionUpdateAge: 24 * 60 * 60, // 24 hours
  },
  
  oauth: {
    google: {
      clientId: env.GOOGLE_CLIENT_ID || null,
      clientSecret: env.GOOGLE_CLIENT_SECRET || null,
    },
  },
  
  email: {
    host: env.SMTP_HOST,
    port: parseInt(env.SMTP_PORT || '587'),
    user: env.SMTP_USER,
    password: env.SMTP_PASSWORD,
    from: `"${env.SMTP_USER}" <noreply@smartfinancialplanner.com>`,
  },
  
  security: {
    bcryptRounds: 12,
    tokenExpiry: {
      emailVerification: 24 * 60 * 60 * 1000, // 24 hours
      passwordReset: 60 * 60 * 1000, // 1 hour
      session: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
  },
  
  rateLimit: {
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 attempts per window
    },
    api: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // 100 requests per window
    },
  },
}

export default config
