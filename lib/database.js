// Modern MongoDB connection optimized for Vercel serverless environment
import { MongoClient } from 'mongodb'

// Global MongoDB client and database cache
let cachedClient = null
let cachedDb = null

// MongoDB connection options optimized for serverless (increased timeouts)
const mongoOptions = {
  maxPoolSize: 10,
  minPoolSize: 2,
  serverSelectionTimeoutMS: 60000, // 60 seconds for serverless cold starts
  socketTimeoutMS: 75000,
  connectTimeoutMS: 60000,
  retryWrites: true,
  retryReads: true,
  w: 'majority',
  tls: true,
  tlsAllowInvalidCertificates: false,
}

export async function connectToDatabase() {
  // Return cached connection if available and still valid
  if (cachedClient && cachedDb) {
    try {
      // Verify the connection is still alive
      await cachedClient.db().admin().ping()
      return cachedDb
    } catch (error) {
      console.warn('⚠️ Cached connection failed, reconnecting...', error.message)
      cachedClient = null
      cachedDb = null
    }
  }

  // Create new connection
  const maxRetries = 3
  let lastError = null

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mongoUri = process.env.MONGODB_URI
      if (!mongoUri) {
        throw new Error('MONGODB_URI environment variable is not set')
      }

      console.log(`🔌 Connecting to MongoDB... (Attempt ${attempt}/${maxRetries})`)
      const client = new MongoClient(mongoUri, mongoOptions)

      // Connect to MongoDB with timeout handling
      await client.connect()

      // Verify connection
      await client.db().admin().ping()

      // Get database instance
      const db = client.db()

      // Cache the connection
      cachedClient = client
      cachedDb = db

      // Set up database indexes and constraints (non-blocking)
      setupDatabase(db).catch(err => console.error('⚠️ Index setup error:', err))

      console.log('✅ Connected to MongoDB successfully')
      return db

    } catch (error) {
      lastError = error
      console.error(`❌ MongoDB connection attempt ${attempt} failed:`, error.message)

      if (attempt < maxRetries) {
        const waitTime = attempt * 2000 // Exponential backoff
        console.log(`⏳ Waiting ${waitTime}ms before retry...`)
        await new Promise(resolve => setTimeout(resolve, waitTime))
      }
    }
  }

  // All retries failed
  console.error('❌ All MongoDB connection attempts failed')
  console.error('Last error details:', {
    name: lastError?.name,
    message: lastError?.message,
    code: lastError?.code
  })
  cachedClient = null
  cachedDb = null
  throw new Error(`Database connection failed after ${maxRetries} attempts: ${lastError?.message}`)
}

// Export client for NextAuth MongoDB adapter
export async function getMongoClient() {
  // If we have a cached client, verify and return it
  if (cachedClient) {
    try {
      await cachedClient.db().admin().ping()
      console.log('✅ Using cached MongoDB client')
      return cachedClient
    } catch (error) {
      console.warn('⚠️ Cached client failed ping, reconnecting...')
      cachedClient = null
      cachedDb = null
    }
  }

  try {
    const mongoUri = process.env.MONGODB_URI
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable is not set')
    }

    console.log('🔌 Creating MongoDB client for NextAuth...')
    const client = new MongoClient(mongoUri, mongoOptions)
    await client.connect()

    // Verify connection
    await client.db().admin().ping()

    cachedClient = client
    console.log('✅ MongoDB client ready for NextAuth')
    return client
  } catch (error) {
    console.error('❌ MongoDB client connection failed:', error)
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code
    })
    cachedClient = null
    throw new Error(`Database client connection failed: ${error.message}`)
  }
}

// Database setup function
async function setupDatabase(db) {
  try {
    // Users collection indexes
    await db.collection('users').createIndex({ email: 1 }, { unique: true }).catch(() => { })
    await db.collection('users').createIndex({ emailVerificationToken: 1 }, { sparse: true }).catch(() => { })
    await db.collection('users').createIndex({ passwordResetToken: 1 }, { sparse: true }).catch(() => { })
    await db.collection('users').createIndex({ createdAt: 1 }).catch(() => { })

    // Sessions collection indexes (for NextAuth)
    await db.collection('sessions').createIndex({ sessionToken: 1 }, { unique: true }).catch(() => { })
    await db.collection('sessions').createIndex({ userId: 1 }).catch(() => { })
    await db.collection('sessions').createIndex({ expires: 1 }, { expireAfterSeconds: 0 }).catch(() => { })

    // Accounts collection indexes (for NextAuth OAuth)
    await db.collection('accounts').createIndex({ provider: 1, providerAccountId: 1 }, { unique: true }).catch(() => { })
    await db.collection('accounts').createIndex({ userId: 1 }).catch(() => { })

    // Verification tokens collection indexes
    await db.collection('verification_tokens').createIndex({ token: 1 }, { unique: true }).catch(() => { })
    await db.collection('verification_tokens').createIndex({ identifier: 1, token: 1 }, { unique: true }).catch(() => { })
    await db.collection('verification_tokens').createIndex({ expires: 1 }, { expireAfterSeconds: 0 }).catch(() => { })

    console.log('✅ Database indexes verified/created successfully')
  } catch (error) {
    // Ignore duplicate index errors
    if (error.code !== 85 && error.code !== 11000) {
      console.error('⚠️ Database setup warning:', error.message)
    }
  }
}

// Graceful shutdown handlers
process.on('SIGINT', async () => {
  if (cachedClient) {
    await cachedClient.close()
    console.log('📦 MongoDB connection closed (SIGINT)')
  }
  process.exit(0)
})

process.on('SIGTERM', async () => {
  if (cachedClient) {
    await cachedClient.close()
    console.log('📦 MongoDB connection closed (SIGTERM)')
  }
  process.exit(0)
})

// Client promise for NextAuth MongoDB adapter
let clientPromise

if (process.env.NODE_ENV === 'development') {
  // In development, use a global variable to preserve the connection
  if (!global._mongoClientPromise) {
    const mongoUri = process.env.MONGODB_URI
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable is required')
    }
    const client = new MongoClient(mongoUri, mongoOptions)
    global._mongoClientPromise = client.connect()
  }
  clientPromise = global._mongoClientPromise
} else {
  // In production, create a new connection promise
  const mongoUri = process.env.MONGODB_URI
  if (!mongoUri) {
    console.error('❌ MONGODB_URI is not set in production environment!')
    throw new Error('MONGODB_URI environment variable is required')
  }
  const client = new MongoClient(mongoUri, mongoOptions)
  clientPromise = client.connect()
}

export default clientPromise
