import mongoose from 'mongoose'

const MONGODB_URI = process.env.MONGODB_URI

if (!MONGODB_URI) {
  throw new Error('Please define the MONGODB_URI environment variable inside .env.local')
}

/**
 * Global is used here to maintain a cached connection across hot reloads
 * in development. This prevents connections growing exponentially
 * during API Route usage.
 */
let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

async function dbConnect() {
  // Return cached connection if available
  if (cached.conn) {
    return cached.conn
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      // Additional production-ready options
      maxIdleTimeMS: 30000,
      serverApi: '1',
    }

    try {
      cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => {
        console.log('✅ Connected to MongoDB with Mongoose')
        
        // Handle connection events
        mongoose.connection.on('error', (err) => {
          console.error('❌ MongoDB connection error:', err)
        })
        
        mongoose.connection.on('disconnected', () => {
          console.log('⚠️ MongoDB disconnected')
        })
        
        return mongoose
      }).catch((error) => {
        console.error('❌ MongoDB connection failed:', error)
        cached.promise = null
        throw error
      })
    } catch (error) {
      console.error('❌ Failed to create MongoDB connection promise:', error)
      cached.promise = null
      throw error
    }
  }

  try {
    cached.conn = await cached.promise
  } catch (e) {
    cached.promise = null
    console.error('❌ MongoDB connection failed:', e)
    throw e
  }

  return cached.conn
}

// Graceful shutdown handling
if (process.env.NODE_ENV !== 'production') {
  process.on('SIGINT', async () => {
    if (cached.conn) {
      await mongoose.connection.close()
      console.log('📦 MongoDB connection closed through app termination')
    }
  })
}

export default dbConnect
