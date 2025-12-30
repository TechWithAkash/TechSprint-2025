import { NextResponse } from 'next/server'
import dbConnect from '@/lib/dbConnect'

export async function GET() {
  try {
    // Test database connection
    await dbConnect()
    
    return NextResponse.json({
      status: 'healthy',
      message: 'Database connection successful',
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Health check failed:', error)
    
    return NextResponse.json({
      status: 'unhealthy',
      message: 'Database connection failed',
      error: error.message,
      timestamp: new Date().toISOString()
    }, { status: 500 })
  }
}
