import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { connectToDatabase } from '@/lib/database'
import Debt from '@/models/Debt'
import { ObjectId } from 'mongodb'
import mongoose from 'mongoose'

// Connect to mongoose
async function connectMongoose() {
  if (mongoose.connections[0].readyState) {
    return
  }
  try {
    await mongoose.connect(process.env.MONGODB_URI)
  } catch (error) {
    console.error('Mongoose connection error:', error)
    throw error
  }
}

// GET /api/debt - Fetch all debts for the authenticated user
export async function GET(request) {
  try {
    // Check authentication
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Connect to database
    await connectMongoose()

    // Parse query parameters
    const { searchParams } = new URL(request.url)
    const type = searchParams.get('type') // 'taken' or 'given'
    const status = searchParams.get('status') // 'active', 'paid', etc.
    const sortBy = searchParams.get('sortBy') || 'dueDate'
    const sortOrder = searchParams.get('sortOrder') || 'asc'

    // Build query
    const query = { userId: new ObjectId(session.user.id) }
    
    if (type && ['taken', 'given'].includes(type)) {
      query.type = type
    }
    
    if (status && ['active', 'paid', 'overdue', 'defaulted'].includes(status)) {
      query.status = status
    }

    // Build sort object
    const sortObj = {}
    sortObj[sortBy] = sortOrder === 'desc' ? -1 : 1

    // Fetch debts
    const debts = await Debt.find(query)
      .sort(sortObj)
      .lean()

    // Get debt summary
    const summary = await Debt.getUserDebtSummary(session.user.id)

    return NextResponse.json({
      debts,
      summary,
      total: debts.length
    })

  } catch (error) {
    console.error('Debt fetch error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch debts' },
      { status: 500 }
    )
  }
}

// POST /api/debt - Add a new debt
export async function POST(request) {
  try {
    // Check authentication
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Connect to database
    await connectMongoose()

    // Parse request body
    const body = await request.json()
    const {
      type,
      name,
      amount,
      interestRate = 0,
      monthlyInstallment = 0,
      duration,
      dueDate,
      description = ''
    } = body

    // Validate required fields
    if (!type || !name || !amount || !duration) {
      return NextResponse.json(
        { error: 'Missing required fields: type, name, amount, duration' },
        { status: 400 }
      )
    }

    // Validate type
    if (!['taken', 'given'].includes(type)) {
      return NextResponse.json(
        { error: 'Type must be either "taken" or "given"' },
        { status: 400 }
      )
    }

    // Validate amount
    if (typeof amount !== 'number' || amount <= 0) {
      return NextResponse.json(
        { error: 'Amount must be a positive number' },
        { status: 400 }
      )
    }

    // Validate duration
    if (typeof duration !== 'number' || duration < 1 || duration > 600) {
      return NextResponse.json(
        { error: 'Duration must be between 1 and 600 months' },
        { status: 400 }
      )
    }

    // Calculate due date from duration if not provided
    let dueDateObj
    if (dueDate) {
      dueDateObj = new Date(dueDate)
      if (isNaN(dueDateObj.getTime())) {
        return NextResponse.json(
          { error: 'Invalid due date' },
          { status: 400 }
        )
      }
    } else {
      // Calculate due date from duration
      const today = new Date()
      dueDateObj = new Date(today.getFullYear(), today.getMonth() + duration, today.getDate())
    }

    // Create new debt
    const debt = new Debt({
      userId: new ObjectId(session.user.id),
      type,
      name: name.trim(),
      amount: Number(amount),
      interestRate: Number(interestRate) || 0,
      monthlyInstallment: Number(monthlyInstallment) || 0,
      duration: Number(duration),
      remainingBalance: Number(amount), // Initially, remaining balance equals original amount
      dueDate: dueDateObj,
      description: description.trim()
    })

    // Save to database
    await debt.save()

    return NextResponse.json({
      message: 'Debt added successfully',
      debt: debt.toObject()
    }, { status: 201 })

  } catch (error) {
    console.error('Debt creation error:', error)
    
    if (error.name === 'ValidationError') {
      return NextResponse.json(
        { error: 'Validation failed', details: error.errors },
        { status: 400 }
      )
    }
    
    return NextResponse.json(
      { error: 'Failed to create debt' },
      { status: 500 }
    )
  }
}
