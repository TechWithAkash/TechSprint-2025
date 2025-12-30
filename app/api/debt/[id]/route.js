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

// PUT /api/debt/[id] - Update a debt
export async function PUT(request, { params }) {
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

    const { id } = params

    // Validate ObjectId
    if (!ObjectId.isValid(id)) {
      return NextResponse.json(
        { error: 'Invalid debt ID' },
        { status: 400 }
      )
    }

    // Parse request body
    const body = await request.json()
    const {
      name,
      amount,
      interestRate,
      monthlyInstallment,
      duration,
      remainingBalance,
      dueDate,
      description,
      status
    } = body

    // Find the debt (ensure it belongs to the authenticated user)
    const debt = await Debt.findOne({
      _id: new ObjectId(id),
      userId: new ObjectId(session.user.id)
    })

    if (!debt) {
      return NextResponse.json(
        { error: 'Debt not found' },
        { status: 404 }
      )
    }

    // Update fields
    if (name !== undefined) debt.name = name.trim()
    if (amount !== undefined) {
      if (typeof amount !== 'number' || amount <= 0) {
        return NextResponse.json(
          { error: 'Amount must be a positive number' },
          { status: 400 }
        )
      }
      debt.amount = Number(amount)
    }
    if (interestRate !== undefined) debt.interestRate = Number(interestRate) || 0
    if (monthlyInstallment !== undefined) debt.monthlyInstallment = Number(monthlyInstallment) || 0
    if (duration !== undefined) {
      if (typeof duration !== 'number' || duration < 1 || duration > 600) {
        return NextResponse.json(
          { error: 'Duration must be between 1 and 600 months' },
          { status: 400 }
        )
      }
      debt.duration = Number(duration)
    }
    if (remainingBalance !== undefined) {
      if (typeof remainingBalance !== 'number' || remainingBalance < 0) {
        return NextResponse.json(
          { error: 'Remaining balance must be a non-negative number' },
          { status: 400 }
        )
      }
      debt.remainingBalance = Number(remainingBalance)
    }
    if (dueDate !== undefined) {
      const dueDateObj = new Date(dueDate)
      if (isNaN(dueDateObj.getTime())) {
        return NextResponse.json(
          { error: 'Invalid due date' },
          { status: 400 }
        )
      }
      debt.dueDate = dueDateObj
    }
    if (description !== undefined) debt.description = description.trim()
    if (status !== undefined) {
      if (!['active', 'paid', 'overdue', 'defaulted'].includes(status)) {
        return NextResponse.json(
          { error: 'Invalid status' },
          { status: 400 }
        )
      }
      debt.status = status
    }

    // Save updated debt
    await debt.save()

    return NextResponse.json({
      message: 'Debt updated successfully',
      debt: debt.toObject()
    })

  } catch (error) {
    console.error('Debt update error:', error)
    
    if (error.name === 'ValidationError') {
      return NextResponse.json(
        { error: 'Validation failed', details: error.errors },
        { status: 400 }
      )
    }
    
    return NextResponse.json(
      { error: 'Failed to update debt' },
      { status: 500 }
    )
  }
}

// DELETE /api/debt/[id] - Delete a debt
export async function DELETE(request, { params }) {
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

    const { id } = params

    // Validate ObjectId
    if (!ObjectId.isValid(id)) {
      return NextResponse.json(
        { error: 'Invalid debt ID' },
        { status: 400 }
      )
    }

    // Delete the debt (ensure it belongs to the authenticated user)
    const result = await Debt.findOneAndDelete({
      _id: new ObjectId(id),
      userId: new ObjectId(session.user.id)
    })

    if (!result) {
      return NextResponse.json(
        { error: 'Debt not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      message: 'Debt deleted successfully'
    })

  } catch (error) {
    console.error('Debt deletion error:', error)
    return NextResponse.json(
      { error: 'Failed to delete debt' },
      { status: 500 }
    )
  }
}

// GET /api/debt/[id] - Get a specific debt
export async function GET(request, { params }) {
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

    const { id } = params

    // Validate ObjectId
    if (!ObjectId.isValid(id)) {
      return NextResponse.json(
        { error: 'Invalid debt ID' },
        { status: 400 }
      )
    }

    // Find the debt (ensure it belongs to the authenticated user)
    const debt = await Debt.findOne({
      _id: new ObjectId(id),
      userId: new ObjectId(session.user.id)
    }).lean()

    if (!debt) {
      return NextResponse.json(
        { error: 'Debt not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({ debt })

  } catch (error) {
    console.error('Debt fetch error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch debt' },
      { status: 500 }
    )
  }
}
