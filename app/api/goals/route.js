import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'

// GET - Get user goals
export async function GET(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })
    
    if (!userProfile) {
      return NextResponse.json({
        success: true,
        goals: []
      })
    }

    const goals = userProfile.goals || []

    return NextResponse.json({
      success: true,
      goals: goals,
      totalGoals: goals.length,
      totalTargetAmount: goals.reduce((sum, goal) => sum + goal.targetAmount, 0),
      totalCurrentAmount: goals.reduce((sum, goal) => sum + goal.currentAmount, 0)
    })

  } catch (error) {
    console.error('Get goals error:', error)
    return NextResponse.json(
      { error: 'Failed to get goals', details: error.message },
      { status: 500 }
    )
  }
}

// POST - Create new goal
export async function POST(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const goalData = await request.json()
    
    // Validate goal data
    if (!goalData.name || !goalData.targetAmount || !goalData.targetMonths) {
      return NextResponse.json(
        { error: 'Name, target amount, and target months are required' },
        { status: 400 }
      )
    }

    if (goalData.targetAmount < 1000) {
      return NextResponse.json(
        { error: 'Target amount must be at least ₹1,000' },
        { status: 400 }
      )
    }

    if (goalData.targetMonths < 1 || goalData.targetMonths > 120) {
      return NextResponse.json(
        { error: 'Target months must be between 1 and 120' },
        { status: 400 }
      )
    }

    await dbConnect()

    // Find user profile
    const userProfile = await UserProfile.findOne({ userId: session.user.id })
    
    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Create goal entry
    const goal = {
      id: Date.now().toString(),
      name: goalData.name.trim(),
      description: goalData.description?.trim() || '',
      targetAmount: Number(goalData.targetAmount),
      currentAmount: Number(goalData.currentAmount) || 0,
      targetMonths: Number(goalData.targetMonths),
      targetDate: goalData.targetDate || new Date(Date.now() + (goalData.targetMonths * 30 * 24 * 60 * 60 * 1000)).toISOString(),
      templateId: goalData.templateId || 'custom',
      category: goalData.category || 'General',
      priority: goalData.priority || 'Medium',
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }

    // Initialize goals array if it doesn't exist
    if (!userProfile.goals) {
      userProfile.goals = []
    }

    // Add goal to user profile
    userProfile.goals.push(goal)
    
    // Update user profile
    userProfile.markModified('goals')
    await userProfile.save()

    console.log('Goal created successfully:', goal)

    return NextResponse.json({
      success: true,
      message: 'Goal created successfully',
      goal: goal,
      totalGoals: userProfile.goals.length
    })

  } catch (error) {
    console.error('Create goal error:', error)
    return NextResponse.json(
      { error: 'Failed to create goal', details: error.message },
      { status: 500 }
    )
  }
}

// PUT - Update goal (add money, update details, etc.)
export async function PUT(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { goalId, updateType, amount, ...updateData } = await request.json()
    
    if (!goalId) {
      return NextResponse.json(
        { error: 'Goal ID is required' },
        { status: 400 }
      )
    }

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })
    
    if (!userProfile || !userProfile.goals) {
      return NextResponse.json(
        { error: 'User profile or goals not found' },
        { status: 404 }
      )
    }

    // Find the goal
    const goalIndex = userProfile.goals.findIndex(goal => goal.id === goalId)
    
    if (goalIndex === -1) {
      return NextResponse.json(
        { error: 'Goal not found' },
        { status: 404 }
      )
    }

    const goal = userProfile.goals[goalIndex]

    // Handle different update types
    if (updateType === 'add_money' && amount) {
      goal.currentAmount = (goal.currentAmount || 0) + Number(amount)
      
      // Check if goal is completed
      if (goal.currentAmount >= goal.targetAmount) {
        goal.status = 'completed'
        goal.completedAt = new Date().toISOString()
      }
    } else if (updateType === 'update_details') {
      // Update goal details
      Object.keys(updateData).forEach(key => {
        if (updateData[key] !== undefined && key !== 'id' && key !== 'createdAt') {
          goal[key] = updateData[key]
        }
      })
    }

    goal.updatedAt = new Date().toISOString()

    // Update user profile
    userProfile.markModified('goals')
    await userProfile.save()

    console.log('Goal updated successfully:', goal)

    return NextResponse.json({
      success: true,
      message: 'Goal updated successfully',
      goal: goal
    })

  } catch (error) {
    console.error('Update goal error:', error)
    return NextResponse.json(
      { error: 'Failed to update goal', details: error.message },
      { status: 500 }
    )
  }
}

// DELETE - Delete a goal
export async function DELETE(request) {
  try {
    const session = await auth()

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { goalId } = await request.json()

    if (!goalId) {
      return NextResponse.json(
        { error: 'Goal ID is required' },
        { status: 400 }
      )
    }

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile || !userProfile.goals) {
      return NextResponse.json(
        { error: 'User profile or goals not found' },
        { status: 404 }
      )
    }

    // Find and remove the goal
    const goalIndex = userProfile.goals.findIndex(goal => goal.id === goalId)

    if (goalIndex === -1) {
      return NextResponse.json(
        { error: 'Goal not found' },
        { status: 404 }
      )
    }

    // Remove the goal
    userProfile.goals.splice(goalIndex, 1)

    // Update user profile
    userProfile.markModified('goals')
    await userProfile.save()

    console.log('Goal deleted successfully:', goalId)

    return NextResponse.json({
      success: true,
      message: 'Goal deleted successfully'
    })

  } catch (error) {
    console.error('Delete goal error:', error)
    return NextResponse.json(
      { error: 'Failed to delete goal', details: error.message },
      { status: 500 }
    )
  }
}
