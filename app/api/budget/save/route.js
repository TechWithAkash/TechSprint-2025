import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'

// API route to save custom budget
export async function POST(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { budget } = await request.json()

    if (!budget || !budget.categories) {
      return NextResponse.json(
        { success: false, error: 'Invalid budget data' },
        { status: 400 }
      )
    }

    // Validate budget structure
    const requiredFields = ['totalBudget', 'categories', 'healthScore']
    const missingFields = requiredFields.filter(field => !budget[field])
    
    if (missingFields.length > 0) {
      return NextResponse.json(
        { success: false, error: `Missing required fields: ${missingFields.join(', ')}` },
        { status: 400 }
      )
    }

    // Add metadata for custom budget
    const customBudgetData = {
      ...budget,
      isCustomized: true,
      customizedAt: new Date().toISOString(),
      userId: session.user.id,
      version: '1.0'
    }

    console.log('Saving custom budget for user:', session.user.id)
    await dbConnect()
    const userProfile = await UserProfile.findOne({ userId: session.user.id })
    if (!userProfile) {
      return NextResponse.json({ success: false, error: 'User profile not found' }, { status: 404 })
    }

    // Merge with existing generated budget (preserve metadata & explanations if missing)
    const existing = userProfile.generatedBudget || {}
    const mergedBudget = {
      ...existing,
      ...customBudgetData,
      categories: { ...existing.categories, ...customBudgetData.categories },
      explanations: {
        ...existing.explanations,
        ...customBudgetData.explanations,
        categories: {
          ...(existing.explanations?.categories || {}),
          ...(customBudgetData.explanations?.categories || {})
        }
      }
    }

    userProfile.generatedBudget = mergedBudget
    userProfile.budgetHealthScore = customBudgetData.healthScore
    userProfile.lastBudgetGenerated = new Date()
    userProfile.markModified('generatedBudget')
    await userProfile.save()

    return NextResponse.json({
      success: true,
      message: 'Custom budget saved successfully',
  budget: mergedBudget
    })

  } catch (error) {
    console.error('Error saving custom budget:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to save custom budget' },
      { status: 500 }
    )
  }
}
