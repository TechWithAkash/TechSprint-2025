
import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'  
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { budgetGenerator, AIBudgetGenerator } from '@/lib/budgetGenerator'

// POST - Generate AI budget for user
export async function POST() {
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
      return NextResponse.json(
        { error: 'User profile not found. Please complete onboarding first.' },
        { status: 404 }
      )
    }

    // Validate required data for budget generation
    const validation = AIBudgetGenerator.validateInput(userProfile)
    if (!validation.isValid) {
      return NextResponse.json(
        { error: 'Incomplete profile data', details: validation.errors },
        { status: 400 }
      )
    }

    // Generate AI-powered budget with Gemini insights
    console.log('Starting budget generation...')
    const generatedBudget = await budgetGenerator.generateBudget({
      monthlyIncome: userProfile.monthlyIncome,
      city: userProfile.city,
      familySize: userProfile.familySize,
      age: userProfile.age,
      occupation: userProfile.occupation || '',
      budgetPreferences: userProfile.budgetPreferences || {}
    })

    console.log('Budget generated successfully')
    console.log('Generated budget recommendations type:', typeof generatedBudget.recommendations)
    console.log('Generated budget recommendations isArray:', Array.isArray(generatedBudget.recommendations))
    console.log('Generated budget recommendations:', JSON.stringify(generatedBudget.recommendations, null, 2))

    // Calculate budget health score
    const healthScore = budgetGenerator.getBudgetHealthScore(generatedBudget)

    // Create a clean budget object for database storage
    const budgetForStorage = {
      categories: {},
      totalBudget: Number(generatedBudget.totalBudget),
      totalAllocated: Number(generatedBudget.totalAllocated),
      savings: {
        amount: Number(generatedBudget.savings?.amount || 0),
        percentage: Number(generatedBudget.savings?.percentage || 0)
      },
      explanations: {
        overall: String(generatedBudget.explanations?.overall || ''),
        categories: {}
      },
      tips: [],
      recommendations: [],
      healthScore: Number(healthScore),
      generatedAt: new Date(),
      metadata: generatedBudget.metadata || {}
    }

    // Convert categories and explanations to regular objects 
    if (generatedBudget.categories && typeof generatedBudget.categories === 'object') {
      Object.entries(generatedBudget.categories).forEach(([key, value]) => {
        budgetForStorage.categories[key] = value
      })
    }

    if (generatedBudget.explanations?.categories && typeof generatedBudget.explanations.categories === 'object') {
      Object.entries(generatedBudget.explanations.categories).forEach(([key, value]) => {
        budgetForStorage.explanations.categories[key] = String(value)
      })
    }

    // Handle tips
    if (Array.isArray(generatedBudget.tips)) {
      budgetForStorage.tips = generatedBudget.tips
    } else if (generatedBudget.tips) {
      budgetForStorage.tips = [String(generatedBudget.tips)]
    }

    // Handle recommendations - save as raw object
    budgetForStorage.recommendations = generatedBudget.recommendations || []

    console.log('Final budget for storage:', JSON.stringify(budgetForStorage, null, 2))

    // Update userProfile with raw object data (let Mongoose handle the conversion)
    userProfile.generatedBudget = budgetForStorage
    userProfile.markModified('generatedBudget')  // Explicitly mark as modified for Mixed types
    
    userProfile.budgetHealthScore = healthScore
    userProfile.lastBudgetGenerated = new Date()
    userProfile.onboardingStep = 'review'

    console.log('Saving user profile...')
    await userProfile.save()
    console.log('User profile saved successfully')

    return NextResponse.json({
      success: true,
      budget: {
        categories: budgetForStorage.categories,
        totalBudget: budgetForStorage.totalBudget,
        totalAllocated: budgetForStorage.totalAllocated,
        savings: budgetForStorage.savings,
        explanations: budgetForStorage.explanations,
        tips: budgetForStorage.tips,
        recommendations: budgetForStorage.recommendations,
        healthScore: budgetForStorage.healthScore,
        generatedAt: budgetForStorage.generatedAt,
        metadata: budgetForStorage.metadata
      }
    })

  } catch (error) {
    console.error('Generate budget error:', error)
    return NextResponse.json(
      { error: 'Failed to generate budget', details: error.message },
      { status: 500 }
    )
  }
}

// GET - Get existing budget for user
export async function GET() {
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
    
    if (!userProfile || !userProfile.generatedBudget) {
      return NextResponse.json(
        { error: 'No budget found. Please generate budget first.' },
        { status: 404 }
      )
    }

    // Return the budget directly since it's stored as Mixed type
    return NextResponse.json({
      success: true,
      budget: userProfile.generatedBudget,
      profile: {
        monthlyIncome: userProfile.monthlyIncome,
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        occupation: userProfile.occupation
      }
    })

  } catch (error) {
    console.error('Get budget error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch budget', details: error.message },
      { status: 500 }
    )
  }
}
