import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { budgetGenerator } from '@/lib/budgetGenerator'

// GET - Get user's onboarding status and current profile
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

    let userProfile = await UserProfile.findOne({ userId: session.user.id })
    
    if (!userProfile) {
      // Create new profile with default values
      userProfile = new UserProfile({
        userId: session.user.id,
        onboardingStep: 'income'
      })
      await userProfile.save()
    }

    return NextResponse.json({
      profile: {
        onboardingCompleted: userProfile.onboardingCompleted,
        onboardingStep: userProfile.onboardingStep,
        monthlyIncome: userProfile.monthlyIncome,
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        occupation: userProfile.occupation,
        incomeSource: userProfile.incomeSource,
        budgetPreferences: userProfile.budgetPreferences,
        generatedBudget: userProfile.generatedBudget
      }
    })

  } catch (error) {
    console.error('Get onboarding error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch onboarding data' },
      { status: 500 }
    )
  }
}

// POST - Update onboarding step data
export async function POST(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const { step, data } = body

    if (!step || !data) {
      return NextResponse.json(
        { error: 'Step and data are required' },
        { status: 400 }
      )
    }

    await dbConnect()

    let userProfile = await UserProfile.findOne({ userId: session.user.id })
    
    if (!userProfile) {
      userProfile = new UserProfile({ userId: session.user.id })
    }

    // Update profile based on step
    switch (step) {
      case 'income':
        const { monthlyIncome, incomeSource } = data
        
        if (!monthlyIncome || monthlyIncome < 1000) {
          return NextResponse.json(
            { error: 'Monthly income must be at least ₹1,000' },
            { status: 400 }
          )
        }

        userProfile.monthlyIncome = monthlyIncome
        userProfile.incomeSource = incomeSource || 'salary'
        userProfile.onboardingStep = 'demographics'
        break

      case 'demographics':
        const { city, familySize, age, occupation } = data
        
        if (!city || city.trim().length < 2) {
          return NextResponse.json(
            { error: 'Please provide a valid city name' },
            { status: 400 }
          )
        }

        if (!familySize || familySize < 1 || familySize > 20) {
          return NextResponse.json(
            { error: 'Family size must be between 1 and 20' },
            { status: 400 }
          )
        }

        if (!age || age < 18 || age > 100) {
          return NextResponse.json(
            { error: 'Age must be between 18 and 100' },
            { status: 400 }
          )
        }

        userProfile.city = city.trim()
        userProfile.familySize = parseInt(familySize)
        userProfile.age = parseInt(age)
        userProfile.occupation = occupation?.trim() || ''
        userProfile.onboardingStep = 'budget_generation'
        break

      case 'preferences':
        const { language, notifications } = data
        
        userProfile.budgetPreferences = {
          language: language || 'hinglish',
          currency: 'INR',
          notifications: notifications !== false
        }
        userProfile.onboardingStep = 'budget_generation'
        break

      case 'complete':
        userProfile.onboardingCompleted = true
        userProfile.onboardingStep = 'completed'
        break

      default:
        return NextResponse.json(
          { error: 'Invalid onboarding step' },
          { status: 400 }
        )
    }

    await userProfile.save()

    return NextResponse.json({
      success: true,
      profile: {
        onboardingCompleted: userProfile.onboardingCompleted,
        onboardingStep: userProfile.onboardingStep,
        monthlyIncome: userProfile.monthlyIncome,
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        occupation: userProfile.occupation,
        incomeSource: userProfile.incomeSource,
        budgetPreferences: userProfile.budgetPreferences
      }
    })

  } catch (error) {
    console.error('Update onboarding error:', error)
    return NextResponse.json(
      { error: 'Failed to update onboarding data' },
      { status: 500 }
    )
  }
}
