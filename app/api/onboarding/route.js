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
      // Create new profile with minimal data - no validation errors
      userProfile = new UserProfile({
        userId: session.user.id,
        onboardingStep: 'income',
        onboardingCompleted: false
      })
      await userProfile.save()
    }

    // Check if onboarding is actually complete
    const isComplete = userProfile.isOnboardingComplete()
    if (isComplete && !userProfile.onboardingCompleted) {
      userProfile.onboardingCompleted = true
      userProfile.onboardingStep = 'completed'
      await userProfile.save()
    }

    return NextResponse.json({
      profile: {
        onboardingCompleted: userProfile.onboardingCompleted,
        onboardingStep: userProfile.onboardingStep,
        onboardingProgress: userProfile.getOnboardingProgress(),
        monthlyIncome: userProfile.monthlyIncome,
        incomeSources: userProfile.incomeSources || [],
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        occupation: userProfile.occupation,
        incomeSource: userProfile.incomeSource,
        budgetPreferences: userProfile.budgetPreferences,
        generatedBudget: userProfile.generatedBudget,
        // Enhanced demographics
        livingSituation: userProfile.livingSituation || '',
        commuteMode: userProfile.commuteMode || '',
        hasKids: userProfile.hasKids || false,
        monthlyRent: userProfile.monthlyRent || 0,
        // Financial pulse
        financialPulse: userProfile.financialPulse || {}
      }
    })

  } catch (error) {
    console.error('Get onboarding error:', error)
    
    // Provide specific error messages for different error types
    if (error.name === 'MongoServerError') {
      if (error.code === 8000) {
        return NextResponse.json(
          { error: 'Database configuration error. Please contact support.' },
          { status: 500 }
        )
      }
    }
    
    if (error.name === 'ValidationError') {
      return NextResponse.json(
        { error: 'Data validation failed', details: error.message },
        { status: 400 }
      )
    }
    
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
        const { monthlyIncome, incomeSource, incomeSources } = data

        // Support both multi-income and legacy single income
        const hasMultipleIncome = incomeSources && incomeSources.length > 0
        const hasLegacyIncome = monthlyIncome && monthlyIncome >= 1000

        if (!hasMultipleIncome && !hasLegacyIncome) {
          return NextResponse.json(
            { error: 'Please add at least one income source with minimum ₹1,000' },
            { status: 400 }
          )
        }

        // If multi-income sources provided, save them and calculate total
        if (hasMultipleIncome) {
          // Strip out temp IDs - MongoDB will generate proper ObjectIds
          userProfile.incomeSources = incomeSources.map(source => {
            const { _id, ...sourceWithoutId } = source
            // Only keep the _id if it's a valid MongoDB ObjectId (24 hex chars)
            if (_id && /^[a-f\d]{24}$/i.test(_id)) {
              return source
            }
            return sourceWithoutId
          })
          // Calculate total monthly income from all sources
          const totalMonthly = incomeSources.reduce((sum, source) => {
            if (!source.includeInBudget) return sum
            const multipliers = {
              weekly: 4.33,
              'bi-weekly': 2.17,
              monthly: 1,
              quarterly: 0.33,
              annually: 0.083,
              irregular: 1
            }
            return sum + Math.round(source.amount * (multipliers[source.frequency] || 1))
          }, 0)
          userProfile.monthlyIncome = totalMonthly
          // Set primary income source type
          const primarySource = incomeSources.reduce((primary, source) => {
            const multipliers = { weekly: 4.33, 'bi-weekly': 2.17, monthly: 1, quarterly: 0.33, annually: 0.083, irregular: 1 }
            const normalizedAmount = Math.round(source.amount * (multipliers[source.frequency] || 1))
            return normalizedAmount > (primary?.normalizedAmount || 0)
              ? { ...source, normalizedAmount }
              : primary
          }, null)
          userProfile.incomeSource = primarySource?.type || 'salary'
        } else {
          // Legacy single income
          userProfile.monthlyIncome = monthlyIncome
          userProfile.incomeSource = incomeSource || 'salary'
        }

        userProfile.onboardingStep = 'demographics'
        break

      case 'demographics':
        const { city, familySize, age, occupation, livingSituation, commuteMode, hasKids, monthlyRent } = data

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

        // Core demographics
        userProfile.city = city.trim()
        userProfile.familySize = parseInt(familySize)
        userProfile.age = parseInt(age)
        userProfile.occupation = occupation?.trim() || ''

        // Enhanced demographics for better AI personalization
        userProfile.livingSituation = livingSituation || ''
        userProfile.commuteMode = commuteMode || ''
        userProfile.hasKids = hasKids === true
        userProfile.monthlyRent = monthlyRent ? parseInt(monthlyRent) : 0

        userProfile.onboardingStep = 'financial_pulse'
        break

      case 'financial_pulse':
        // Strategic questions that power AI recommendations
        const { financialPulse, budgetPreferences } = data

        if (financialPulse) {
          userProfile.financialPulse = {
            debtStatus: financialPulse.debt_status || '',
            savingsStatus: financialPulse.savings_status || '',
            moneyStress: financialPulse.money_stress || '',
            spendingStyle: financialPulse.spending_style || '',
            primaryGoal: financialPulse.primary_goal || ''
          }
        }

        // Merge budget preferences from pulse answers
        if (budgetPreferences) {
          userProfile.budgetPreferences = {
            ...userProfile.budgetPreferences,
            ...budgetPreferences
          }
        }

        userProfile.onboardingStep = 'budget_generation'
        break

      case 'lifestyle_quiz':
        // Legacy support for old lifestyle quiz
        const { lifestyleAnswers } = data
        if (lifestyleAnswers) {
          userProfile.lifestyleAnswers = lifestyleAnswers
        }
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
        incomeSources: userProfile.incomeSources || [],
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        occupation: userProfile.occupation,
        incomeSource: userProfile.incomeSource,
        budgetPreferences: userProfile.budgetPreferences,
        // Enhanced demographics
        livingSituation: userProfile.livingSituation || '',
        commuteMode: userProfile.commuteMode || '',
        hasKids: userProfile.hasKids || false,
        monthlyRent: userProfile.monthlyRent || 0,
        // Financial pulse
        financialPulse: userProfile.financialPulse || {}
      }
    })

  } catch (error) {
    console.error('Update onboarding error:', error)
    
    // Provide specific error messages for different error types
    if (error.name === 'MongoServerError') {
      if (error.code === 8000) {
        return NextResponse.json(
          { error: 'Database configuration error. Please contact support.' },
          { status: 500 }
        )
      }
    }
    
    if (error.name === 'ValidationError') {
      return NextResponse.json(
        { error: 'Data validation failed', details: error.message },
        { status: 400 }
      )
    }
    
    return NextResponse.json(
      { error: 'Failed to update onboarding data' },
      { status: 500 }
    )
  }
}
