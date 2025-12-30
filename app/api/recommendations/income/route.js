import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { advancedBudgetEngine } from '@/lib/advancedBudgetEngine'

// GET - Get income-based recommendations
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

    if (!userProfile) {
      return NextResponse.json(
        { error: 'Profile not found' },
        { status: 404 }
      )
    }

    // Get user's income data
    const monthlyIncome = userProfile.monthlyIncome || 0
    const incomeSources = userProfile.incomeSources || []
    const age = userProfile.age || 30

    if (monthlyIncome < 10000) {
      return NextResponse.json({
        success: true,
        message: 'Please complete your profile with income information',
        incomeReport: null
      })
    }

    // Calculate stability ratio from income sources
    let stabilityRatio = 100
    if (incomeSources.length > 0) {
      const totalIncome = incomeSources.reduce((sum, s) => {
        const multiplier = getFrequencyMultiplier(s.frequency)
        return sum + (s.amount * multiplier)
      }, 0)
      const stableIncome = incomeSources
        .filter(s => s.isStable)
        .reduce((sum, s) => {
          const multiplier = getFrequencyMultiplier(s.frequency)
          return sum + (s.amount * multiplier)
        }, 0)
      stabilityRatio = totalIncome > 0 ? Math.round((stableIncome / totalIncome) * 100) : 100
    }

    // Generate comprehensive income report
    const incomeReport = advancedBudgetEngine.generateIncomeReport({
      monthlyIncome,
      incomeSources: incomeSources.map(s => ({
        name: s.name,
        type: s.type,
        amount: s.amount,
        frequency: s.frequency,
        isStable: s.isStable
      })),
      age,
      hasHomeLoan: userProfile.hasHomeLoan || false,
      hasNPS: userProfile.hasNPS || false
    })

    // Get peer insights
    const userSavingsRate = userProfile.currentSavingsRate ||
      (userProfile.budgetPreferences?.savingsGoal / 100 * monthlyIncome) ||
      15
    const peerInsights = advancedBudgetEngine.getPeerInsights(monthlyIncome, userSavingsRate)

    // Get tax optimization recommendations
    const taxRecommendations = advancedBudgetEngine.getTaxOptimizationRecommendations(
      monthlyIncome,
      age,
      userProfile.hasHomeLoan || false,
      userProfile.hasNPS || false
    )

    // Get income-based recommendations
    const incomeRecommendations = advancedBudgetEngine.getIncomeBasedRecommendations(
      monthlyIncome,
      stabilityRatio,
      incomeSources
    )

    return NextResponse.json({
      success: true,
      incomeReport,
      peerInsights,
      taxRecommendations,
      incomeRecommendations,
      userProfile: {
        monthlyIncome,
        incomeSources: incomeSources.length,
        stabilityRatio,
        age
      }
    })

  } catch (error) {
    console.error('Get income recommendations error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch income recommendations' },
      { status: 500 }
    )
  }
}

// Helper function for frequency multipliers
function getFrequencyMultiplier(frequency) {
  const multipliers = {
    weekly: 4.33,
    'bi-weekly': 2.17,
    monthly: 1,
    quarterly: 0.33,
    annually: 0.083,
    irregular: 1
  }
  return multipliers[frequency] || 1
}
