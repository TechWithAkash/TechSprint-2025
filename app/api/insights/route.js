import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { insightsGenerator } from '@/lib/insightsGenerator'
import { getUpcomingEvents } from '@/lib/indianFinancialCalendar'

// GET - Generate personalized financial insights
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

    // Fetch user profile with all data
    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Get upcoming seasonal events
    let seasonalEvents = []
    try {
      seasonalEvents = getUpcomingEvents(90) // Next 90 days
    } catch (e) {
      console.warn('Could not fetch seasonal events:', e)
    }

    // Prepare user data for insights generation
    const userData = {
      budget: userProfile.budget,
      expenses: userProfile.expenses || [],
      goals: userProfile.savingsGoals || [],
      profile: {
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        monthlyIncome: userProfile.monthlyIncome
      },
      seasonalEvents
    }

    // Generate insights
    const insights = await insightsGenerator.generateInsights(userData)

    return NextResponse.json({
      success: true,
      insights,
      generatedAt: new Date().toISOString(),
      meta: {
        totalExpenses: userData.expenses.length,
        totalGoals: userData.goals.length,
        hasBudget: !!userData.budget
      }
    })

  } catch (error) {
    console.error('Insights generation error:', error)
    return NextResponse.json(
      { error: 'Failed to generate insights', details: error.message },
      { status: 500 }
    )
  }
}
