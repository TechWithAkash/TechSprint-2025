import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { expenseInsightsGenerator } from '@/lib/expenseInsightsGenerator'

// GET - Generate comprehensive expense insights report
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
        { error: 'User profile not found. Please complete onboarding first.' },
        { status: 404 }
      )
    }

    // Check if user has expenses
    const expenses = userProfile.expenses || []

    if (expenses.length === 0) {
      return NextResponse.json({
        success: true,
        report: null,
        message: 'No expenses found. Add some expenses to get AI-powered insights!',
        meta: {
          hasExpenses: false,
          hasBudget: !!userProfile.budget
        }
      })
    }

    // Prepare user data for insights generation
    const userData = {
      expenses,
      budget: userProfile.budget,
      profile: {
        city: userProfile.city,
        familySize: userProfile.familySize,
        age: userProfile.age,
        monthlyIncome: userProfile.monthlyIncome,
        occupation: userProfile.occupation
      }
    }

    // Generate comprehensive expense report
    const report = await expenseInsightsGenerator.generateExpenseReport(userData)

    return NextResponse.json({
      success: true,
      report,
      meta: {
        hasExpenses: true,
        expenseCount: expenses.length,
        hasBudget: !!userProfile.budget,
        aiEnabled: report.aiGenerated
      }
    })

  } catch (error) {
    console.error('Expense insights generation error:', error)
    return NextResponse.json(
      {
        error: 'Failed to generate expense insights',
        details: error.message
      },
      { status: 500 }
    )
  }
}
