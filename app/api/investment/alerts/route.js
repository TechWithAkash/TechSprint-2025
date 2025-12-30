import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { investmentAlertSystem } from '@/lib/investmentAlerts'

// POST - Check for investment opportunities
export async function POST(request) {
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
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Calculate user's current savings from budget
    let userSavings = 0
    if (userProfile.generatedBudget && userProfile.generatedBudget.savings) {
      userSavings = userProfile.generatedBudget.savings.amount || 0
    }

    // Check for investment opportunities
    const opportunityResult = investmentAlertSystem.checkInvestmentOpportunity(
      userSavings, 
      userProfile
    )

    if (opportunityResult) {
      console.log('Investment opportunity found:', opportunityResult)
      
      return NextResponse.json({
        success: true,
        hasOpportunity: true,
        alert: opportunityResult.alert,
        userSavings: userSavings
      })
    } else {
      return NextResponse.json({
        success: true,
        hasOpportunity: false,
        message: 'No investment opportunities at this time',
        userSavings: userSavings
      })
    }

  } catch (error) {
    console.error('Investment alert error:', error)
    return NextResponse.json(
      { error: 'Failed to check investment opportunities', details: error.message },
      { status: 500 }
    )
  }
}

// GET - Get current market status
export async function GET() {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Update market data for demo
    investmentAlertSystem.updateMarketData()

    return NextResponse.json({
      success: true,
      marketData: investmentAlertSystem.marketData,
      lastUpdate: new Date(),
      features: {
        alertsEnabled: true,
        simulationMode: true,
        minSavingsRequired: 500
      }
    })

  } catch (error) {
    console.error('Market data error:', error)
    return NextResponse.json(
      { error: 'Failed to get market data' },
      { status: 500 }
    )
  }
}
