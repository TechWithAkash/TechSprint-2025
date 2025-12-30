import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'

// GET - Get user's emergency alert settings
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

    // Return settings with defaults
    const defaultSettings = {
      enabled: true,
      emailAlertsEnabled: true,
      lowBalanceThreshold: 5000,
      criticalBalanceThreshold: 1000,
      budgetCriticalPercent: 100,
      unusualExpenseMultiplier: 3,
      quietHoursEnabled: true,
      quietHoursStart: 22,
      quietHoursEnd: 7,
      alertCooldownHours: 4,
      alertCategories: {
        lowBalance: true,
        budgetExceeded: true,
        unusualExpense: true,
        emiAtRisk: true
      }
    }

    const settings = {
      ...defaultSettings,
      ...userProfile.emergencyAlertSettings,
      alertCategories: {
        ...defaultSettings.alertCategories,
        ...userProfile.emergencyAlertSettings?.alertCategories
      }
    }

    return NextResponse.json({
      success: true,
      settings
    })

  } catch (error) {
    console.error('Get emergency settings error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch emergency settings' },
      { status: 500 }
    )
  }
}

// PUT - Update user's emergency alert settings
export async function PUT(request) {
  try {
    const session = await auth()

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const {
      enabled,
      emailAlertsEnabled,
      lowBalanceThreshold,
      criticalBalanceThreshold,
      budgetCriticalPercent,
      unusualExpenseMultiplier,
      quietHoursEnabled,
      quietHoursStart,
      quietHoursEnd,
      alertCooldownHours,
      alertCategories
    } = body

    // Validate thresholds
    if (lowBalanceThreshold !== undefined && lowBalanceThreshold < 0) {
      return NextResponse.json(
        { error: 'Low balance threshold cannot be negative' },
        { status: 400 }
      )
    }

    if (criticalBalanceThreshold !== undefined && criticalBalanceThreshold < 0) {
      return NextResponse.json(
        { error: 'Critical balance threshold cannot be negative' },
        { status: 400 }
      )
    }

    if (budgetCriticalPercent !== undefined && (budgetCriticalPercent < 50 || budgetCriticalPercent > 200)) {
      return NextResponse.json(
        { error: 'Budget critical percent must be between 50 and 200' },
        { status: 400 }
      )
    }

    if (unusualExpenseMultiplier !== undefined && (unusualExpenseMultiplier < 2 || unusualExpenseMultiplier > 10)) {
      return NextResponse.json(
        { error: 'Unusual expense multiplier must be between 2 and 10' },
        { status: 400 }
      )
    }

    if (alertCooldownHours !== undefined && (alertCooldownHours < 1 || alertCooldownHours > 24)) {
      return NextResponse.json(
        { error: 'Alert cooldown must be between 1 and 24 hours' },
        { status: 400 }
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

    // Update emergency alert settings
    userProfile.emergencyAlertSettings = {
      enabled: enabled !== undefined ? enabled : true,
      emailAlertsEnabled: emailAlertsEnabled !== undefined ? emailAlertsEnabled : true,
      lowBalanceThreshold: lowBalanceThreshold ?? 5000,
      criticalBalanceThreshold: criticalBalanceThreshold ?? 1000,
      budgetCriticalPercent: budgetCriticalPercent ?? 100,
      unusualExpenseMultiplier: unusualExpenseMultiplier ?? 3,
      quietHoursEnabled: quietHoursEnabled !== undefined ? quietHoursEnabled : true,
      quietHoursStart: quietHoursStart ?? 22,
      quietHoursEnd: quietHoursEnd ?? 7,
      alertCooldownHours: alertCooldownHours ?? 4,
      alertCategories: {
        lowBalance: alertCategories?.lowBalance !== undefined ? alertCategories.lowBalance : true,
        budgetExceeded: alertCategories?.budgetExceeded !== undefined ? alertCategories.budgetExceeded : true,
        unusualExpense: alertCategories?.unusualExpense !== undefined ? alertCategories.unusualExpense : true,
        emiAtRisk: alertCategories?.emiAtRisk !== undefined ? alertCategories.emiAtRisk : true
      },
      updatedAt: new Date()
    }

    await userProfile.save()

    return NextResponse.json({
      success: true,
      settings: userProfile.emergencyAlertSettings,
      message: 'Emergency settings updated successfully'
    })

  } catch (error) {
    console.error('Update emergency settings error:', error)
    return NextResponse.json(
      { error: 'Failed to update emergency settings' },
      { status: 500 }
    )
  }
}
