import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { retentionEngine } from '@/lib/retentionEngine'

/**
 * GET /api/retention/smart-nudges
 * Get pending smart nudges for the user
 */
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
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Check if nudges are enabled
    if (userProfile.retentionPreferences?.smartNudgesEnabled === false) {
      return NextResponse.json({
        success: true,
        nudges: [],
        disabled: true
      })
    }

    // Check quiet hours
    const now = new Date()
    const currentHour = now.getHours()
    const quietStart = userProfile.retentionPreferences?.quietHoursStart ?? 22
    const quietEnd = userProfile.retentionPreferences?.quietHoursEnd ?? 7

    const isQuietHours = quietStart > quietEnd
      ? (currentHour >= quietStart || currentHour < quietEnd)
      : (currentHour >= quietStart && currentHour < quietEnd)

    if (isQuietHours) {
      return NextResponse.json({
        success: true,
        nudges: [],
        quietHours: true
      })
    }

    // Get nudges
    const userData = {
      expenses: userProfile.expenses || [],
      budget: userProfile.generatedBudget,
      goals: userProfile.goals || [],
      profile: {
        monthlyIncome: userProfile.monthlyIncome
      },
      activityTracking: userProfile.activityTracking || {},
      nudgeHistory: userProfile.activityTracking?.nudgeHistory || []
    }

    const nudges = retentionEngine.checkSmartNudges(userData)

    return NextResponse.json({
      success: true,
      nudges
    })

  } catch (error) {
    console.error('Smart nudges GET error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch nudges', details: error.message },
      { status: 500 }
    )
  }
}

/**
 * POST /api/retention/smart-nudges
 * Dismiss a nudge or record interaction
 */
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
    const { nudgeId, nudgeType, action } = body

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Initialize if needed
    if (!userProfile.activityTracking) {
      userProfile.activityTracking = {}
    }
    if (!userProfile.activityTracking.nudgeHistory) {
      userProfile.activityTracking.nudgeHistory = []
    }

    if (action === 'dismiss' && nudgeType) {
      // Record dismissed nudge
      userProfile.activityTracking.nudgeHistory.push({
        type: nudgeType,
        sentAt: new Date(),
        dismissed: true
      })

      // Keep only last 50 nudges
      if (userProfile.activityTracking.nudgeHistory.length > 50) {
        userProfile.activityTracking.nudgeHistory =
          userProfile.activityTracking.nudgeHistory.slice(-50)
      }

      await userProfile.save()

      return NextResponse.json({
        success: true,
        message: 'Nudge dismissed'
      })
    }

    if (action === 'clicked' && nudgeType) {
      // Record that user clicked on the nudge
      userProfile.activityTracking.nudgeHistory.push({
        type: nudgeType,
        sentAt: new Date(),
        dismissed: false,
        clicked: true
      })

      await userProfile.save()

      return NextResponse.json({
        success: true,
        message: 'Nudge interaction recorded'
      })
    }

    if (action === 'toggle') {
      // Toggle nudges enabled/disabled
      if (!userProfile.retentionPreferences) {
        userProfile.retentionPreferences = {}
      }
      userProfile.retentionPreferences.smartNudgesEnabled =
        !userProfile.retentionPreferences.smartNudgesEnabled

      await userProfile.save()

      return NextResponse.json({
        success: true,
        enabled: userProfile.retentionPreferences.smartNudgesEnabled
      })
    }

    return NextResponse.json(
      { error: 'Invalid action' },
      { status: 400 }
    )

  } catch (error) {
    console.error('Smart nudges POST error:', error)
    return NextResponse.json(
      { error: 'Failed to process nudge action', details: error.message },
      { status: 500 }
    )
  }
}
