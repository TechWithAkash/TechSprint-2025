import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { retentionEngine } from '@/lib/retentionEngine'

/**
 * GET /api/retention/daily-tip
 * Returns personalized daily tip for the user
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

    // Check if tips are enabled
    if (userProfile.retentionPreferences?.dailyTipsEnabled === false) {
      return NextResponse.json({
        success: true,
        tip: null,
        disabled: true
      })
    }

    // Check if tip was already shown today
    const today = new Date().toISOString().split('T')[0]
    const lastTipDate = userProfile.activityTracking?.lastTipShownDate
    const lastTipToday = lastTipDate &&
      new Date(lastTipDate).toISOString().split('T')[0] === today

    // Get last shown tip if it's from today
    if (lastTipToday && userProfile.activityTracking?.tipsShown?.length > 0) {
      const tipsShown = userProfile.activityTracking.tipsShown
      const todaysTip = tipsShown[tipsShown.length - 1]

      return NextResponse.json({
        success: true,
        tip: {
          id: todaysTip.tipId,
          message: todaysTip.message || 'Keep tracking your expenses!',
          category: todaysTip.category || 'general',
          alreadyShown: true
        }
      })
    }

    // Generate new tip
    const userData = {
      expenses: userProfile.expenses || [],
      budget: userProfile.generatedBudget,
      goals: userProfile.goals || [],
      profile: {
        monthlyIncome: userProfile.monthlyIncome,
        city: userProfile.city,
        familySize: userProfile.familySize
      },
      tipsShown: userProfile.activityTracking?.tipsShown || []
    }

    const tip = retentionEngine.generateDailyTip(userData)

    if (!tip) {
      return NextResponse.json({
        success: true,
        tip: null
      })
    }

    // Save tip to history
    if (!userProfile.activityTracking) {
      userProfile.activityTracking = {}
    }
    if (!userProfile.activityTracking.tipsShown) {
      userProfile.activityTracking.tipsShown = []
    }

    userProfile.activityTracking.tipsShown.push({
      tipId: tip.id,
      shownAt: new Date(),
      feedback: null,
      message: tip.message,
      category: tip.category
    })

    // Keep only last 30 tips
    if (userProfile.activityTracking.tipsShown.length > 30) {
      userProfile.activityTracking.tipsShown =
        userProfile.activityTracking.tipsShown.slice(-30)
    }

    userProfile.activityTracking.lastTipShownDate = new Date()
    userProfile.activityTracking.lastActiveDate = new Date()

    await userProfile.save()

    return NextResponse.json({
      success: true,
      tip: {
        id: tip.id,
        title: tip.title,
        message: tip.message,
        category: tip.category,
        priority: tip.priority
      }
    })

  } catch (error) {
    console.error('Daily tip API error:', error)
    return NextResponse.json(
      { error: 'Failed to generate daily tip', details: error.message },
      { status: 500 }
    )
  }
}

/**
 * POST /api/retention/daily-tip
 * Submit feedback on a tip or dismiss tips for the day
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
    const { tipId, feedback, action } = body

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    if (action === 'feedback' && tipId && feedback) {
      // Record feedback on tip
      const tipsShown = userProfile.activityTracking?.tipsShown || []
      const tipIndex = tipsShown.findIndex(t => t.tipId === tipId)

      if (tipIndex !== -1) {
        tipsShown[tipIndex].feedback = feedback
        userProfile.activityTracking.tipsShown = tipsShown
        await userProfile.save()

        return NextResponse.json({
          success: true,
          message: 'Feedback recorded'
        })
      }
    }

    if (action === 'dismiss') {
      // Mark tips as dismissed for today (just update lastTipShownDate)
      if (!userProfile.activityTracking) {
        userProfile.activityTracking = {}
      }
      userProfile.activityTracking.lastTipShownDate = new Date()
      await userProfile.save()

      return NextResponse.json({
        success: true,
        message: 'Tips dismissed for today'
      })
    }

    if (action === 'toggle') {
      // Toggle tips enabled/disabled
      if (!userProfile.retentionPreferences) {
        userProfile.retentionPreferences = {}
      }
      userProfile.retentionPreferences.dailyTipsEnabled =
        !userProfile.retentionPreferences.dailyTipsEnabled

      await userProfile.save()

      return NextResponse.json({
        success: true,
        enabled: userProfile.retentionPreferences.dailyTipsEnabled
      })
    }

    return NextResponse.json(
      { error: 'Invalid action' },
      { status: 400 }
    )

  } catch (error) {
    console.error('Daily tip POST error:', error)
    return NextResponse.json(
      { error: 'Failed to process tip action', details: error.message },
      { status: 500 }
    )
  }
}
