import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'

/**
 * GET /api/retention/daily-pulse
 * Get today's pulse status and weekly summary
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

    const today = new Date().toISOString().split('T')[0]
    const pulseHistory = userProfile.activityTracking?.dailyPulseHistory || []

    // Check if already checked in today
    const todaysPulse = pulseHistory.find(p =>
      new Date(p.date).toISOString().split('T')[0] === today
    )

    // Get this week's data
    const now = new Date()
    const weekStart = new Date(now)
    weekStart.setDate(now.getDate() - 6)
    weekStart.setHours(0, 0, 0, 0)

    const weekPulses = pulseHistory.filter(p =>
      new Date(p.date) >= weekStart
    )

    // Calculate weekly stats from expenses
    const expenses = userProfile.expenses || []
    const weekExpenses = expenses.filter(e => {
      const expDate = new Date(e.date)
      return expDate >= weekStart
    })

    const weeklySpent = weekExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const daysTracked = weekPulses.length

    return NextResponse.json({
      success: true,
      checkedInToday: !!todaysPulse,
      todaysPulse: todaysPulse ? {
        mood: todaysPulse.mood,
        estimatedSpend: todaysPulse.estimatedSpend
      } : null,
      weekSummary: {
        totalSpent: weeklySpent,
        daysTracked,
        pulses: weekPulses.map(p => ({
          date: p.date,
          mood: p.mood,
          estimatedSpend: p.estimatedSpend
        }))
      },
      enabled: userProfile.retentionPreferences?.dailyPulseEnabled !== false
    })

  } catch (error) {
    console.error('Daily pulse GET error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch daily pulse', details: error.message },
      { status: 500 }
    )
  }
}

/**
 * POST /api/retention/daily-pulse
 * Record today's pulse check-in
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
    const { mood, estimatedSpend } = body

    if (!mood || !['great', 'good', 'okay', 'tough'].includes(mood)) {
      return NextResponse.json(
        { error: 'Invalid mood value' },
        { status: 400 }
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

    // Initialize activity tracking if needed
    if (!userProfile.activityTracking) {
      userProfile.activityTracking = {}
    }
    if (!userProfile.activityTracking.dailyPulseHistory) {
      userProfile.activityTracking.dailyPulseHistory = []
    }

    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const todayStr = today.toISOString().split('T')[0]

    // Check if already checked in today
    const existingIndex = userProfile.activityTracking.dailyPulseHistory.findIndex(p =>
      new Date(p.date).toISOString().split('T')[0] === todayStr
    )

    const pulseEntry = {
      date: today,
      mood,
      estimatedSpend: estimatedSpend || 0
    }

    if (existingIndex !== -1) {
      // Update existing
      userProfile.activityTracking.dailyPulseHistory[existingIndex] = pulseEntry
    } else {
      // Add new
      userProfile.activityTracking.dailyPulseHistory.push(pulseEntry)
    }

    // Keep only last 90 days
    if (userProfile.activityTracking.dailyPulseHistory.length > 90) {
      userProfile.activityTracking.dailyPulseHistory =
        userProfile.activityTracking.dailyPulseHistory.slice(-90)
    }

    // Update last active date
    userProfile.activityTracking.lastActiveDate = new Date()

    await userProfile.save()

    // Get encouraging message based on mood
    const messages = {
      great: "Excellent! A no-spend day builds wealth fast.",
      good: "Nice! Keeping expenses low is the key to saving.",
      okay: "Moderate spending - you're doing fine!",
      tough: "Every day is a fresh start. Tomorrow will be better!"
    }

    return NextResponse.json({
      success: true,
      message: messages[mood],
      pulse: pulseEntry
    })

  } catch (error) {
    console.error('Daily pulse POST error:', error)
    return NextResponse.json(
      { error: 'Failed to record daily pulse', details: error.message },
      { status: 500 }
    )
  }
}
