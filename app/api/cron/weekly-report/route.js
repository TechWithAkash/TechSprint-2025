import { NextResponse } from 'next/server'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import User from '@/models/User'
import { retentionEngine } from '@/lib/retentionEngine'
import { generateWeeklyReportEmail } from '@/lib/emailTemplates/weeklyReport'
import { sendEmail } from '@/lib/emailService'

/**
 * GET /api/cron/weekly-report
 *
 * Cron endpoint to send weekly email reports to all users
 * Configure in vercel.json:
 * {
 *   "crons": [{
 *     "path": "/api/cron/weekly-report",
 *     "schedule": "0 9 * * 0"  // Every Sunday at 9 AM
 *   }]
 * }
 */
export async function GET(request) {
  try {
    // Verify cron secret for security (optional but recommended)
    const authHeader = request.headers.get('authorization')
    const cronSecret = process.env.CRON_SECRET

    // In production, verify the cron secret
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      // Allow in development or if no secret is set
      if (process.env.NODE_ENV === 'production') {
        return NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        )
      }
    }

    await dbConnect()

    // Get all users who have weekly reports enabled
    const userProfiles = await UserProfile.find({
      onboardingCompleted: true,
      'budgetPreferences.weeklyReports': { $ne: false },
      'retentionPreferences.weeklyEmailEnabled': { $ne: false }
    }).limit(100) // Process in batches

    const results = {
      total: userProfiles.length,
      sent: 0,
      skipped: 0,
      errors: []
    }

    for (const profile of userProfiles) {
      try {
        // Get user email
        const user = await User.findById(profile.userId)
        if (!user?.email) {
          results.skipped++
          continue
        }

        // Check if report was already sent this week
        const lastReportSent = profile.activityTracking?.weeklyReportsSent?.slice(-1)[0]
        if (lastReportSent) {
          const daysSinceLastReport = (new Date() - new Date(lastReportSent)) / (1000 * 60 * 60 * 24)
          if (daysSinceLastReport < 6) {
            results.skipped++
            continue
          }
        }

        // Build weekly report data
        const reportData = retentionEngine.buildWeeklyReport({
          expenses: profile.expenses || [],
          budget: profile.generatedBudget,
          goals: profile.goals || [],
          profile: {
            monthlyIncome: profile.monthlyIncome
          }
        })

        // Generate email
        const emailContent = generateWeeklyReportEmail({
          userName: user.name || profile.name || 'there',
          period: reportData.period,
          summary: reportData.summary,
          topCategories: reportData.topCategories,
          highlights: reportData.highlights,
          tipOfWeek: reportData.tipOfWeek,
          dashboardUrl: process.env.NEXT_PUBLIC_APP_URL || 'https://mywealthwise.tech/dashboard'
        })

        // Send email
        await sendEmail({
          to: user.email,
          subject: emailContent.subject,
          html: emailContent.html,
          text: emailContent.text
        })

        // Record that report was sent
        if (!profile.activityTracking) {
          profile.activityTracking = {}
        }
        if (!profile.activityTracking.weeklyReportsSent) {
          profile.activityTracking.weeklyReportsSent = []
        }
        profile.activityTracking.weeklyReportsSent.push(new Date())

        // Keep only last 12 weeks
        if (profile.activityTracking.weeklyReportsSent.length > 12) {
          profile.activityTracking.weeklyReportsSent =
            profile.activityTracking.weeklyReportsSent.slice(-12)
        }

        await profile.save()
        results.sent++

      } catch (error) {
        console.error(`Failed to send report to user ${profile.userId}:`, error)
        results.errors.push({
          userId: profile.userId.toString(),
          error: error.message
        })
      }
    }

    return NextResponse.json({
      success: true,
      message: `Weekly reports processed`,
      results
    })

  } catch (error) {
    console.error('Weekly report cron error:', error)
    return NextResponse.json(
      { error: 'Failed to process weekly reports', details: error.message },
      { status: 500 }
    )
  }
}

/**
 * POST /api/cron/weekly-report
 *
 * Manual trigger for testing - sends report to a specific user
 */
export async function POST(request) {
  try {
    const body = await request.json()
    const { userId, email } = body

    if (!userId && !email) {
      return NextResponse.json(
        { error: 'userId or email required' },
        { status: 400 }
      )
    }

    await dbConnect()

    // Find user profile
    let profile
    let user

    if (userId) {
      profile = await UserProfile.findOne({ userId })
      user = await User.findById(userId)
    } else if (email) {
      user = await User.findOne({ email })
      if (user) {
        profile = await UserProfile.findOne({ userId: user._id })
      }
    }

    if (!profile || !user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // Build weekly report data
    const reportData = retentionEngine.buildWeeklyReport({
      expenses: profile.expenses || [],
      budget: profile.generatedBudget,
      goals: profile.goals || [],
      profile: {
        monthlyIncome: profile.monthlyIncome
      }
    })

    // Generate email
    const emailContent = generateWeeklyReportEmail({
      userName: user.name || profile.name || 'there',
      period: reportData.period,
      summary: reportData.summary,
      topCategories: reportData.topCategories,
      highlights: reportData.highlights,
      tipOfWeek: reportData.tipOfWeek,
      dashboardUrl: process.env.NEXT_PUBLIC_APP_URL || 'https://mywealthwise.tech/dashboard'
    })

    // Send email
    await sendEmail({
      to: user.email,
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text
    })

    return NextResponse.json({
      success: true,
      message: `Weekly report sent to ${user.email}`,
      preview: {
        subject: emailContent.subject,
        summary: reportData.summary
      }
    })

  } catch (error) {
    console.error('Manual weekly report error:', error)
    return NextResponse.json(
      { error: 'Failed to send weekly report', details: error.message },
      { status: 500 }
    )
  }
}
