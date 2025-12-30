import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { retentionEngine, ACHIEVEMENTS } from '@/lib/retentionEngine'

/**
 * GET /api/retention/achievements
 * Returns all achievements with unlock status and progress
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

    // Get all achievements with status
    const achievements = retentionEngine.getAllAchievements(userProfile)

    // Group by category
    const grouped = {
      tracking: achievements.filter(a => a.category === 'tracking'),
      savings: achievements.filter(a => a.category === 'savings'),
      budget: achievements.filter(a => a.category === 'budget'),
      goals: achievements.filter(a => a.category === 'goals')
    }

    // Stats
    const unlockedCount = achievements.filter(a => a.isUnlocked).length
    const totalPoints = achievements
      .filter(a => a.isUnlocked)
      .reduce((sum, a) => sum + (a.points || 0), 0)

    // Get uncelebrated achievements
    const uncelebrated = achievements.filter(a => a.isUnlocked && !a.celebrated)

    return NextResponse.json({
      success: true,
      achievements: grouped,
      allAchievements: achievements,
      stats: {
        unlocked: unlockedCount,
        total: achievements.length,
        points: totalPoints,
        percentComplete: Math.round((unlockedCount / achievements.length) * 100)
      },
      uncelebrated
    })

  } catch (error) {
    console.error('Achievements API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch achievements', details: error.message },
      { status: 500 }
    )
  }
}

/**
 * POST /api/retention/achievements
 * Mark achievement as celebrated or trigger check for new achievements
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
    const { action, achievementId } = body

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    if (action === 'celebrate' && achievementId) {
      // Mark achievement as celebrated
      const unlocked = userProfile.achievements?.unlocked || []
      const index = unlocked.findIndex(a => a.id === achievementId)

      if (index !== -1) {
        unlocked[index].celebrated = true
        userProfile.achievements.unlocked = unlocked
        await userProfile.save()

        return NextResponse.json({
          success: true,
          message: 'Achievement celebrated'
        })
      }
    }

    if (action === 'check') {
      // Check for new achievements
      const newAchievements = retentionEngine.calculateNewAchievements(userProfile)

      if (newAchievements.length > 0) {
        // Initialize achievements if needed
        if (!userProfile.achievements) {
          userProfile.achievements = { unlocked: [], progress: {} }
        }
        if (!userProfile.achievements.unlocked) {
          userProfile.achievements.unlocked = []
        }

        // Add new achievements
        newAchievements.forEach(achievement => {
          userProfile.achievements.unlocked.push({
            id: achievement.id,
            unlockedAt: new Date(),
            celebrated: false
          })
        })

        userProfile.achievements.lastChecked = new Date()
        await userProfile.save()

        return NextResponse.json({
          success: true,
          newAchievements: newAchievements.map(a => ({
            id: a.id,
            name: a.name,
            description: a.description,
            emoji: a.emoji,
            points: a.points
          }))
        })
      }

      return NextResponse.json({
        success: true,
        newAchievements: []
      })
    }

    return NextResponse.json(
      { error: 'Invalid action' },
      { status: 400 }
    )

  } catch (error) {
    console.error('Achievements POST error:', error)
    return NextResponse.json(
      { error: 'Failed to process achievement action', details: error.message },
      { status: 500 }
    )
  }
}
