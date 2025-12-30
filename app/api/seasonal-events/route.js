import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { getUpcomingEvents, estimateEventExpense } from '@/lib/indianFinancialCalendar'
import { seasonalPlanner } from '@/lib/seasonalPlanner'

// GET - Get user's seasonal events and calendar events
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

    // Get months parameter (default 12)
    const { searchParams } = new URL(request.url)
    const months = parseInt(searchParams.get('months')) || 12

    if (!userProfile) {
      // Return calendar events with defaults if no profile exists yet
      const defaultIncome = 50000
      const defaultFamilySize = 1
      const defaultCalendarEvents = getUpcomingEvents(months, new Date()).map(e => ({
        ...e,
        estimatedCost: estimateEventExpense(e.id, { monthlyIncome: defaultIncome, familySize: defaultFamilySize }),
        source: 'calendar'
      }))

      return NextResponse.json({
        success: true,
        userEvents: [],
        calendarEvents: defaultCalendarEvents,
        allEvents: defaultCalendarEvents,
        savingsData: seasonalPlanner.calculateMonthlySavingsRequired(defaultCalendarEvents, 50000, new Date()),
        preferences: {},
        userProfile: {
          monthlyIncome: 50000,
          familySize: 1,
          city: '',
          seasonalPlanningPreferences: {}
        }
      })
    }

    // Get user's custom events
    const userEvents = userProfile.seasonalEvents || []

    // Get calendar events - pass userProfile object for proper expense calculation
    const calendarEvents = getUpcomingEvents(months, new Date())
      .map(e => ({
        ...e,
        estimatedCost: estimateEventExpense(e.id, {
          monthlyIncome: userProfile.monthlyIncome,
          familySize: userProfile.familySize
        }),
        source: 'calendar'
      }))

    // Calculate savings data
    const allEvents = [
      ...calendarEvents,
      ...userEvents.filter(e => e.enabled !== false).map(e => ({
        ...e,
        source: 'user'
      }))
    ]

    const savingsData = seasonalPlanner.calculateMonthlySavingsRequired(
      allEvents,
      userProfile.monthlyIncome,
      new Date()
    )

    return NextResponse.json({
      success: true,
      userEvents,
      calendarEvents,
      allEvents,
      savingsData,
      preferences: userProfile.seasonalPlanningPreferences || {},
      userProfile: {
        monthlyIncome: userProfile.monthlyIncome || 50000,
        familySize: userProfile.familySize || 1,
        city: userProfile.city || '',
        seasonalPlanningPreferences: userProfile.seasonalPlanningPreferences || {}
      }
    })

  } catch (error) {
    console.error('Get seasonal events error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch seasonal events' },
      { status: 500 }
    )
  }
}

// POST - Add new custom event
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
    const { name, category, date, amount, description, recurrence, priority, enabled } = body

    // Validate required fields
    if (!name || !date || !amount) {
      return NextResponse.json(
        { error: 'Name, date, and amount are required' },
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

    // Create new event
    const newEvent = {
      name: name.trim(),
      category: category || 'custom',
      date: new Date(date),
      amount: parseFloat(amount),
      description: description?.trim() || '',
      recurrence: recurrence || 'once',
      priority: priority || 2,
      enabled: enabled !== false,
      createdAt: new Date()
    }

    // Add to user's seasonal events
    if (!userProfile.seasonalEvents) {
      userProfile.seasonalEvents = []
    }
    userProfile.seasonalEvents.push(newEvent)

    await userProfile.save()

    // Get the saved event with _id
    const savedEvent = userProfile.seasonalEvents[userProfile.seasonalEvents.length - 1]

    return NextResponse.json({
      success: true,
      event: savedEvent,
      message: 'Event added successfully'
    })

  } catch (error) {
    console.error('Add seasonal event error:', error)
    return NextResponse.json(
      { error: 'Failed to add event' },
      { status: 500 }
    )
  }
}

// PUT - Update existing event
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
    const { _id, name, category, date, amount, description, recurrence, priority, enabled } = body

    if (!_id) {
      return NextResponse.json(
        { error: 'Event ID is required' },
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

    // Find and update the event
    const eventIndex = userProfile.seasonalEvents?.findIndex(
      e => e._id.toString() === _id
    )

    if (eventIndex === -1) {
      return NextResponse.json(
        { error: 'Event not found' },
        { status: 404 }
      )
    }

    // Update event fields
    const event = userProfile.seasonalEvents[eventIndex]
    if (name) event.name = name.trim()
    if (category) event.category = category
    if (date) event.date = new Date(date)
    if (amount !== undefined) event.amount = parseFloat(amount)
    if (description !== undefined) event.description = description.trim()
    if (recurrence) event.recurrence = recurrence
    if (priority !== undefined) event.priority = priority
    if (enabled !== undefined) event.enabled = enabled
    event.updatedAt = new Date()

    await userProfile.save()

    return NextResponse.json({
      success: true,
      event: userProfile.seasonalEvents[eventIndex],
      message: 'Event updated successfully'
    })

  } catch (error) {
    console.error('Update seasonal event error:', error)
    return NextResponse.json(
      { error: 'Failed to update event' },
      { status: 500 }
    )
  }
}

// DELETE - Delete event
export async function DELETE(request) {
  try {
    const session = await auth()

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { searchParams } = new URL(request.url)
    const eventId = searchParams.get('id')

    if (!eventId) {
      return NextResponse.json(
        { error: 'Event ID is required' },
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

    // Remove the event
    const initialLength = userProfile.seasonalEvents?.length || 0
    userProfile.seasonalEvents = userProfile.seasonalEvents?.filter(
      e => e._id.toString() !== eventId
    ) || []

    if (userProfile.seasonalEvents.length === initialLength) {
      return NextResponse.json(
        { error: 'Event not found' },
        { status: 404 }
      )
    }

    await userProfile.save()

    return NextResponse.json({
      success: true,
      message: 'Event deleted successfully'
    })

  } catch (error) {
    console.error('Delete seasonal event error:', error)
    return NextResponse.json(
      { error: 'Failed to delete event' },
      { status: 500 }
    )
  }
}
