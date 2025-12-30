import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'

// Frequency multipliers for monthly normalization
const FREQUENCY_MULTIPLIERS = {
  weekly: 4.33,
  'bi-weekly': 2.17,
  monthly: 1,
  quarterly: 0.33,
  annually: 0.083,
  irregular: 1
}

// Normalize amount to monthly
function normalizeToMonthly(amount, frequency) {
  return Math.round(amount * (FREQUENCY_MULTIPLIERS[frequency] || 1))
}

// Calculate totals from income sources
function calculateIncomeTotals(sources) {
  let totalMonthly = 0
  let stableMonthly = 0

  sources.forEach(source => {
    if (!source.includeInBudget) return
    const monthlyAmount = normalizeToMonthly(source.amount, source.frequency)
    totalMonthly += monthlyAmount
    if (source.isStable) {
      stableMonthly += monthlyAmount
    }
  })

  const variableMonthly = totalMonthly - stableMonthly
  const stabilityRatio = totalMonthly > 0 ? Math.round((stableMonthly / totalMonthly) * 100) : 100

  return {
    totalMonthly,
    stableMonthly,
    variableMonthly,
    stabilityRatio
  }
}

// GET - Get user's income sources
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

    const incomeSources = userProfile.incomeSources || []
    const totals = calculateIncomeTotals(incomeSources)

    return NextResponse.json({
      incomeSources,
      totals,
      // Legacy field for backward compatibility
      monthlyIncome: userProfile.monthlyIncome
    })

  } catch (error) {
    console.error('Get income sources error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch income sources' },
      { status: 500 }
    )
  }
}

// POST - Add new income source
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
    const { name, type, amount, frequency, isStable, includeInBudget, description } = body

    // Validate required fields
    if (!name || !amount) {
      return NextResponse.json(
        { error: 'Name and amount are required' },
        { status: 400 }
      )
    }

    if (parseFloat(amount) < 0) {
      return NextResponse.json(
        { error: 'Amount cannot be negative' },
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

    // Create new income source
    const newSource = {
      name: name.trim(),
      type: type || 'other',
      amount: parseFloat(amount),
      frequency: frequency || 'monthly',
      isStable: isStable !== false,
      includeInBudget: includeInBudget !== false,
      description: description?.trim() || '',
      createdAt: new Date()
    }

    // Add to user's income sources
    if (!userProfile.incomeSources) {
      userProfile.incomeSources = []
    }
    userProfile.incomeSources.push(newSource)

    // Update legacy monthlyIncome field
    const totals = calculateIncomeTotals(userProfile.incomeSources)
    userProfile.monthlyIncome = totals.totalMonthly

    // Update primary income source type
    const primarySource = userProfile.incomeSources.reduce((primary, source) => {
      const normalizedAmount = normalizeToMonthly(source.amount, source.frequency)
      return normalizedAmount > (primary?.normalizedAmount || 0)
        ? { ...source, normalizedAmount }
        : primary
    }, null)
    if (primarySource) {
      userProfile.incomeSource = primarySource.type
    }

    await userProfile.save()

    // Get the saved source with _id
    const savedSource = userProfile.incomeSources[userProfile.incomeSources.length - 1]

    return NextResponse.json({
      success: true,
      source: savedSource,
      totals: calculateIncomeTotals(userProfile.incomeSources),
      message: 'Income source added successfully'
    })

  } catch (error) {
    console.error('Add income source error:', error)
    return NextResponse.json(
      { error: 'Failed to add income source' },
      { status: 500 }
    )
  }
}

// PUT - Update existing income source
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
    const { _id, name, type, amount, frequency, isStable, includeInBudget, description } = body

    if (!_id) {
      return NextResponse.json(
        { error: 'Income source ID is required' },
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

    // Find and update the income source
    const sourceIndex = userProfile.incomeSources?.findIndex(
      s => s._id.toString() === _id
    )

    if (sourceIndex === -1) {
      return NextResponse.json(
        { error: 'Income source not found' },
        { status: 404 }
      )
    }

    // Update source fields
    const source = userProfile.incomeSources[sourceIndex]
    if (name) source.name = name.trim()
    if (type) source.type = type
    if (amount !== undefined) source.amount = parseFloat(amount)
    if (frequency) source.frequency = frequency
    if (isStable !== undefined) source.isStable = isStable
    if (includeInBudget !== undefined) source.includeInBudget = includeInBudget
    if (description !== undefined) source.description = description.trim()
    source.updatedAt = new Date()

    // Update legacy monthlyIncome field
    const totals = calculateIncomeTotals(userProfile.incomeSources)
    userProfile.monthlyIncome = totals.totalMonthly

    // Update primary income source type
    const primarySource = userProfile.incomeSources.reduce((primary, s) => {
      const normalizedAmount = normalizeToMonthly(s.amount, s.frequency)
      return normalizedAmount > (primary?.normalizedAmount || 0)
        ? { ...s, normalizedAmount }
        : primary
    }, null)
    if (primarySource) {
      userProfile.incomeSource = primarySource.type
    }

    await userProfile.save()

    return NextResponse.json({
      success: true,
      source: userProfile.incomeSources[sourceIndex],
      totals,
      message: 'Income source updated successfully'
    })

  } catch (error) {
    console.error('Update income source error:', error)
    return NextResponse.json(
      { error: 'Failed to update income source' },
      { status: 500 }
    )
  }
}

// DELETE - Delete income source
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
    const sourceId = searchParams.get('id')

    if (!sourceId) {
      return NextResponse.json(
        { error: 'Income source ID is required' },
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

    // Don't allow deleting the last income source
    if (userProfile.incomeSources?.length <= 1) {
      return NextResponse.json(
        { error: 'Cannot delete the last income source' },
        { status: 400 }
      )
    }

    // Remove the income source
    const initialLength = userProfile.incomeSources?.length || 0
    userProfile.incomeSources = userProfile.incomeSources?.filter(
      s => s._id.toString() !== sourceId
    ) || []

    if (userProfile.incomeSources.length === initialLength) {
      return NextResponse.json(
        { error: 'Income source not found' },
        { status: 404 }
      )
    }

    // Update legacy monthlyIncome field
    const totals = calculateIncomeTotals(userProfile.incomeSources)
    userProfile.monthlyIncome = totals.totalMonthly

    // Update primary income source type
    const primarySource = userProfile.incomeSources.reduce((primary, s) => {
      const normalizedAmount = normalizeToMonthly(s.amount, s.frequency)
      return normalizedAmount > (primary?.normalizedAmount || 0)
        ? { ...s, normalizedAmount }
        : primary
    }, null)
    if (primarySource) {
      userProfile.incomeSource = primarySource.type
    }

    await userProfile.save()

    return NextResponse.json({
      success: true,
      totals,
      message: 'Income source deleted successfully'
    })

  } catch (error) {
    console.error('Delete income source error:', error)
    return NextResponse.json(
      { error: 'Failed to delete income source' },
      { status: 500 }
    )
  }
}
