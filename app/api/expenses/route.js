import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import eventBus, { EVENTS } from '@/lib/eventBus'
import notificationService from '@/lib/notificationService'

// Canonical category mapping to unify voice + manual + budget keys
// All expense.category values will be normalized to these display names
// This ensures consistency between voice entry, manual entry, and budget categories
const CATEGORY_CANONICAL_MAP = {
  // Food & Dining (budget key: food_dining)
  'food': 'Food & Dining',
  'food & dining': 'Food & Dining',
  'Food & Dining': 'Food & Dining',
  'food_dining': 'Food & Dining',
  'food &dining': 'Food & Dining',
  'food and dining': 'Food & Dining',
  'food & dining ': 'Food & Dining',
  'food ': 'Food & Dining',
  'food&dining': 'Food & Dining',
  'food & dine': 'Food & Dining',
  'foodanddining': 'Food & Dining',
  'lunch': 'Food & Dining',
  'dinner': 'Food & Dining',
  'breakfast': 'Food & Dining',
  'snack': 'Food & Dining',
  'snacks': 'Food & Dining',
  'Food': 'Food & Dining',
  'dining': 'Food & Dining',
  'meal': 'Food & Dining',
  'restaurant': 'Food & Dining',
  'cafe': 'Food & Dining',

  // Transportation (budget key: transportation)
  'transport': 'Transportation',
  'transportation': 'Transportation',
  'Transportation': 'Transportation',
  'Transport': 'Transportation',
  'travel': 'Transportation',
  'Travel': 'Transportation',
  'metro': 'Transportation',
  'bus': 'Transportation',
  'uber': 'Transportation',
  'ola': 'Transportation',
  'taxi': 'Transportation',
  'cab': 'Transportation',
  'auto': 'Transportation',
  'rickshaw': 'Transportation',
  'petrol': 'Transportation',
  'fuel': 'Transportation',
  'parking': 'Transportation',
  'toll': 'Transportation',
  'rapido': 'Transportation',

  // Home & Utilities (budget key: home_utilities)
  'home': 'Home & Utilities',
  'home_utilities': 'Home & Utilities',
  'Home & Utilities': 'Home & Utilities',
  'utilities': 'Home & Utilities',
  'Home': 'Home & Utilities',
  'Utilities': 'Home & Utilities',
  'home & utilities': 'Home & Utilities',
  'housing': 'Home & Utilities',
  'Housing': 'Home & Utilities',
  'rent': 'Home & Utilities',
  'electricity': 'Home & Utilities',
  'water': 'Home & Utilities',
  'gas': 'Home & Utilities',
  'internet': 'Home & Utilities',
  'wifi': 'Home & Utilities',
  'bill': 'Home & Utilities',
  'bills': 'Home & Utilities',
  'maintenance': 'Home & Utilities',
  'recharge': 'Home & Utilities',

  // Entertainment (budget key: entertainment)
  'entertainment': 'Entertainment',
  'Entertainment': 'Entertainment',
  'movie': 'Entertainment',
  'movies': 'Entertainment',
  'cinema': 'Entertainment',
  'game': 'Entertainment',
  'games': 'Entertainment',
  'gaming': 'Entertainment',
  'netflix': 'Entertainment',
  'ott': 'Entertainment',
  'subscription': 'Entertainment',
  'gym': 'Entertainment',
  'party': 'Entertainment',
  'concert': 'Entertainment',
  'event': 'Entertainment',

  // Shopping (budget key: shopping)
  'shopping': 'Shopping',
  'Shopping': 'Shopping',
  'clothes': 'Shopping',
  'clothing': 'Shopping',
  'shoes': 'Shopping',
  'amazon': 'Shopping',
  'flipkart': 'Shopping',
  'myntra': 'Shopping',
  'mall': 'Shopping',
  'apparel': 'Shopping',
  'electronics': 'Shopping',
  'gadget': 'Shopping',
  'gadgets': 'Shopping',

  // Healthcare (budget key: healthcare)
  'healthcare': 'Healthcare',
  'Healthcare': 'Healthcare',
  'medical': 'Healthcare',
  'medicine': 'Healthcare',
  'medicines': 'Healthcare',
  'doctor': 'Healthcare',
  'hospital': 'Healthcare',
  'clinic': 'Healthcare',
  'pharmacy': 'Healthcare',
  'health': 'Healthcare',
  'checkup': 'Healthcare',

  // Savings (budget key: savings)
  'savings': 'Savings',
  'Savings': 'Savings',
  'saving': 'Savings',
  'Saving': 'Savings',
  'investment': 'Savings',
  'investments': 'Savings',
  'mutual fund': 'Savings',
  'fd': 'Savings',
  'rd': 'Savings',

  // Other / fallback
  'other': 'Other',
  'Other': 'Other',
  'misc': 'Other',
  'miscellaneous': 'Other'
}

function unifyCategory(raw) {
  if (!raw) return 'Other'
  const key = String(raw).trim().toLowerCase()
  return CATEGORY_CANONICAL_MAP[raw] || CATEGORY_CANONICAL_MAP[key] || CATEGORY_CANONICAL_MAP[key.replace(/\s+/g, ' ')] || 'Other'
}

// POST - Add new expense entry
export async function POST(request) {
  try {
    const session = await auth()

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const expenseData = await request.json()

    // Validate expense data
    if (!expenseData.amount || !expenseData.category) {
      return NextResponse.json(
        { error: 'Amount and category are required' },
        { status: 400 }
      )
    }

    await dbConnect()

    // Find user profile
    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile) {
      return NextResponse.json(
        { error: 'User profile not found' },
        { status: 404 }
      )
    }

    // Normalize category to canonical budget display name
    const unifiedCategory = unifyCategory(expenseData.category)

    // Create expense entry
    const expense = {
      id: Date.now().toString(), // Simple ID for now
      amount: Number(expenseData.amount),
      category: unifiedCategory,
      description: expenseData.description || '',
      merchant: expenseData.merchant || null,
      date: expenseData.date || new Date().toISOString().split('T')[0],
      timestamp: new Date(),
      entryMethod: expenseData.entryMethod || 'manual', // 'voice' or 'manual'
      originalText: expenseData.originalText || null, // For voice entries
      confidence: expenseData.confidence || null // For voice entries
    }

    // Initialize expenses array if it doesn't exist
    if (!userProfile.expenses) {
      userProfile.expenses = []
    }

    // Add expense to user profile
    userProfile.expenses.push(expense)

    // Update user profile
    userProfile.markModified('expenses')
    await userProfile.save()

    console.log('Expense added successfully:', expense)

    // Calculate category spending for notifications
    const currentMonthExpenses = userProfile.expenses
      .filter(e => e.date && e.date.startsWith(new Date().toISOString().slice(0, 7)))

    const monthlyTotal = currentMonthExpenses.reduce((sum, e) => sum + e.amount, 0)

    const categoryTotal = currentMonthExpenses
      .filter(e => unifyCategory(e.category) === unifiedCategory)
      .reduce((sum, e) => sum + e.amount, 0)

    // Get budget information if available
    let budgetAmount = null
    let categoryBudgetAmount = null

    try {
      if (userProfile.budget?.totalBudget) {
        budgetAmount = userProfile.budget.totalBudget

        // Find budget for this category
        // Bug fix: Handle both array and object formats for categories
        if (userProfile.budget.categories) {
          const categories = userProfile.budget.categories
          const categoriesArray = Array.isArray(categories)
            ? categories
            : Object.values(categories)

          const categoryBudget = categoriesArray.find(
            cat => cat?.name === unifiedCategory ||
                   cat?.category === unifiedCategory ||
                   cat?.englishName === unifiedCategory
          )
          if (categoryBudget) {
            categoryBudgetAmount = categoryBudget.amount
          }
        }
      }
    } catch (budgetError) {
      console.warn('⚠️ Could not fetch budget:', budgetError)
    }

    // 🤖 Emit event for AI Agents and Notifications
    try {
      eventBus.emit(EVENTS.EXPENSE_ADDED, {
        userId: session.user.id,
        amount: expense.amount,
        category: expense.category,
        description: expense.description,
        merchant: expense.merchant,
        date: expense.date,
        timestamp: expense.timestamp,
        entryMethod: expense.entryMethod,
        totalExpenses: userProfile.expenses.length,
        monthlyTotal: monthlyTotal,
        categoryTotal: categoryTotal,
        budgetAmount: budgetAmount,
        categoryBudgetAmount: categoryBudgetAmount
      })
      console.log('✅ EventBus: EXPENSE_ADDED event emitted with budget context')
    } catch (eventError) {
      console.error('⚠️ EventBus emit failed:', eventError)
      // Don't fail the request if event emission fails
    }

    // 🔔 Create smart notification if overspending detected
    try {
      if (categoryBudgetAmount && categoryTotal > 0) {
        const spentPercentage = (categoryTotal / categoryBudgetAmount) * 100

        // Critical notification if 95%+ spent
        if (spentPercentage >= 95) {
          await notificationService.create({
            userId: session.user.id,
            type: 'OVERSPENDING',
            priority: 'CRITICAL',
            category: 'SPENDING',
            title: `🚨 Critical: ${unifiedCategory} Budget Exceeded!`,
            message: `You've spent ₹${categoryTotal.toLocaleString('en-IN')} (${spentPercentage.toFixed(0)}%) of your ₹${categoryBudgetAmount.toLocaleString('en-IN')} budget. Consider reducing expenses in this category.`,
            actionLabel: 'View Budget',
            actionUrl: '/dashboard/budget'
          })
        }
        // Warning notification if 80-94% spent
        else if (spentPercentage >= 80) {
          await notificationService.create({
            userId: session.user.id,
            type: 'BUDGET_WARNING',
            priority: 'HIGH',
            category: 'SPENDING',
            title: `⚠️ ${unifiedCategory} Budget Alert`,
            message: `You've used ${spentPercentage.toFixed(0)}% of your ${unifiedCategory} budget (₹${categoryTotal.toLocaleString('en-IN')} of ₹${categoryBudgetAmount.toLocaleString('en-IN')}). Watch your spending!`,
            actionLabel: 'Review Expenses',
            actionUrl: '/dashboard/expenses'
          })
        }
      }
    } catch (notificationError) {
      console.error('⚠️ Notification creation failed:', notificationError)
      // Don't fail the request if notification fails
    }

    return NextResponse.json({
      success: true,
      message: 'Expense added successfully',
      expense: expense,
      totalExpenses: userProfile.expenses.length
    })

  } catch (error) {
    console.error('Add expense error:', error)
    return NextResponse.json(
      { error: 'Failed to add expense', details: error.message },
      { status: 500 }
    )
  }
}

// GET - Get user expenses
export async function GET(request) {
  try {
    const session = await auth()

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { searchParams } = new URL(request.url)
    const month = searchParams.get('month') // Format: YYYY-MM
    const category = searchParams.get('category')
    const limit = parseInt(searchParams.get('limit')) || 50

    await dbConnect()

    const userProfile = await UserProfile.findOne({ userId: session.user.id })

    if (!userProfile || !userProfile.expenses) {
      return NextResponse.json({
        success: true,
        expenses: [],
        totalExpenses: 0,
        monthlyTotal: 0
      })
    }

    let expenses = userProfile.expenses || []

    // Filter by month if specified
    if (month) {
      expenses = expenses.filter(expense => {
        // Bug fix: Add null check for expense.date
        if (!expense.date) return false
        const expenseMonth = expense.date.substring(0, 7) // Extract YYYY-MM
        return expenseMonth === month
      })
    }

    // Filter by category if specified
    if (category) {
      expenses = expenses.filter(expense => expense.category === category)
    }

    // Sort by date (newest first) and limit
    expenses = expenses
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit)

    // Calculate totals
    const monthlyTotal = expenses.reduce((sum, expense) => sum + expense.amount, 0)

    // Group expenses by normalized category for summary (legacy entries normalized on the fly)
    const categoryTotals = expenses.reduce((acc, expense) => {
      const unified = unifyCategory(expense.category)
      acc[unified] = (acc[unified] || 0) + expense.amount
      return acc
    }, {})

    // Also normalize categories within returned expense objects for consistency
    expenses = expenses.map(e => ({ ...e, category: unifyCategory(e.category) }))

    return NextResponse.json({
      success: true,
      expenses: expenses,
      totalExpenses: expenses.length,
      monthlyTotal: monthlyTotal,
      categoryTotals: categoryTotals,
      filters: {
        month: month,
        category: category,
        limit: limit
      }
    })

  } catch (error) {
    console.error('Get expenses error:', error)
    return NextResponse.json(
      { error: 'Failed to get expenses', details: error.message },
      { status: 500 }
    )
  }
}

// DELETE - Remove an expense by id
export async function DELETE(request) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
    }
    const { searchParams } = new URL(request.url)
    const id = searchParams.get('id')
    if (!id) {
      return NextResponse.json({ error: 'Expense id is required' }, { status: 400 })
    }
    await dbConnect()
    const userProfile = await UserProfile.findOne({ userId: session.user.id })
    if (!userProfile || !Array.isArray(userProfile.expenses)) {
      return NextResponse.json({ error: 'No expenses found' }, { status: 404 })
    }
    const before = userProfile.expenses.length
    userProfile.expenses = userProfile.expenses.filter(e => String(e.id) !== String(id))
    if (userProfile.expenses.length === before) {
      return NextResponse.json({ error: 'Expense not found' }, { status: 404 })
    }
    userProfile.markModified('expenses')
    await userProfile.save()
    return NextResponse.json({ success: true, message: 'Expense deleted', deletedId: id, totalExpenses: userProfile.expenses.length })
  } catch (error) {
    console.error('Delete expense error:', error)
    return NextResponse.json({ error: 'Failed to delete expense', details: error.message }, { status: 500 })
  }
}
