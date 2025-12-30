import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { emailService } from '@/lib/emailService'

// POST - Send emergency email alert
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
    const { alertType, data } = body

    if (!alertType || !data) {
      return NextResponse.json(
        { error: 'Alert type and data are required' },
        { status: 400 }
      )
    }

    // Add user info to data
    const user = {
      email: session.user.email,
      name: session.user.name,
      ...data.user
    }

    let result = null

    switch (alertType) {
      case 'low_balance':
        result = await emailService.sendLowBalanceAlert({
          user,
          currentBalance: data.currentBalance,
          threshold: data.threshold,
          accountName: data.accountName
        })
        break

      case 'budget_exceeded':
        result = await emailService.sendBudgetExceededAlert({
          user,
          categoryName: data.categoryName,
          budgetAmount: data.budgetAmount,
          spentAmount: data.spentAmount,
          percentage: data.percentage
        })
        break

      case 'unusual_expense':
        result = await emailService.sendUnusualExpenseAlert({
          user,
          expenseAmount: data.expenseAmount,
          categoryName: data.categoryName,
          averageAmount: data.averageAmount,
          multiplier: data.multiplier
        })
        break

      case 'emi_risk':
        result = await emailService.sendEMIRiskAlert({
          user,
          emiAmount: data.emiAmount,
          emiName: data.emiName,
          dueDate: data.dueDate,
          currentBalance: data.currentBalance
        })
        break

      default:
        return NextResponse.json(
          { error: 'Unknown alert type' },
          { status: 400 }
        )
    }

    return NextResponse.json({
      success: true,
      message: 'Emergency email sent successfully',
      result
    })

  } catch (error) {
    console.error('Send emergency email error:', error)
    return NextResponse.json(
      { error: 'Failed to send emergency email' },
      { status: 500 }
    )
  }
}
