/**
 * WealthWise Retention Engine
 *
 * Core logic for:
 * - Achievement tracking and unlocking
 * - Daily personalized tips
 * - Weekly report generation
 * - Smart nudge detection
 */

// ============================================
// ACHIEVEMENT DEFINITIONS
// ============================================

export const ACHIEVEMENTS = {
  // Tracking Achievements
  first_expense: {
    id: 'first_expense',
    name: 'First Step',
    description: 'Add your first expense',
    icon: 'Sprout',
    emoji: '🌱',
    category: 'tracking',
    criteria: { expenseCount: 1 },
    points: 10
  },
  consistent_tracker: {
    id: 'consistent_tracker',
    name: 'Consistent',
    description: 'Log 7 expenses',
    icon: 'ClipboardList',
    emoji: '📝',
    category: 'tracking',
    criteria: { expenseCount: 7 },
    points: 25
  },
  dedicated_tracker: {
    id: 'dedicated_tracker',
    name: 'Dedicated',
    description: 'Log 30 expenses',
    icon: 'Target',
    emoji: '🎯',
    category: 'tracking',
    criteria: { expenseCount: 30 },
    points: 50
  },
  expense_pro: {
    id: 'expense_pro',
    name: 'Expense Pro',
    description: 'Log 100 expenses',
    icon: 'Trophy',
    emoji: '🏆',
    category: 'tracking',
    criteria: { expenseCount: 100 },
    points: 100
  },
  voice_master: {
    id: 'voice_master',
    name: 'Voice Master',
    description: 'Add 10 expenses using voice',
    icon: 'Mic',
    emoji: '🎤',
    category: 'tracking',
    criteria: { voiceEntryCount: 10 },
    points: 30
  },

  // Savings Achievements
  saver_starter: {
    id: 'saver_starter',
    name: 'Saver Starter',
    description: 'Save your first ₹1,000',
    icon: 'Coins',
    emoji: '💰',
    category: 'savings',
    criteria: { totalSaved: 1000 },
    points: 20
  },
  piggy_builder: {
    id: 'piggy_builder',
    name: 'Piggy Builder',
    description: 'Save ₹10,000',
    icon: 'PiggyBank',
    emoji: '🐷',
    category: 'savings',
    criteria: { totalSaved: 10000 },
    points: 50
  },
  wealth_builder: {
    id: 'wealth_builder',
    name: 'Wealth Builder',
    description: 'Save ₹1,00,000',
    icon: 'Gem',
    emoji: '💎',
    category: 'savings',
    criteria: { totalSaved: 100000 },
    points: 200
  },
  rate_master: {
    id: 'rate_master',
    name: 'Rate Master',
    description: '20%+ savings rate for a month',
    icon: 'TrendingUp',
    emoji: '📈',
    category: 'savings',
    criteria: { monthsWith20PercentSavings: 1 },
    points: 75
  },

  // Budget Achievements
  budget_keeper: {
    id: 'budget_keeper',
    name: 'Budget Keeper',
    description: 'Stay under budget for 7 days',
    icon: 'CheckCircle',
    emoji: '✅',
    category: 'budget',
    criteria: { consecutiveDaysUnderBudget: 7 },
    points: 40
  },
  budget_guardian: {
    id: 'budget_guardian',
    name: 'Budget Guardian',
    description: 'Stay under budget for a full month',
    icon: 'Shield',
    emoji: '🛡️',
    category: 'budget',
    criteria: { monthsUnderBudget: 1 },
    points: 100
  },
  category_champ: {
    id: 'category_champ',
    name: 'Category Champ',
    description: 'Keep one category under budget all month',
    icon: 'Zap',
    emoji: '⚡',
    category: 'budget',
    criteria: { categoriesUnderBudgetThisMonth: 1 },
    points: 35
  },

  // Goal Achievements
  goal_setter: {
    id: 'goal_setter',
    name: 'Goal Setter',
    description: 'Create your first savings goal',
    icon: 'Target',
    emoji: '🎯',
    category: 'goals',
    criteria: { goalsCreated: 1 },
    points: 15
  },
  halfway_there: {
    id: 'halfway_there',
    name: 'Halfway There',
    description: 'Reach 50% on any goal',
    icon: 'Rocket',
    emoji: '🚀',
    category: 'goals',
    criteria: { goalsMilestoneReached: '50' },
    points: 50
  },
  goal_crusher: {
    id: 'goal_crusher',
    name: 'Goal Crusher',
    description: 'Complete any savings goal',
    icon: 'Flag',
    emoji: '🏁',
    category: 'goals',
    criteria: { goalsCompleted: 1 },
    points: 100
  }
}

// ============================================
// DAILY TIP TEMPLATES
// ============================================

const GENERAL_TIPS = [
  {
    id: 'tip_24hr_rule',
    category: 'wisdom',
    title: 'The 24-Hour Rule',
    template: 'Before making any purchase over ₹1,000, wait 24 hours. This simple habit prevents impulse buys and can save you thousands each month.'
  },
  {
    id: 'tip_50_30_20',
    category: 'wisdom',
    title: 'The 50-30-20 Rule',
    template: 'Try allocating 50% of income to needs, 30% to wants, and 20% to savings. It\'s a simple framework that works for most people.'
  },
  {
    id: 'tip_emergency_fund',
    category: 'wisdom',
    title: 'Emergency Fund Priority',
    template: 'Financial experts recommend having 3-6 months of expenses saved before investing. It\'s your financial safety net.'
  },
  {
    id: 'tip_automation',
    category: 'wisdom',
    title: 'Automate Your Savings',
    template: 'Set up automatic transfers to savings on payday. What you don\'t see, you won\'t spend.'
  },
  {
    id: 'tip_small_changes',
    category: 'wisdom',
    title: 'Small Changes Add Up',
    template: 'Saving just ₹100/day = ₹36,500/year. Small, consistent changes create big results over time.'
  },
  {
    id: 'tip_subscription_audit',
    category: 'wisdom',
    title: 'Subscription Audit',
    template: 'Review your subscriptions quarterly. The average person has 2-3 unused subscriptions costing ₹500-1,000/month.'
  },
  {
    id: 'tip_cash_diet',
    category: 'wisdom',
    title: 'Try a Cash Diet',
    template: 'For discretionary spending, try using only cash for a week. Physical money makes spending feel more real.'
  },
  {
    id: 'tip_meal_prep',
    category: 'wisdom',
    title: 'Meal Prep Saves Money',
    template: 'Preparing meals at home for just 2 more days a week can save ₹3,000-5,000 monthly compared to ordering in.'
  }
]

// ============================================
// RETENTION ENGINE CLASS
// ============================================

class RetentionEngine {

  /**
   * Calculate which achievements should be unlocked based on user progress
   * @param {Object} userProfile - User profile with achievements.progress
   * @returns {Array} - Newly unlocked achievements
   */
  calculateNewAchievements(userProfile) {
    const progress = userProfile.achievements?.progress || {}
    const alreadyUnlocked = (userProfile.achievements?.unlocked || []).map(a => a.id)
    const newlyUnlocked = []

    for (const [id, achievement] of Object.entries(ACHIEVEMENTS)) {
      // Skip if already unlocked
      if (alreadyUnlocked.includes(id)) continue

      // Check criteria
      const criteria = achievement.criteria
      let isUnlocked = true

      for (const [key, requiredValue] of Object.entries(criteria)) {
        const currentValue = progress[key]

        // Special handling for array-based criteria (like goalsMilestoneReached)
        if (key === 'goalsMilestoneReached') {
          isUnlocked = Array.isArray(currentValue) &&
            currentValue.some(m => m.includes(`:${requiredValue}`))
        } else if (key === 'categoriesUnderBudgetThisMonth') {
          isUnlocked = Array.isArray(currentValue) && currentValue.length >= requiredValue
        } else {
          isUnlocked = (currentValue || 0) >= requiredValue
        }

        if (!isUnlocked) break
      }

      if (isUnlocked) {
        newlyUnlocked.push({
          ...achievement,
          unlockedAt: new Date()
        })
      }
    }

    return newlyUnlocked
  }

  /**
   * Get all achievements with unlock status and progress
   * @param {Object} userProfile - User profile
   * @returns {Array} - All achievements with status
   */
  getAllAchievements(userProfile) {
    const progress = userProfile.achievements?.progress || {}
    const unlockedMap = new Map(
      (userProfile.achievements?.unlocked || []).map(a => [a.id, a])
    )

    return Object.values(ACHIEVEMENTS).map(achievement => {
      const unlocked = unlockedMap.get(achievement.id)

      // Calculate progress percentage
      let progressPercent = 0
      const criteria = Object.entries(achievement.criteria)[0]

      if (criteria) {
        const [key, target] = criteria
        if (key === 'goalsMilestoneReached' || key === 'categoriesUnderBudgetThisMonth') {
          const arr = progress[key] || []
          progressPercent = arr.length > 0 ? 100 : 0
        } else {
          const current = progress[key] || 0
          progressPercent = Math.min(100, Math.round((current / target) * 100))
        }
      }

      return {
        ...achievement,
        isUnlocked: !!unlocked,
        unlockedAt: unlocked?.unlockedAt,
        celebrated: unlocked?.celebrated || false,
        progressPercent,
        currentValue: progress[Object.keys(achievement.criteria)[0]] || 0
      }
    })
  }

  /**
   * Generate a personalized daily tip based on user data
   * @param {Object} userData - User expenses, budget, goals
   * @returns {Object} - Daily tip object
   */
  generateDailyTip(userData) {
    const { expenses = [], budget, goals = [], profile, tipsShown = [] } = userData
    const tips = []

    // Get current month expenses
    const now = new Date()
    const currentMonth = now.toISOString().substring(0, 7)
    const monthExpenses = expenses.filter(e =>
      e.date?.startsWith?.(currentMonth) ||
      new Date(e.date).toISOString().substring(0, 7) === currentMonth
    )

    const totalSpent = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const income = budget?.totalBudget || profile?.monthlyIncome || 50000
    const savingsRate = income > 0 ? ((income - totalSpent) / income) * 100 : 0

    // Calculate category spending
    const categorySpending = {}
    monthExpenses.forEach(e => {
      const cat = e.category || 'Other'
      categorySpending[cat] = (categorySpending[cat] || 0) + (e.amount || 0)
    })

    // Find top merchant
    const merchantSpending = {}
    monthExpenses.forEach(e => {
      const merchant = e.merchant || e.description || 'Unknown'
      if (merchant && merchant !== 'Unknown') {
        merchantSpending[merchant] = (merchantSpending[merchant] || 0) + (e.amount || 0)
      }
    })
    const topMerchant = Object.entries(merchantSpending)
      .sort((a, b) => b[1] - a[1])[0]

    // Priority 1: Urgent issues
    if (savingsRate < 10 && totalSpent > 0) {
      tips.push({
        id: 'tip_low_savings',
        category: 'warning',
        priority: 1,
        title: 'Savings Alert',
        message: `Your savings rate is ${savingsRate.toFixed(0)}% this month. Even saving 10% of your income can build a ₹${Math.round(income * 0.1).toLocaleString('en-IN')} buffer over time. Try identifying one expense to cut this week.`
      })
    }

    // Check category overspending
    if (budget?.categories) {
      for (const [catKey, catBudget] of Object.entries(budget.categories)) {
        const spent = categorySpending[catBudget.englishName] || categorySpending[catKey] || 0
        const budgetAmount = catBudget.amount || 0
        if (budgetAmount > 0 && spent > budgetAmount * 0.9) {
          tips.push({
            id: `tip_category_${catKey}`,
            category: 'warning',
            priority: 1,
            title: `${catBudget.englishName} Budget Alert`,
            message: `You've used ${Math.round((spent / budgetAmount) * 100)}% of your ${catBudget.englishName} budget. You have ₹${Math.max(0, budgetAmount - spent).toLocaleString('en-IN')} left for the rest of the month.`
          })
          break // Only one budget warning
        }
      }
    }

    // Priority 2: Opportunities
    if (topMerchant && topMerchant[1] > 3000) {
      const [merchantName, amount] = topMerchant
      tips.push({
        id: 'tip_top_merchant',
        category: 'insight',
        priority: 2,
        title: 'Spending Insight',
        message: `You've spent ₹${amount.toLocaleString('en-IN')} at ${merchantName} this month. If this is food delivery, cooking 2 meals at home weekly could save you ₹${Math.round(amount * 0.3).toLocaleString('en-IN')}/month.`
      })
    }

    // Goal encouragement
    const activeGoals = goals.filter(g => g.progress > 0 && g.progress < 100)
    if (activeGoals.length > 0) {
      const closestGoal = activeGoals.sort((a, b) => b.progress - a.progress)[0]
      if (closestGoal.progress >= 40 && closestGoal.progress < 60) {
        tips.push({
          id: 'tip_goal_encouragement',
          category: 'achievement',
          priority: 2,
          title: 'Almost Halfway!',
          message: `Your "${closestGoal.name}" goal is at ${closestGoal.progress}%! Keep going - you're building great saving habits. At this rate, you'll reach your goal ${closestGoal.targetDate ? `by ${new Date(closestGoal.targetDate).toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}` : 'soon'}.`
        })
      }
    }

    // Positive reinforcement
    if (savingsRate >= 20) {
      tips.push({
        id: 'tip_good_savings',
        category: 'achievement',
        priority: 3,
        title: 'Great Savings Rate!',
        message: `You're saving ${savingsRate.toFixed(0)}% of your income this month - that's excellent! Keep this up and you'll save ₹${Math.round(income * savingsRate / 100 * 12).toLocaleString('en-IN')} this year.`
      })
    }

    // Add general tips as fallback
    GENERAL_TIPS.forEach(tip => {
      tips.push({
        ...tip,
        priority: 4,
        message: tip.template
      })
    })

    // Filter out recently shown tips (last 7 days)
    const recentTipIds = new Set(
      tipsShown
        .filter(t => {
          const shownDate = new Date(t.shownAt)
          const daysSince = (now - shownDate) / (1000 * 60 * 60 * 24)
          return daysSince < 7
        })
        .map(t => t.tipId)
    )

    const availableTips = tips.filter(t => !recentTipIds.has(t.id))

    // Sort by priority and return the best one
    availableTips.sort((a, b) => a.priority - b.priority)

    return availableTips[0] || tips[0] // Fallback to any tip if all were shown
  }

  /**
   * Build weekly report data
   * @param {Object} userData - User profile with expenses, budget, goals
   * @returns {Object} - Weekly report data
   */
  buildWeeklyReport(userData) {
    const { expenses = [], budget, goals = [], profile } = userData
    const now = new Date()

    // Calculate week boundaries (Sunday to Saturday)
    const dayOfWeek = now.getDay()
    const endOfWeek = new Date(now)
    endOfWeek.setDate(now.getDate() - dayOfWeek) // Go back to Sunday
    endOfWeek.setHours(23, 59, 59, 999)

    const startOfWeek = new Date(endOfWeek)
    startOfWeek.setDate(endOfWeek.getDate() - 6)
    startOfWeek.setHours(0, 0, 0, 0)

    // Previous week for comparison
    const prevWeekEnd = new Date(startOfWeek)
    prevWeekEnd.setDate(prevWeekEnd.getDate() - 1)
    const prevWeekStart = new Date(prevWeekEnd)
    prevWeekStart.setDate(prevWeekEnd.getDate() - 6)

    // Filter expenses for this week
    const weekExpenses = expenses.filter(e => {
      const date = new Date(e.date)
      return date >= startOfWeek && date <= endOfWeek
    })

    const prevWeekExpenses = expenses.filter(e => {
      const date = new Date(e.date)
      return date >= prevWeekStart && date <= prevWeekEnd
    })

    // Calculate totals
    const totalSpent = weekExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const prevWeekTotal = prevWeekExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const transactionCount = weekExpenses.length

    // Income and savings
    const weeklyBudget = (budget?.totalBudget || profile?.monthlyIncome || 50000) / 4
    const savingsRate = weeklyBudget > 0 ?
      Math.round(((weeklyBudget - totalSpent) / weeklyBudget) * 100) : 0

    // Category breakdown
    const categorySpending = {}
    weekExpenses.forEach(e => {
      const cat = e.category || 'Other'
      categorySpending[cat] = (categorySpending[cat] || 0) + (e.amount || 0)
    })

    const topCategories = Object.entries(categorySpending)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, amount]) => ({
        name,
        amount,
        percentage: totalSpent > 0 ? Math.round((amount / totalSpent) * 100) : 0,
        emoji: this._getCategoryEmoji(name)
      }))

    // Calculate grade
    const grade = this._calculateGrade(savingsRate, categorySpending, budget)

    // Generate highlights
    const highlights = []

    // Week-over-week comparison
    if (prevWeekTotal > 0) {
      const changePercent = Math.round(((totalSpent - prevWeekTotal) / prevWeekTotal) * 100)
      if (changePercent < 0) {
        highlights.push({
          type: 'positive',
          emoji: '✅',
          text: `Spent ${Math.abs(changePercent)}% less than last week`
        })
      } else if (changePercent > 20) {
        highlights.push({
          type: 'warning',
          emoji: '⚠️',
          text: `Spending up ${changePercent}% from last week`
        })
      }
    }

    // Goal progress
    if (goals.length > 0) {
      const progressingGoal = goals.find(g => g.progress > 0 && g.progress < 100)
      if (progressingGoal) {
        highlights.push({
          type: 'positive',
          emoji: '🎯',
          text: `${progressingGoal.name}: ${progressingGoal.progress}% complete`
        })
      }
    }

    // Category alert
    const highestCategory = topCategories[0]
    if (highestCategory && highestCategory.percentage > 50) {
      highlights.push({
        type: 'info',
        emoji: highestCategory.emoji,
        text: `${highestCategory.name} was ${highestCategory.percentage}% of spending`
      })
    }

    // Generate tip of the week
    const tipOfWeek = this.generateDailyTip({
      expenses,
      budget,
      goals,
      profile,
      tipsShown: []
    })

    return {
      period: {
        start: startOfWeek,
        end: endOfWeek,
        formatted: `${startOfWeek.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })} - ${endOfWeek.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })}`
      },
      summary: {
        totalSpent,
        savingsRate: Math.max(0, savingsRate),
        transactionCount,
        grade
      },
      topCategories,
      highlights,
      tipOfWeek: tipOfWeek?.message || 'Keep tracking your expenses to get personalized insights!',
      comparison: {
        prevWeekTotal,
        change: totalSpent - prevWeekTotal,
        changePercent: prevWeekTotal > 0 ?
          Math.round(((totalSpent - prevWeekTotal) / prevWeekTotal) * 100) : 0
      }
    }
  }

  /**
   * Check for smart nudges that should be shown
   * @param {Object} userData - User data
   * @returns {Array} - Nudges to show
   */
  checkSmartNudges(userData) {
    const { expenses = [], budget, goals = [], profile, nudgeHistory = [] } = userData
    const nudges = []
    const now = new Date()

    // Get recent nudges for cooldown
    const recentNudges = new Map(
      nudgeHistory
        .filter(n => {
          const sentAt = new Date(n.sentAt)
          const hoursSince = (now - sentAt) / (1000 * 60 * 60)
          return hoursSince < 24
        })
        .map(n => [n.type, n])
    )

    // Current month expenses
    const currentMonth = now.toISOString().substring(0, 7)
    const monthExpenses = expenses.filter(e =>
      e.date?.startsWith?.(currentMonth) ||
      new Date(e.date).toISOString().substring(0, 7) === currentMonth
    )

    // Category spending
    const categorySpending = {}
    monthExpenses.forEach(e => {
      const cat = e.category || 'Other'
      categorySpending[cat] = (categorySpending[cat] || 0) + (e.amount || 0)
    })

    // Check budget warnings
    if (budget?.categories && !recentNudges.has('budget_warning')) {
      for (const [catKey, catBudget] of Object.entries(budget.categories)) {
        const spent = categorySpending[catBudget.englishName] || categorySpending[catKey] || 0
        const budgetAmount = catBudget.amount || 0

        if (budgetAmount > 0) {
          const percentUsed = (spent / budgetAmount) * 100

          if (percentUsed >= 95 && !recentNudges.has('budget_critical')) {
            const daysLeft = this._getDaysLeftInMonth()
            nudges.push({
              id: `nudge_budget_critical_${catKey}`,
              type: 'budget_critical',
              priority: 'high',
              icon: 'AlertTriangle',
              title: `${catBudget.englishName} budget at ${Math.round(percentUsed)}%`,
              message: `₹${Math.max(0, budgetAmount - spent).toLocaleString('en-IN')} left for ${daysLeft} days`,
              actionLabel: 'View Budget',
              actionUrl: '/dashboard/budget'
            })
            break
          } else if (percentUsed >= 80 && percentUsed < 95) {
            const daysLeft = this._getDaysLeftInMonth()
            nudges.push({
              id: `nudge_budget_warning_${catKey}`,
              type: 'budget_warning',
              priority: 'medium',
              icon: 'AlertCircle',
              title: `${catBudget.englishName} budget at ${Math.round(percentUsed)}%`,
              message: `₹${Math.max(0, budgetAmount - spent).toLocaleString('en-IN')} left for ${daysLeft} days`,
              actionLabel: 'View Budget',
              actionUrl: '/dashboard/budget'
            })
            break
          }
        }
      }
    }

    // Check for unusual expense (last expense)
    if (expenses.length > 0 && !recentNudges.has('unusual_expense')) {
      const lastExpense = expenses.sort((a, b) =>
        new Date(b.date || b.timestamp) - new Date(a.date || a.timestamp)
      )[0]

      const category = lastExpense.category || 'Other'
      const categoryAvg = this._calculateCategoryAverage(expenses, category)

      if (categoryAvg > 0 && lastExpense.amount > categoryAvg * 3) {
        nudges.push({
          id: `nudge_unusual_${lastExpense.id}`,
          type: 'unusual_expense',
          priority: 'high',
          icon: 'Zap',
          title: 'Unusual expense detected',
          message: `₹${lastExpense.amount.toLocaleString('en-IN')} on ${category} is ${Math.round(lastExpense.amount / categoryAvg)}x your average`,
          actionLabel: 'Review',
          actionUrl: '/dashboard/expenses'
        })
      }
    }

    // Check goal milestones
    goals.forEach(goal => {
      const milestones = [25, 50, 75, 100]
      const currentMilestone = milestones.find(m =>
        goal.progress >= m && goal.progress < m + 5
      )

      if (currentMilestone && !recentNudges.has(`goal_${goal.id}_${currentMilestone}`)) {
        nudges.push({
          id: `nudge_goal_${goal.id}_${currentMilestone}`,
          type: `goal_milestone_${currentMilestone}`,
          priority: 'low',
          icon: currentMilestone === 100 ? 'Trophy' : 'Target',
          title: currentMilestone === 100 ? 'Goal completed!' : `${goal.name} at ${currentMilestone}%`,
          message: currentMilestone === 100 ?
            `Congratulations! You've reached your "${goal.name}" goal!` :
            `You're ${currentMilestone}% of the way to your goal. Keep it up!`,
          actionLabel: 'View Goals',
          actionUrl: '/dashboard/goals'
        })
      }
    })

    // Check inactivity
    const lastExpenseDate = userData.activityTracking?.lastExpenseDate
    if (lastExpenseDate && !recentNudges.has('inactivity')) {
      const daysSinceLastExpense = Math.floor(
        (now - new Date(lastExpenseDate)) / (1000 * 60 * 60 * 24)
      )

      if (daysSinceLastExpense >= 3) {
        nudges.push({
          id: 'nudge_inactivity',
          type: 'inactivity',
          priority: 'low',
          icon: 'Clock',
          title: 'Keep your records up to date',
          message: `It's been ${daysSinceLastExpense} days since your last expense. Did you forget to log something?`,
          actionLabel: 'Add Expense',
          actionUrl: '/dashboard/expenses'
        })
      }
    }

    // Sort by priority
    const priorityOrder = { high: 0, medium: 1, low: 2 }
    nudges.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority])

    return nudges.slice(0, 3) // Max 3 nudges at a time
  }

  // ============================================
  // HELPER METHODS
  // ============================================

  _calculateGrade(savingsRate, categorySpending, budget) {
    let categoriesOver = 0

    if (budget?.categories) {
      for (const [catKey, catBudget] of Object.entries(budget.categories)) {
        const spent = categorySpending[catBudget.englishName] || categorySpending[catKey] || 0
        if (spent > (catBudget.amount || 0)) {
          categoriesOver++
        }
      }
    }

    if (savingsRate >= 30 && categoriesOver === 0) return 'A+'
    if (savingsRate >= 25 && categoriesOver <= 1) return 'A'
    if (savingsRate >= 20 && categoriesOver <= 2) return 'B+'
    if (savingsRate >= 15) return 'B'
    if (savingsRate >= 10) return 'C'
    return 'D'
  }

  _getCategoryEmoji(category) {
    const emojiMap = {
      'Food & Dining': '🍔',
      'Food': '🍔',
      'Transportation': '🚗',
      'Housing': '🏠',
      'Entertainment': '🎬',
      'Healthcare': '🏥',
      'Shopping': '🛒',
      'Utilities': '💡',
      'Personal Care': '💆',
      'Other': '📦'
    }
    return emojiMap[category] || '📦'
  }

  _getDaysLeftInMonth() {
    const now = new Date()
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0)
    return lastDay.getDate() - now.getDate()
  }

  _calculateCategoryAverage(expenses, category) {
    const categoryExpenses = expenses.filter(e => e.category === category)
    if (categoryExpenses.length === 0) return 0
    const total = categoryExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    return total / categoryExpenses.length
  }

  /**
   * Update achievement progress after an action
   * @param {Object} userProfile - User profile
   * @param {String} action - Action type
   * @param {Object} data - Action data
   * @returns {Object} - Updated progress and new achievements
   */
  updateProgress(userProfile, action, data = {}) {
    const progress = { ...userProfile.achievements?.progress } || {}

    switch (action) {
      case 'expense_added':
        progress.expenseCount = (progress.expenseCount || 0) + 1
        if (data.entryMethod === 'voice') {
          progress.voiceEntryCount = (progress.voiceEntryCount || 0) + 1
        }
        break

      case 'goal_created':
        progress.goalsCreated = (progress.goalsCreated || 0) + 1
        break

      case 'goal_completed':
        progress.goalsCompleted = (progress.goalsCompleted || 0) + 1
        break

      case 'goal_milestone':
        if (!progress.goalsMilestoneReached) {
          progress.goalsMilestoneReached = []
        }
        const milestoneKey = `${data.goalId}:${data.milestone}`
        if (!progress.goalsMilestoneReached.includes(milestoneKey)) {
          progress.goalsMilestoneReached.push(milestoneKey)
        }
        break

      case 'savings_updated':
        progress.totalSaved = data.totalSaved || progress.totalSaved || 0
        break

      case 'month_ended':
        // Called at month end to update monthly achievements
        if (data.savingsRate >= 20) {
          progress.monthsWith20PercentSavings = (progress.monthsWith20PercentSavings || 0) + 1
        }
        if (data.underBudget) {
          progress.monthsUnderBudget = (progress.monthsUnderBudget || 0) + 1
        }
        progress.categoriesUnderBudgetThisMonth = data.categoriesUnderBudget || []
        break
    }

    return progress
  }
}

// Export singleton instance
export const retentionEngine = new RetentionEngine()
export default retentionEngine
