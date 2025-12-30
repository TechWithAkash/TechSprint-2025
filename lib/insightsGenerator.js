// lib/insightsGenerator.js
// AI-powered Financial Insights Generator for WealthWise
import { GoogleGenerativeAI } from '@google/generative-ai'

class InsightsGenerator {
  constructor() {
    this.genAI = process.env.GEMINI_API_KEY
      ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
      : null
    this.model = this.genAI?.getGenerativeModel({ model: "gemini-2.5-flash" })
  }

  /**
   * Generate personalized financial insights based on user data
   */
  async generateInsights(userData) {
    const {
      budget,
      expenses,
      goals,
      profile,
      seasonalEvents
    } = userData

    // Always generate rule-based insights first (fallback)
    const ruleBasedInsights = this.generateRuleBasedInsights(userData)

    // Try AI-powered insights if API is available
    if (this.model) {
      try {
        const aiInsights = await this.generateAIInsights(userData)
        // Merge and deduplicate insights
        return this.mergeInsights(aiInsights, ruleBasedInsights)
      } catch (error) {
        console.error('AI insights generation failed:', error)
        return ruleBasedInsights
      }
    }

    return ruleBasedInsights
  }

  /**
   * Generate insights using Gemini AI
   */
  async generateAIInsights(userData) {
    const { budget, expenses, goals, profile, seasonalEvents } = userData

    // Prepare context for AI
    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = (expenses || []).filter(e => e.date?.startsWith(currentMonth))
    const totalSpent = monthExpenses.reduce((sum, e) => sum + e.amount, 0)
    const totalBudget = budget?.totalBudget || 0
    const savings = totalBudget - totalSpent

    // Category breakdown
    const categorySpending = monthExpenses.reduce((acc, e) => {
      const cat = e.category || 'Other'
      acc[cat] = (acc[cat] || 0) + e.amount
      return acc
    }, {})

    // Goals summary
    const goalsSummary = (goals || []).map(g => ({
      name: g.name,
      progress: Math.round((g.currentAmount / g.targetAmount) * 100),
      remaining: g.targetAmount - g.currentAmount,
      deadline: g.deadline
    }))

    const prompt = `You are a friendly Indian financial advisor for WealthWise app. Analyze this user's financial data and provide 4-6 personalized insights.

USER DATA:
- Monthly Income: ₹${totalBudget.toLocaleString('en-IN')}
- Spent This Month: ₹${totalSpent.toLocaleString('en-IN')}
- Savings This Month: ₹${savings.toLocaleString('en-IN')} (${totalBudget > 0 ? Math.round((savings / totalBudget) * 100) : 0}%)
- City: ${profile?.city || 'Unknown'}
- Family Size: ${profile?.familySize || 1}

CATEGORY SPENDING:
${Object.entries(categorySpending).map(([cat, amt]) => `- ${cat}: ₹${amt.toLocaleString('en-IN')}`).join('\n')}

BUDGET CATEGORIES:
${budget?.categories ? Object.entries(budget.categories).map(([key, cat]) =>
      `- ${cat.englishName}: Budget ₹${cat.amount?.toLocaleString('en-IN')}`
    ).join('\n') : 'No budget set'}

GOALS:
${goalsSummary.length > 0 ? goalsSummary.map(g =>
      `- ${g.name}: ${g.progress}% complete, ₹${g.remaining.toLocaleString('en-IN')} remaining`
    ).join('\n') : 'No goals set'}

UPCOMING EVENTS:
${(seasonalEvents || []).slice(0, 3).map(e => `- ${e.name} in ${e.daysUntil} days`).join('\n') || 'None'}

Generate insights in this exact JSON format (no markdown, just JSON):
{
  "insights": [
    {
      "type": "spending|achievement|warning|recommendation|celebration",
      "priority": "high|medium|low",
      "title": "Brief catchy title (max 50 chars)",
      "message": "Detailed insight with specific numbers (max 150 chars)",
      "actionLabel": "Button text for action (optional)",
      "actionUrl": "/dashboard/budget or /dashboard/goals etc (optional)"
    }
  ]
}

RULES:
- Use Indian context (festivals like Diwali, Holi; tax deadlines; Indian Rupee format)
- Be encouraging but honest
- Include specific numbers from the data
- Mix positive and constructive feedback
- If savings rate > 20%, celebrate it
- If any category > 90% used, warn about it
- Recommend upcoming festival preparation if relevant
- Keep it conversational and friendly`

    const result = await this.model.generateContent(prompt)
    const response = await result.response
    const text = response.text()

    // Parse JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) throw new Error('No valid JSON in response')

    const parsed = JSON.parse(jsonMatch[0])
    return (parsed.insights || []).map(insight => ({
      ...insight,
      source: 'ai',
      generatedAt: new Date().toISOString()
    }))
  }

  /**
   * Generate rule-based insights (fallback)
   */
  generateRuleBasedInsights(userData) {
    const { budget, expenses, goals, seasonalEvents } = userData
    const insights = []

    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = (expenses || []).filter(e => e.date?.startsWith(currentMonth))
    const totalSpent = monthExpenses.reduce((sum, e) => sum + e.amount, 0)
    const totalBudget = budget?.totalBudget || 0
    const savings = totalBudget - totalSpent
    const savingsRate = totalBudget > 0 ? Math.round((savings / totalBudget) * 100) : 0

    // 1. Savings Rate Insight
    if (savingsRate >= 30) {
      insights.push({
        type: 'celebration',
        priority: 'high',
        title: 'Excellent Savings!',
        message: `You're saving ${savingsRate}% of your income this month. That's above the recommended 20%! Keep it up!`,
        source: 'rule'
      })
    } else if (savingsRate >= 20) {
      insights.push({
        type: 'achievement',
        priority: 'medium',
        title: 'On Track with Savings',
        message: `Your ${savingsRate}% savings rate meets the recommended target. You're building a solid financial foundation.`,
        source: 'rule'
      })
    } else if (savingsRate < 10 && totalBudget > 0) {
      insights.push({
        type: 'warning',
        priority: 'high',
        title: 'Savings Alert',
        message: `Your savings rate is only ${savingsRate}%. Try to save at least 20% of your income for financial security.`,
        actionLabel: 'Review Budget',
        actionUrl: '/dashboard/budget',
        source: 'rule'
      })
    }

    // 2. Category Overspending
    if (budget?.categories) {
      const categorySpending = monthExpenses.reduce((acc, e) => {
        const cat = e.category || 'Other'
        acc[cat] = (acc[cat] || 0) + e.amount
        return acc
      }, {})

      Object.entries(budget.categories).forEach(([key, cat]) => {
        const spent = categorySpending[cat.englishName] || 0
        const budgeted = cat.amount || 0
        const usagePercent = budgeted > 0 ? Math.round((spent / budgeted) * 100) : 0

        if (usagePercent >= 95) {
          insights.push({
            type: 'warning',
            priority: 'high',
            title: `${cat.emoji} ${cat.englishName} Over Budget`,
            message: `You've spent ₹${spent.toLocaleString('en-IN')} (${usagePercent}%) of your ₹${budgeted.toLocaleString('en-IN')} budget.`,
            actionLabel: 'View Details',
            actionUrl: '/dashboard/expenses',
            source: 'rule'
          })
        } else if (usagePercent >= 80 && usagePercent < 95) {
          insights.push({
            type: 'spending',
            priority: 'medium',
            title: `${cat.emoji} ${cat.englishName} at ${usagePercent}%`,
            message: `You've used most of your ${cat.englishName} budget. ₹${(budgeted - spent).toLocaleString('en-IN')} remaining.`,
            source: 'rule'
          })
        }
      })
    }

    // 3. Goal Progress
    if (goals && goals.length > 0) {
      goals.forEach(goal => {
        const progress = Math.round((goal.currentAmount / goal.targetAmount) * 100)
        const remaining = goal.targetAmount - goal.currentAmount

        if (progress >= 100) {
          insights.push({
            type: 'celebration',
            priority: 'high',
            title: `Goal Achieved: ${goal.name}!`,
            message: `Congratulations! You've reached your ₹${goal.targetAmount.toLocaleString('en-IN')} goal!`,
            actionLabel: 'View Goals',
            actionUrl: '/dashboard/goals',
            source: 'rule'
          })
        } else if (progress >= 75) {
          insights.push({
            type: 'achievement',
            priority: 'medium',
            title: `Almost There: ${goal.name}`,
            message: `You're ${progress}% to your goal. Just ₹${remaining.toLocaleString('en-IN')} more to go!`,
            source: 'rule'
          })
        }
      })
    }

    // 4. Seasonal Events
    if (seasonalEvents && seasonalEvents.length > 0) {
      const upcomingEvent = seasonalEvents.find(e => e.daysUntil <= 30 && e.daysUntil > 0)
      if (upcomingEvent) {
        insights.push({
          type: 'recommendation',
          priority: 'medium',
          title: `${upcomingEvent.emoji || '📅'} ${upcomingEvent.name} Coming Up`,
          message: `${upcomingEvent.name} is in ${upcomingEvent.daysUntil} days. Consider setting aside ₹${(upcomingEvent.estimatedCost || 5000).toLocaleString('en-IN')} for it.`,
          actionLabel: 'Plan Budget',
          actionUrl: '/dashboard/budget#seasonal',
          source: 'rule'
        })
      }
    }

    // 5. Transaction Count
    if (monthExpenses.length >= 50) {
      insights.push({
        type: 'spending',
        priority: 'low',
        title: 'High Transaction Volume',
        message: `You've made ${monthExpenses.length} transactions this month. Consider consolidating small purchases.`,
        source: 'rule'
      })
    }

    // 6. Tax Reminder (if between Jan-March)
    const currentMonthNum = new Date().getMonth()
    if (currentMonthNum >= 0 && currentMonthNum <= 2) {
      insights.push({
        type: 'recommendation',
        priority: 'high',
        title: 'Tax Season Reminder',
        message: 'March 31 deadline approaching! Make sure you\'ve invested in tax-saving instruments under Section 80C.',
        source: 'rule'
      })
    }

    // Sort by priority and limit
    const priorityOrder = { high: 0, medium: 1, low: 2 }
    return insights
      .sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority])
      .slice(0, 6)
  }

  /**
   * Merge AI and rule-based insights, removing duplicates
   */
  mergeInsights(aiInsights, ruleInsights) {
    const merged = [...aiInsights]
    const aiTitles = new Set(aiInsights.map(i => i.title.toLowerCase()))

    // Add rule-based insights that don't duplicate AI ones
    ruleInsights.forEach(insight => {
      if (!aiTitles.has(insight.title.toLowerCase())) {
        merged.push(insight)
      }
    })

    // Sort by priority and limit to 6
    const priorityOrder = { high: 0, medium: 1, low: 2 }
    return merged
      .sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority])
      .slice(0, 6)
  }
}

export const insightsGenerator = new InsightsGenerator()
export default insightsGenerator
