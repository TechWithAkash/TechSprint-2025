// lib/expenseInsightsGenerator.js
// Comprehensive Expense Insights Generator for WealthWise
import { GoogleGenerativeAI } from '@google/generative-ai'

class ExpenseInsightsGenerator {
  constructor() {
    this.genAI = process.env.GEMINI_API_KEY
      ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
      : null
    this.model = this.genAI?.getGenerativeModel({ model: "gemini-2.5-flash" })
  }

  /**
   * Generate comprehensive expense insights report
   */
  async generateExpenseReport(userData) {
    const { expenses, budget, profile } = userData

    // Calculate all analytics
    const analytics = this.calculateAnalytics(expenses, budget)

    // Generate AI insights if available
    let aiRecommendations = []
    if (this.model) {
      try {
        aiRecommendations = await this.generateAIRecommendations(analytics, profile)
      } catch (error) {
        console.error('AI recommendations failed:', error)
        aiRecommendations = this.generateRuleBasedRecommendations(analytics)
      }
    } else {
      aiRecommendations = this.generateRuleBasedRecommendations(analytics)
    }

    return {
      generatedAt: new Date().toISOString(),
      period: analytics.period,
      summary: analytics.summary,
      spendingPatterns: analytics.spendingPatterns,
      savingsOpportunities: analytics.savingsOpportunities,
      predictions: analytics.predictions,
      recommendations: aiRecommendations,
      aiGenerated: !!this.model
    }
  }

  /**
   * Calculate comprehensive spending analytics
   */
  calculateAnalytics(expenses = [], budget = null) {
    const now = new Date()
    const currentMonth = now.toISOString().substring(0, 7)
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().substring(0, 7)

    // Filter expenses
    const monthExpenses = expenses.filter(e => e.date?.startsWith(currentMonth))
    const lastMonthExpenses = expenses.filter(e => e.date?.startsWith(lastMonth))

    // Basic calculations
    const totalSpent = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const lastMonthTotal = lastMonthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const totalBudget = budget?.totalBudget || 0
    const savingsRate = totalBudget > 0 ? Math.round(((totalBudget - totalSpent) / totalBudget) * 100) : 0

    // Days analysis
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()
    const currentDay = now.getDate()
    const dailyAverage = currentDay > 0 ? totalSpent / currentDay : 0

    return {
      period: {
        start: `${currentMonth}-01`,
        end: now.toISOString().split('T')[0],
        daysElapsed: currentDay,
        daysRemaining: daysInMonth - currentDay
      },
      summary: {
        totalSpent,
        totalBudget,
        savingsRate: Math.max(0, savingsRate),
        transactionCount: monthExpenses.length,
        dailyAverage: Math.round(dailyAverage),
        monthOverMonthChange: lastMonthTotal > 0
          ? Math.round(((totalSpent - lastMonthTotal) / lastMonthTotal) * 100)
          : 0
      },
      spendingPatterns: this.analyzeSpendingPatterns(monthExpenses, budget),
      savingsOpportunities: this.analyzeSavingsOpportunities(monthExpenses, budget),
      predictions: this.generatePredictions(monthExpenses, budget, currentDay, daysInMonth)
    }
  }

  /**
   * Analyze spending patterns
   */
  analyzeSpendingPatterns(expenses, budget) {
    // Category breakdown
    const categoryTotals = expenses.reduce((acc, e) => {
      const cat = e.category || 'Other'
      acc[cat] = (acc[cat] || 0) + (e.amount || 0)
      return acc
    }, {})

    const totalSpent = Object.values(categoryTotals).reduce((a, b) => a + b, 0)

    const categoryBreakdown = Object.entries(categoryTotals)
      .map(([category, amount]) => ({
        category,
        amount,
        percentage: totalSpent > 0 ? Math.round((amount / totalSpent) * 100) : 0,
        budgeted: this.getCategoryBudget(category, budget),
        color: this.getCategoryColor(category)
      }))
      .sort((a, b) => b.amount - a.amount)

    // Peak spending days (by day of week)
    const dayOfWeekSpending = [0, 0, 0, 0, 0, 0, 0] // Sun-Sat
    const dayOfWeekCounts = [0, 0, 0, 0, 0, 0, 0]
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

    expenses.forEach(e => {
      if (e.date) {
        const day = new Date(e.date).getDay()
        dayOfWeekSpending[day] += e.amount || 0
        dayOfWeekCounts[day]++
      }
    })

    const peakDays = dayOfWeekSpending.map((total, idx) => ({
      day: dayNames[idx],
      total,
      count: dayOfWeekCounts[idx],
      average: dayOfWeekCounts[idx] > 0 ? Math.round(total / dayOfWeekCounts[idx]) : 0
    })).sort((a, b) => b.total - a.total)

    // Top merchants/descriptions
    const merchantTotals = expenses.reduce((acc, e) => {
      const merchant = e.merchant || e.description || 'Unknown'
      if (!acc[merchant]) acc[merchant] = { total: 0, count: 0 }
      acc[merchant].total += e.amount || 0
      acc[merchant].count++
      return acc
    }, {})

    const topMerchants = Object.entries(merchantTotals)
      .map(([name, data]) => ({ name, ...data }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5)

    // Entry method analysis
    const voiceEntries = expenses.filter(e => e.entryMethod === 'voice')
    const manualEntries = expenses.filter(e => e.entryMethod !== 'voice')

    return {
      categoryBreakdown,
      peakDays: peakDays.slice(0, 3),
      topMerchants,
      entryMethods: {
        voice: { count: voiceEntries.length, total: voiceEntries.reduce((s, e) => s + (e.amount || 0), 0) },
        manual: { count: manualEntries.length, total: manualEntries.reduce((s, e) => s + (e.amount || 0), 0) }
      },
      largestExpense: expenses.length > 0
        ? expenses.reduce((max, e) => (e.amount || 0) > (max.amount || 0) ? e : max, expenses[0])
        : null,
      averageTransaction: expenses.length > 0
        ? Math.round(totalSpent / expenses.length)
        : 0
    }
  }

  /**
   * Analyze savings opportunities
   */
  analyzeSavingsOpportunities(expenses, budget) {
    const opportunities = []
    let totalPotentialSavings = 0

    if (!budget?.categories) {
      return {
        areasToReduce: [],
        potentialSavings: 0,
        budgetComparisons: [],
        suggestions: ['Set up a budget to see personalized savings opportunities']
      }
    }

    // Category spending
    const categorySpending = expenses.reduce((acc, e) => {
      const cat = e.category || 'Other'
      acc[cat] = (acc[cat] || 0) + (e.amount || 0)
      return acc
    }, {})

    // Compare with budget
    const budgetComparisons = []

    Object.entries(budget.categories).forEach(([key, cat]) => {
      const spent = categorySpending[cat.englishName] || 0
      const budgeted = cat.amount || 0
      const difference = budgeted - spent
      const usagePercent = budgeted > 0 ? Math.round((spent / budgeted) * 100) : 0

      budgetComparisons.push({
        category: cat.englishName,
        emoji: cat.emoji,
        spent,
        budgeted,
        difference,
        usagePercent,
        status: usagePercent > 100 ? 'over' : usagePercent > 80 ? 'warning' : 'good'
      })

      // Identify reduction opportunities
      if (usagePercent > 100) {
        const overAmount = spent - budgeted
        const suggestedReduction = Math.round(overAmount * 0.5) // Suggest 50% reduction of overage
        opportunities.push({
          category: cat.englishName,
          emoji: cat.emoji,
          currentSpend: spent,
          budgeted,
          overBy: overAmount,
          suggestedReduction,
          tip: this.getReductionTip(cat.englishName, overAmount)
        })
        totalPotentialSavings += suggestedReduction
      } else if (usagePercent > 90) {
        const potentialSaving = Math.round(spent * 0.1) // 10% potential saving
        opportunities.push({
          category: cat.englishName,
          emoji: cat.emoji,
          currentSpend: spent,
          budgeted,
          overBy: 0,
          suggestedReduction: potentialSaving,
          tip: this.getReductionTip(cat.englishName, potentialSaving)
        })
        totalPotentialSavings += potentialSaving
      }
    })

    return {
      areasToReduce: opportunities.sort((a, b) => b.suggestedReduction - a.suggestedReduction),
      potentialSavings: totalPotentialSavings,
      budgetComparisons: budgetComparisons.sort((a, b) => b.usagePercent - a.usagePercent),
      suggestions: this.generateSavingsSuggestions(opportunities)
    }
  }

  /**
   * Generate predictions
   */
  generatePredictions(expenses, budget, currentDay, daysInMonth) {
    const totalSpent = expenses.reduce((sum, e) => sum + (e.amount || 0), 0)
    const totalBudget = budget?.totalBudget || 0

    // Linear projection for month end
    const dailyRate = currentDay > 0 ? totalSpent / currentDay : 0
    const monthEndForecast = Math.round(dailyRate * daysInMonth)
    const willExceedBudget = totalBudget > 0 && monthEndForecast > totalBudget

    // Category breach warnings
    const warnings = []
    const categorySpending = expenses.reduce((acc, e) => {
      const cat = e.category || 'Other'
      acc[cat] = (acc[cat] || 0) + (e.amount || 0)
      return acc
    }, {})

    if (budget?.categories) {
      Object.entries(budget.categories).forEach(([key, cat]) => {
        const spent = categorySpending[cat.englishName] || 0
        const budgeted = cat.amount || 0
        const projectedSpend = currentDay > 0 ? Math.round((spent / currentDay) * daysInMonth) : 0

        if (budgeted > 0 && projectedSpend > budgeted) {
          warnings.push({
            category: cat.englishName,
            emoji: cat.emoji,
            currentSpend: spent,
            budgeted,
            projectedSpend,
            projectedOverage: projectedSpend - budgeted,
            severity: projectedSpend > budgeted * 1.2 ? 'high' : 'medium'
          })
        }
      })
    }

    // Detect anomalies (expenses significantly higher than average)
    const categoryAverages = {}
    const categoryCounts = {}
    expenses.forEach(e => {
      const cat = e.category || 'Other'
      if (!categoryAverages[cat]) {
        categoryAverages[cat] = 0
        categoryCounts[cat] = 0
      }
      categoryAverages[cat] += e.amount || 0
      categoryCounts[cat]++
    })

    const anomalies = expenses.filter(e => {
      const cat = e.category || 'Other'
      const avg = categoryCounts[cat] > 1 ? categoryAverages[cat] / categoryCounts[cat] : 0
      return avg > 0 && (e.amount || 0) > avg * 2.5 // 2.5x average is anomaly
    }).map(e => ({
      description: e.description || e.category,
      amount: e.amount,
      date: e.date,
      category: e.category,
      reason: 'Significantly higher than your average for this category'
    })).slice(0, 3)

    return {
      monthEndForecast,
      projectedSavings: Math.max(0, totalBudget - monthEndForecast),
      willExceedBudget,
      exceedBy: willExceedBudget ? monthEndForecast - totalBudget : 0,
      warnings: warnings.sort((a, b) => b.projectedOverage - a.projectedOverage),
      anomalies,
      confidence: currentDay >= 15 ? 'high' : currentDay >= 7 ? 'medium' : 'low'
    }
  }

  /**
   * Generate AI-powered recommendations
   */
  async generateAIRecommendations(analytics, profile) {
    const { summary, spendingPatterns, savingsOpportunities, predictions } = analytics

    const prompt = `You are a friendly Indian financial advisor for WealthWise app. Based on this expense analysis, provide 5-6 specific, actionable recommendations.

EXPENSE SUMMARY:
- Total Spent: Rs.${summary.totalSpent.toLocaleString('en-IN')}
- Budget: Rs.${summary.totalBudget.toLocaleString('en-IN')}
- Savings Rate: ${summary.savingsRate}%
- Transactions: ${summary.transactionCount}
- Month-over-Month Change: ${summary.monthOverMonthChange}%

TOP SPENDING CATEGORIES:
${spendingPatterns.categoryBreakdown.slice(0, 5).map(c =>
      `- ${c.category}: Rs.${c.amount.toLocaleString('en-IN')} (${c.percentage}%)`
    ).join('\n')}

PEAK SPENDING DAYS:
${spendingPatterns.peakDays.map(d => `- ${d.day}: Rs.${d.total.toLocaleString('en-IN')}`).join('\n')}

AREAS OVER BUDGET:
${savingsOpportunities.areasToReduce.slice(0, 3).map(a =>
      `- ${a.category}: Over by Rs.${a.overBy?.toLocaleString('en-IN') || 0}`
    ).join('\n') || 'None'}

PREDICTIONS:
- Month-end forecast: Rs.${predictions.monthEndForecast.toLocaleString('en-IN')}
- Will exceed budget: ${predictions.willExceedBudget ? 'Yes' : 'No'}

USER PROFILE:
- City: ${profile?.city || 'Not specified'}
- Family Size: ${profile?.familySize || 1}

Generate recommendations in this exact JSON format:
{
  "recommendations": [
    {
      "priority": "high|medium|low",
      "title": "Short actionable title (max 40 chars)",
      "description": "Specific advice with numbers (max 120 chars)",
      "impact": "Potential savings or benefit (e.g., 'Save Rs.2,000/month')",
      "category": "spending|saving|budgeting|lifestyle"
    }
  ]
}

RULES:
- Be specific with numbers from the data
- Use Indian context and Rs. currency format
- Mix quick wins and long-term advice
- Be encouraging but practical
- Include at least one celebration if savings rate > 15%`

    const result = await this.model.generateContent(prompt)
    const response = await result.response
    const text = response.text()

    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) throw new Error('No valid JSON in response')

    const parsed = JSON.parse(jsonMatch[0])
    return (parsed.recommendations || []).map(rec => ({
      ...rec,
      source: 'ai'
    }))
  }

  /**
   * Generate rule-based recommendations (fallback)
   */
  generateRuleBasedRecommendations(analytics) {
    const recommendations = []
    const { summary, spendingPatterns, savingsOpportunities, predictions } = analytics

    // Savings rate recommendations
    if (summary.savingsRate < 10) {
      recommendations.push({
        priority: 'high',
        title: 'Boost Your Savings Rate',
        description: `Your ${summary.savingsRate}% savings is below the recommended 20%. Try the 50-30-20 rule.`,
        impact: `Save Rs.${Math.round(summary.totalBudget * 0.1).toLocaleString('en-IN')} more`,
        category: 'saving',
        source: 'rule'
      })
    } else if (summary.savingsRate >= 25) {
      recommendations.push({
        priority: 'low',
        title: 'Excellent Savings!',
        description: `You're saving ${summary.savingsRate}% - that's above average! Consider investing the surplus.`,
        impact: 'Build long-term wealth',
        category: 'saving',
        source: 'rule'
      })
    }

    // Overspending areas
    savingsOpportunities.areasToReduce.slice(0, 2).forEach(area => {
      recommendations.push({
        priority: 'high',
        title: `Reduce ${area.category} Spending`,
        description: `You're Rs.${area.overBy?.toLocaleString('en-IN') || 0} over budget. ${area.tip}`,
        impact: `Save Rs.${area.suggestedReduction?.toLocaleString('en-IN')}/month`,
        category: 'spending',
        source: 'rule'
      })
    })

    // Peak day advice
    if (spendingPatterns.peakDays.length > 0) {
      const peakDay = spendingPatterns.peakDays[0]
      recommendations.push({
        priority: 'medium',
        title: `Watch ${peakDay.day} Spending`,
        description: `You spend most on ${peakDay.day}s (Rs.${peakDay.total.toLocaleString('en-IN')}). Plan purchases ahead.`,
        impact: 'Avoid impulse buying',
        category: 'lifestyle',
        source: 'rule'
      })
    }

    // Budget breach warning
    if (predictions.willExceedBudget) {
      recommendations.push({
        priority: 'high',
        title: 'Budget Alert',
        description: `At current pace, you'll exceed budget by Rs.${predictions.exceedBy.toLocaleString('en-IN')}. Slow down spending.`,
        impact: `Stay within Rs.${summary.totalBudget.toLocaleString('en-IN')} budget`,
        category: 'budgeting',
        source: 'rule'
      })
    }

    // Transaction count advice
    if (summary.transactionCount > 40) {
      recommendations.push({
        priority: 'low',
        title: 'Consolidate Purchases',
        description: `${summary.transactionCount} transactions this month. Try batch shopping to save time and money.`,
        impact: 'Reduce impulse purchases',
        category: 'lifestyle',
        source: 'rule'
      })
    }

    return recommendations.slice(0, 6)
  }

  // Helper methods
  getCategoryBudget(category, budget) {
    if (!budget?.categories) return 0
    const cat = Object.values(budget.categories).find(c => c.englishName === category)
    return cat?.amount || 0
  }

  getCategoryColor(category) {
    const colors = {
      'Food & Dining': '#F59E0B',
      'Transportation': '#3B82F6',
      'Shopping': '#EC4899',
      'Entertainment': '#8B5CF6',
      'Healthcare': '#EF4444',
      'Home & Utilities': '#10B981',
      'Savings': '#06B6D4',
      'Other': '#6B7280'
    }
    return colors[category] || '#6B7280'
  }

  getReductionTip(category, amount) {
    const tips = {
      'Food & Dining': 'Try meal prep and cooking at home more often',
      'Transportation': 'Consider carpooling or public transport',
      'Shopping': 'Wait 24 hours before non-essential purchases',
      'Entertainment': 'Look for free events and discount offers',
      'Healthcare': 'Use generic medicines and preventive care',
      'Home & Utilities': 'Check for energy-saving opportunities',
      'Other': 'Review and categorize these expenses'
    }
    return tips[category] || 'Review this category for savings'
  }

  generateSavingsSuggestions(opportunities) {
    if (opportunities.length === 0) {
      return ['Great job! You\'re staying within budget across all categories.']
    }

    const suggestions = opportunities.slice(0, 3).map(o =>
      `Reduce ${o.category} by Rs.${o.suggestedReduction?.toLocaleString('en-IN')} - ${o.tip}`
    )

    return suggestions
  }
}

export const expenseInsightsGenerator = new ExpenseInsightsGenerator()
export default expenseInsightsGenerator
