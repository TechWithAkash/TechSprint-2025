/**
 * Seasonal Planner Service
 * Core calculation logic for seasonal financial planning in WealthWise
 */

import {
  INDIAN_FINANCIAL_CALENDAR,
  getUpcomingEvents,
  getEventById,
  estimateEventExpense,
  getDaysUntilEvent,
  getMonthsUntilEvent,
  formatEventDate
} from './indianFinancialCalendar.js'

class SeasonalPlanner {
  constructor() {
    this.maxSeasonalReservePercent = 20 // Cap at 20% of income
    this.minMonthsForSaving = 1 // Minimum months to start saving
  }

  /**
   * Calculate monthly savings needed for all upcoming events
   * @param {Array} events - User's seasonal events
   * @param {Number} monthlyIncome - User's total monthly income
   * @param {Date} currentDate - Current date for calculations
   * @returns {Object} Savings breakdown and recommendations
   */
  calculateMonthlySavingsRequired(events, monthlyIncome, currentDate = new Date()) {
    const upcomingEvents = this.getUpcomingEventsFiltered(events, 12, currentDate)

    let totalRequiredSavings = 0
    const eventBreakdown = []

    for (const event of upcomingEvents) {
      const eventDate = new Date(event.date)
      const monthsUntilEvent = this.getMonthsBetween(currentDate, eventDate)
      const remainingToSave = event.estimatedExpense - (event.currentSavings || 0)

      if (remainingToSave > 0 && monthsUntilEvent >= this.minMonthsForSaving) {
        const monthlySavingsForEvent = Math.ceil(remainingToSave / monthsUntilEvent)
        const expectedSavings = this.getExpectedSavings(event, currentDate)
        const isOnTrack = (event.currentSavings || 0) >= expectedSavings

        eventBreakdown.push({
          eventId: event._id || event.id,
          eventName: event.name,
          eventDate: eventDate,
          category: event.category,
          icon: event.icon,
          totalExpense: event.estimatedExpense,
          currentSavings: event.currentSavings || 0,
          remainingToSave,
          monthsRemaining: monthsUntilEvent,
          daysRemaining: getDaysUntilEvent(eventDate),
          monthlySavingsRequired: monthlySavingsForEvent,
          percentageComplete: Math.round(((event.currentSavings || 0) / event.estimatedExpense) * 100),
          isOnTrack,
          priority: event.priority || 'medium',
          status: event.status || 'upcoming',
          progressStatus: this.getProgressStatus(event, currentDate)
        })

        totalRequiredSavings += monthlySavingsForEvent
      } else if (remainingToSave > 0 && monthsUntilEvent < this.minMonthsForSaving) {
        // Event is too close, mark as urgent
        eventBreakdown.push({
          eventId: event._id || event.id,
          eventName: event.name,
          eventDate: eventDate,
          category: event.category,
          icon: event.icon,
          totalExpense: event.estimatedExpense,
          currentSavings: event.currentSavings || 0,
          remainingToSave,
          monthsRemaining: monthsUntilEvent,
          daysRemaining: getDaysUntilEvent(eventDate),
          monthlySavingsRequired: remainingToSave,
          percentageComplete: Math.round(((event.currentSavings || 0) / event.estimatedExpense) * 100),
          isOnTrack: false,
          priority: 'critical',
          status: 'urgent',
          progressStatus: 'behind'
        })

        totalRequiredSavings += remainingToSave
      }
    }

    // Sort by urgency (months remaining + priority)
    eventBreakdown.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      const priorityDiff = priorityOrder[a.priority] - priorityOrder[b.priority]
      if (priorityDiff !== 0) return priorityDiff
      return a.monthsRemaining - b.monthsRemaining
    })

    const percentageOfIncome = monthlyIncome > 0
      ? ((totalRequiredSavings / monthlyIncome) * 100).toFixed(1)
      : 0

    return {
      totalMonthlySavingsRequired: totalRequiredSavings,
      percentageOfIncome: parseFloat(percentageOfIncome),
      eventBreakdown,
      eventCount: eventBreakdown.length,
      recommendation: this.generateSavingsRecommendation(totalRequiredSavings, monthlyIncome),
      isAffordable: totalRequiredSavings <= (monthlyIncome * 0.25),
      suggestedPrioritization: this.prioritizeEvents(eventBreakdown, monthlyIncome),
      summary: this.generateSummary(eventBreakdown, totalRequiredSavings, monthlyIncome)
    }
  }

  /**
   * Get upcoming events filtered and sorted
   */
  getUpcomingEventsFiltered(events, monthsAhead = 12, currentDate = new Date()) {
    const futureDate = new Date(currentDate)
    futureDate.setMonth(futureDate.getMonth() + monthsAhead)

    return events.filter(event => {
      const eventDate = new Date(event.date)
      return eventDate >= currentDate &&
             eventDate <= futureDate &&
             event.status !== 'completed' &&
             event.status !== 'skipped'
    }).sort((a, b) => new Date(a.date) - new Date(b.date))
  }

  /**
   * Calculate months between two dates
   */
  getMonthsBetween(startDate, endDate) {
    const start = new Date(startDate)
    const end = new Date(endDate)
    const months = (end.getFullYear() - start.getFullYear()) * 12 +
                   (end.getMonth() - start.getMonth())
    return Math.max(0, months)
  }

  /**
   * Get expected savings at this point in time
   */
  getExpectedSavings(event, currentDate) {
    const eventDate = new Date(event.date)
    const createdDate = new Date(event.createdAt || currentDate)

    const totalMonths = this.getMonthsBetween(createdDate, eventDate)
    const monthsElapsed = this.getMonthsBetween(createdDate, currentDate)

    if (totalMonths === 0) return event.estimatedExpense

    const progressRatio = monthsElapsed / totalMonths
    return Math.round(event.estimatedExpense * progressRatio)
  }

  /**
   * Get progress status for an event
   */
  getProgressStatus(event, currentDate) {
    const expected = this.getExpectedSavings(event, currentDate)
    const actual = event.currentSavings || 0
    const percentage = expected > 0 ? (actual / expected) * 100 : 100

    if (percentage >= 100) return 'on_track'
    if (percentage >= 75) return 'slightly_behind'
    if (percentage >= 50) return 'behind'
    return 'significantly_behind'
  }

  /**
   * Generate savings recommendation based on capacity
   */
  generateSavingsRecommendation(requiredSavings, monthlyIncome) {
    if (monthlyIncome === 0) {
      return {
        status: 'unknown',
        message: 'Add your income to get personalized recommendations.',
        actionItems: ['Complete your profile with income details']
      }
    }

    const percentage = (requiredSavings / monthlyIncome) * 100

    if (percentage <= 10) {
      return {
        status: 'comfortable',
        statusColor: 'green',
        message: `Great news! You only need ${percentage.toFixed(1)}% of your income for seasonal savings.`,
        actionItems: [
          'Continue your current savings plan',
          'Consider investing the surplus',
          'Build additional emergency fund'
        ]
      }
    } else if (percentage <= 20) {
      return {
        status: 'manageable',
        statusColor: 'blue',
        message: `Saving ${percentage.toFixed(1)}% for seasonal events is achievable with discipline.`,
        actionItems: [
          'Set up automatic monthly transfers',
          'Track spending in discretionary categories',
          'Look for early-bird deals on planned purchases'
        ]
      }
    } else if (percentage <= 30) {
      return {
        status: 'challenging',
        statusColor: 'yellow',
        message: `At ${percentage.toFixed(1)}%, you may need to prioritize some events.`,
        actionItems: [
          'Prioritize critical events first',
          'Consider reducing expense estimates',
          'Look for ways to increase income',
          'Cut non-essential expenses temporarily'
        ]
      }
    } else {
      return {
        status: 'needs_adjustment',
        statusColor: 'red',
        message: `${percentage.toFixed(1)}% is quite high. Consider adjusting your plans.`,
        actionItems: [
          'Spread events over a longer period',
          'Reduce expense estimates significantly',
          'Skip or scale down some events',
          'Focus only on critical celebrations',
          'Explore loan options only as last resort'
        ]
      }
    }
  }

  /**
   * Prioritize events when savings capacity is limited
   */
  prioritizeEvents(eventBreakdown, monthlyIncome) {
    const maxMonthlySavings = monthlyIncome * 0.25 // Max 25% for seasonal
    const totalRequired = eventBreakdown.reduce((sum, e) => sum + e.monthlySavingsRequired, 0)

    if (totalRequired <= maxMonthlySavings) {
      return {
        strategy: 'full',
        message: 'You can fully fund all upcoming events!',
        events: eventBreakdown,
        totalAllocated: totalRequired
      }
    }

    // Prioritize by: 1) Priority level, 2) Urgency (months), 3) Amount
    const prioritized = [...eventBreakdown].sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
        return priorityOrder[a.priority] - priorityOrder[b.priority]
      }
      return a.monthsRemaining - b.monthsRemaining
    })

    let allocatedSavings = 0
    const fullyFunded = []
    const partiallyFunded = []
    const deferred = []

    for (const event of prioritized) {
      if (allocatedSavings + event.monthlySavingsRequired <= maxMonthlySavings) {
        allocatedSavings += event.monthlySavingsRequired
        fullyFunded.push({ ...event, fundingStatus: 'full', allocatedAmount: event.monthlySavingsRequired })
      } else if (allocatedSavings < maxMonthlySavings) {
        const remaining = maxMonthlySavings - allocatedSavings
        allocatedSavings = maxMonthlySavings
        partiallyFunded.push({
          ...event,
          fundingStatus: 'partial',
          allocatedAmount: remaining,
          shortfall: event.monthlySavingsRequired - remaining
        })
      } else {
        deferred.push({ ...event, fundingStatus: 'deferred', allocatedAmount: 0 })
      }
    }

    return {
      strategy: 'prioritized',
      message: `Limited budget - prioritizing ${fullyFunded.length} event(s) fully.`,
      totalAllocated: allocatedSavings,
      maxAvailable: maxMonthlySavings,
      fullyFunded,
      partiallyFunded,
      deferred,
      recommendations: this.getDeferralRecommendations(deferred)
    }
  }

  /**
   * Get recommendations for deferred events
   */
  getDeferralRecommendations(deferredEvents) {
    if (deferredEvents.length === 0) return []

    const recommendations = []

    for (const event of deferredEvents) {
      if (event.category === 'festival') {
        recommendations.push({
          eventName: event.eventName,
          suggestion: 'Consider celebrating with a smaller budget this year',
          alternativeAmount: Math.round(event.totalExpense * 0.5)
        })
      } else if (event.category === 'education') {
        recommendations.push({
          eventName: event.eventName,
          suggestion: 'Explore education loans or payment plans',
          alternativeAmount: null
        })
      } else {
        recommendations.push({
          eventName: event.eventName,
          suggestion: 'Postpone or reduce scope if possible',
          alternativeAmount: Math.round(event.totalExpense * 0.7)
        })
      }
    }

    return recommendations
  }

  /**
   * Calculate seasonal reserve for budget integration
   */
  calculateSeasonalReserve(monthlyIncome, seasonalPlanningPreferences, upcomingEvents) {
    const userPreferredPercent = seasonalPlanningPreferences?.seasonalReservePercentage || 10

    // Calculate actual required based on upcoming events
    const savingsAnalysis = this.calculateMonthlySavingsRequired(upcomingEvents, monthlyIncome)

    // Use higher of: user preference or actual requirement (capped at 20%)
    const actualRequired = Math.min(
      Math.max(
        (monthlyIncome * userPreferredPercent / 100),
        savingsAnalysis.totalMonthlySavingsRequired
      ),
      monthlyIncome * this.maxSeasonalReservePercent / 100
    )

    const surplus = actualRequired - savingsAnalysis.totalMonthlySavingsRequired

    return {
      reserveAmount: Math.round(actualRequired),
      percentageOfIncome: parseFloat(((actualRequired / monthlyIncome) * 100).toFixed(1)),
      breakdown: savingsAnalysis.eventBreakdown.slice(0, 5), // Top 5 events
      surplus: Math.round(surplus),
      recommendation: surplus < 0
        ? 'Consider increasing seasonal savings or reducing event budgets'
        : 'Your seasonal savings are on track',
      isAdequate: surplus >= 0
    }
  }

  /**
   * Generate event reminders
   */
  generateReminders(events, currentDate = new Date()) {
    const reminders = []

    for (const event of events) {
      if (event.status === 'completed' || event.status === 'skipped') continue

      const eventDate = new Date(event.date)
      const daysUntilEvent = getDaysUntilEvent(eventDate)

      if (daysUntilEvent < 0) continue // Event has passed

      const reminderSettings = event.reminderSettings || { enabled: true, reminderDays: [30, 14, 7, 1] }

      if (reminderSettings.enabled && reminderSettings.reminderDays) {
        for (const reminderDay of reminderSettings.reminderDays) {
          if (daysUntilEvent === reminderDay) {
            const savingsProgress = event.estimatedExpense > 0
              ? ((event.currentSavings || 0) / event.estimatedExpense * 100).toFixed(0)
              : 0

            reminders.push({
              eventId: event._id || event.id,
              eventName: event.name,
              eventDate: eventDate,
              category: event.category,
              icon: event.icon,
              daysUntil: daysUntilEvent,
              message: this.generateReminderMessage(event, daysUntilEvent, savingsProgress),
              priority: this.getReminderPriority(daysUntilEvent, event.priority),
              savingsStatus: {
                current: event.currentSavings || 0,
                target: event.estimatedExpense,
                progress: parseFloat(savingsProgress),
                remaining: event.estimatedExpense - (event.currentSavings || 0)
              },
              actionItems: this.getReminderActionItems(event, daysUntilEvent, savingsProgress)
            })
          }
        }
      }
    }

    return reminders.sort((a, b) => a.daysUntil - b.daysUntil)
  }

  /**
   * Generate reminder message
   */
  generateReminderMessage(event, daysUntil, savingsProgress) {
    const isOnTrack = parseFloat(savingsProgress) >= 75

    if (daysUntil <= 3) {
      return `🚨 ${event.name} is in ${daysUntil} day(s)! ${isOnTrack ? 'You\'re ready!' : 'Final savings push needed.'}`
    } else if (daysUntil <= 7) {
      return `⏰ ${event.name} is in ${daysUntil} days. You've saved ${savingsProgress}% of your target.`
    } else if (daysUntil <= 14) {
      return `📅 ${event.name} is in 2 weeks. Currently at ${savingsProgress}% of savings goal.`
    } else if (daysUntil <= 30) {
      return `💰 ${event.name} is coming up in ${daysUntil} days. Time to boost your savings!`
    } else {
      const monthsUntil = Math.ceil(daysUntil / 30)
      return `📆 ${event.name} is ${monthsUntil} month(s) away. Stay on track with your savings plan.`
    }
  }

  /**
   * Get reminder priority
   */
  getReminderPriority(daysUntil, eventPriority) {
    if (daysUntil <= 3) return 'critical'
    if (daysUntil <= 7 || eventPriority === 'critical') return 'high'
    if (daysUntil <= 14 || eventPriority === 'high') return 'medium'
    return 'low'
  }

  /**
   * Get action items for reminder
   */
  getReminderActionItems(event, daysUntil, savingsProgress) {
    const items = []
    const progress = parseFloat(savingsProgress)

    if (progress < 50) {
      items.push(`Save ₹${Math.round((event.estimatedExpense - (event.currentSavings || 0)) / Math.max(1, Math.ceil(daysUntil / 30)))} this month`)
    }

    if (daysUntil <= 14 && event.category === 'festival') {
      items.push('Start shopping for gifts and essentials')
      items.push('Compare prices online before buying')
    }

    if (daysUntil <= 7) {
      items.push('Finalize your budget breakdown')
      items.push('Make a shopping list to avoid overspending')
    }

    if (progress >= 100) {
      items.push('You\'ve reached your savings goal! Enjoy responsibly.')
    }

    return items
  }

  /**
   * Generate summary for display
   */
  generateSummary(eventBreakdown, totalSavings, monthlyIncome) {
    const onTrackCount = eventBreakdown.filter(e => e.isOnTrack).length
    const behindCount = eventBreakdown.length - onTrackCount
    const next3Months = eventBreakdown.filter(e => e.monthsRemaining <= 3)

    return {
      totalEvents: eventBreakdown.length,
      onTrack: onTrackCount,
      behind: behindCount,
      upcomingIn3Months: next3Months.length,
      totalMonthlySavings: totalSavings,
      percentOfIncome: monthlyIncome > 0 ? ((totalSavings / monthlyIncome) * 100).toFixed(1) : 0,
      nextEvent: eventBreakdown[0] || null
    }
  }

  /**
   * Create event from prebuilt template
   */
  createFromPrebuilt(prebuiltEventId, userProfile, customizations = {}) {
    const template = getEventById(prebuiltEventId)
    if (!template) return null

    const estimatedExpense = customizations.estimatedExpense ||
                            estimateEventExpense(prebuiltEventId, userProfile)

    const nextDate = template.getNextDate()
    if (!nextDate) return null

    return {
      eventType: 'prebuilt',
      prebuiltEventId: prebuiltEventId,
      name: customizations.name || template.name,
      description: template.description,
      category: template.category,
      icon: template.icon,
      date: customizations.date || nextDate,
      isRecurring: template.isRecurring || false,
      recurringPattern: template.recurringPattern || 'yearly',
      estimatedExpense: estimatedExpense,
      currentSavings: customizations.currentSavings || 0,
      priority: customizations.priority || 'medium',
      reminderSettings: {
        enabled: true,
        reminderDays: [30, 14, 7, 1]
      },
      status: 'upcoming',
      notes: customizations.notes || '',
      createdAt: new Date()
    }
  }

  /**
   * Get suggested prebuilt events for a user
   */
  getSuggestedEvents(userProfile, region = null) {
    const suggestions = []
    const now = new Date()
    const sixMonthsLater = new Date(now)
    sixMonthsLater.setMonth(sixMonthsLater.getMonth() + 6)

    // Get upcoming prebuilt events
    const upcomingPrebuilt = getUpcomingEvents(6, region)

    for (const event of upcomingPrebuilt) {
      const estimatedExpense = estimateEventExpense(event.id, userProfile)
      const daysUntil = getDaysUntilEvent(event.date)
      const monthsUntil = getMonthsUntilEvent(event.date)

      suggestions.push({
        ...event,
        estimatedExpense,
        monthlySavingsNeeded: monthsUntil > 0 ? Math.ceil(estimatedExpense / monthsUntil) : estimatedExpense,
        daysUntil,
        monthsUntil,
        formattedDate: formatEventDate(event.date),
        isUrgent: monthsUntil <= 2
      })
    }

    // Sort by date
    suggestions.sort((a, b) => a.daysUntil - b.daysUntil)

    return suggestions
  }

  /**
   * Add savings to an event
   */
  addSavingsToEvent(event, amount) {
    const newSavings = (event.currentSavings || 0) + amount
    const percentComplete = (newSavings / event.estimatedExpense) * 100

    return {
      ...event,
      currentSavings: newSavings,
      percentComplete: Math.min(100, Math.round(percentComplete)),
      isComplete: newSavings >= event.estimatedExpense
    }
  }
}

// Export singleton instance
export const seasonalPlanner = new SeasonalPlanner()

// Export class for testing
export default SeasonalPlanner
