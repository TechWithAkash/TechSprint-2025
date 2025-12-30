// lib/agents/SpendingPatternAgent.js - Autonomous Spending Behavior Monitor
import { BaseAgent } from './BaseAgent.js'
import { eventBus, EVENTS } from '../events/EventBus.js'

/**
 * Spending Pattern Agent - Learns and monitors spending behavior
 * Autonomous Features:
 * - Detects spending patterns and triggers
 * - Proactive intervention BEFORE overspending
 * - Anomaly detection
 * - Behavioral learning
 */
export class SpendingPatternAgent extends BaseAgent {
    constructor(config = {}) {
        super('SpendingPatternAgent', config)
        this.patterns = new Map() // userId -> patterns
        this.interventionThreshold = config.interventionThreshold || 0.8
    }

    /**
     * Register event handlers
     */
    registerEventHandlers() {
        // Listen for expense additions
        eventBus.on(EVENTS.EXPENSE_ADDED, (data) => this.handleExpenseAdded(data))

        // Listen for voice expenses (higher intervention priority)
        eventBus.on(EVENTS.VOICE_EXPENSE_DETECTED, (data) => this.handleVoiceExpense(data))
    }

    /**
     * Handle new expense
     */
    async handleExpenseAdded(data) {
        console.log('🧠 SpendingPatternAgent: Analyzing new expense...', data)

        // Emit user-friendly activity
        eventBus.emit(EVENTS.AGENT_ACTION, {
            agent: 'Spending Agent',
            action: `Analyzed ${data.category} expense of ₹${data.amount.toLocaleString('en-IN')}${data.description ? ` for "${data.description}"` : ''}. Monthly ${data.category} total: ₹${(data.monthlyTotal || data.amount).toLocaleString('en-IN')}`,
            confidence: 0.92,
            timestamp: new Date()
        })

        // Learn from this transaction
        await this.learnPattern(data)

        // Check if intervention needed
        const shouldIntervene = await this.shouldIntervene(data)

        if (shouldIntervene.intervene) {
            await this.proactiveIntervention(data, shouldIntervene)
        }

        // Detect anomalies
        const anomaly = await this.detectAnomaly(data)

        if (anomaly.isAnomaly) {
            eventBus.emit(EVENTS.ANOMALY_DETECTED, {
                userId: data.userId,
                expense: data,
                anomaly
            })

            // User-friendly alert
            eventBus.emit(EVENTS.AGENT_ALERT, {
                agent: 'Spending Agent',
                message: `Unusual ${data.category} expense detected: ₹${data.amount.toLocaleString('en-IN')} is ${Math.round(anomaly.zScore * 100)}% higher than your average. Is everything okay?`,
                severity: 'warning',
                timestamp: new Date()
            })
        }
    }

    /**
     * Learn spending patterns from transaction
     */
    async learnPattern(transaction) {
        const { userId, amount, category, date } = transaction

        if (!this.patterns.has(userId)) {
            this.patterns.set(userId, {
                byCategory: {},
                byDayOfWeek: {},
                byTimeOfDay: {},
                byLocation: {},
                triggers: []
            })
        }

        const userPatterns = this.patterns.get(userId)
        const transactionDate = new Date(date)
        const dayOfWeek = transactionDate.getDay()
        const hour = transactionDate.getHours()

        // Category patterns
        if (!userPatterns.byCategory[category]) {
            userPatterns.byCategory[category] = {
                count: 0,
                totalAmount: 0,
                averageAmount: 0,
                transactions: []
            }
        }

        userPatterns.byCategory[category].count++
        userPatterns.byCategory[category].totalAmount += amount
        userPatterns.byCategory[category].averageAmount =
            userPatterns.byCategory[category].totalAmount / userPatterns.byCategory[category].count
        userPatterns.byCategory[category].transactions.push({
            amount,
            date,
            dayOfWeek,
            hour
        })

        // Day of week patterns
        if (!userPatterns.byDayOfWeek[dayOfWeek]) {
            userPatterns.byDayOfWeek[dayOfWeek] = {
                count: 0,
                totalAmount: 0,
                averageAmount: 0
            }
        }

        userPatterns.byDayOfWeek[dayOfWeek].count++
        userPatterns.byDayOfWeek[dayOfWeek].totalAmount += amount
        userPatterns.byDayOfWeek[dayOfWeek].averageAmount =
            userPatterns.byDayOfWeek[dayOfWeek].totalAmount / userPatterns.byDayOfWeek[dayOfWeek].count

        // Time of day patterns
        const timeSlot = this.getTimeSlot(hour)
        if (!userPatterns.byTimeOfDay[timeSlot]) {
            userPatterns.byTimeOfDay[timeSlot] = {
                count: 0,
                totalAmount: 0,
                categories: {}
            }
        }

        userPatterns.byTimeOfDay[timeSlot].count++
        userPatterns.byTimeOfDay[timeSlot].totalAmount += amount

        // Detect triggers
        await this.detectSpendingTriggers(userId, transaction, userPatterns)

        console.log(`📚 Pattern learned: ${category} on ${this.getDayName(dayOfWeek)} (Avg: ₹${Math.round(userPatterns.byCategory[category].averageAmount)})`)
    }

    /**
     * Detect spending triggers
     */
    async detectSpendingTriggers(userId, transaction, patterns) {
        const { category, amount, date } = transaction
        const transactionDate = new Date(date)
        const dayOfWeek = transactionDate.getDay()
        const hour = transactionDate.getHours()

        // Pattern 1: Weekend overspending
        if ((dayOfWeek === 0 || dayOfWeek === 6) && category === 'food_dining') {
            const weekendPattern = patterns.byCategory['food_dining']?.transactions.filter(t => {
                const d = new Date(t.date).getDay()
                return d === 0 || d === 6
            })

            if (weekendPattern && weekendPattern.length > 3) {
                const avgWeekendSpending = weekendPattern.reduce((sum, t) => sum + t.amount, 0) / weekendPattern.length

                if (avgWeekendSpending > 800) {
                    patterns.triggers.push({
                        type: 'WEEKEND_FOOD_SPLURGE',
                        description: 'Tendency to overspend on food during weekends',
                        averageAmount: avgWeekendSpending,
                        frequency: weekendPattern.length,
                        confidence: 0.85,
                        intervention: {
                            message: `🤔 Weekend food spending pattern detected. Average: ₹${Math.round(avgWeekendSpending)}`,
                            suggestion: 'Consider cooking at home on weekends to save ₹2,000+/month'
                        }
                    })
                }
            }
        }

        // Pattern 2: Late night impulse spending
        if (hour >= 20 || hour <= 2) {
            const lateNightTxns = Object.values(patterns.byCategory).reduce((count, cat) => {
                const lateNight = cat.transactions.filter(t => {
                    const h = new Date(t.date).getHours()
                    return h >= 20 || h <= 2
                })
                return count + lateNight.length
            }, 0)

            if (lateNightTxns > 5) {
                patterns.triggers.push({
                    type: 'LATE_NIGHT_IMPULSE',
                    description: 'Impulse spending late at night',
                    frequency: lateNightTxns,
                    confidence: 0.75,
                    intervention: {
                        message: '🌙 Late night spending detected. Sleep on it?',
                        suggestion: 'Wait till morning - 60% of late-night purchases are regretted'
                    }
                })
            }
        }

        // Pattern 3: Friday payday splurge
        if (dayOfWeek === 5 && amount > 1000) {
            patterns.triggers.push({
                type: 'FRIDAY_SPLURGE',
                description: 'Large expenses on Fridays (possibly payday)',
                averageAmount: amount,
                confidence: 0.7,
                intervention: {
                    message: '💸 Friday spending spike!',
                    suggestion: 'Set aside savings first before discretionary spending'
                }
            })
        }
    }

    /**
     * Should we intervene?
     */
    async shouldIntervene(transaction) {
        const { userId, amount, category, date } = transaction
        const patterns = this.patterns.get(userId)

        if (!patterns || !patterns.byCategory[category]) {
            return { intervene: false, reason: 'Not enough pattern data' }
        }

        const categoryPattern = patterns.byCategory[category]
        const todayDate = new Date(date)

        // Get today's spending in this category
        const todaySpending = categoryPattern.transactions
            .filter(t => {
                const txDate = new Date(t.date)
                return txDate.toDateString() === todayDate.toDateString()
            })
            .reduce((sum, t) => sum + t.amount, 0)

        // Intervention Rule 1: Exceeding daily average by 2x
        if (todaySpending > categoryPattern.averageAmount * 2) {
            return {
                intervene: true,
                reason: 'EXCEEDING_AVERAGE',
                message: `⚠️ You've already spent ₹${Math.round(todaySpending)} on ${category} today.\nYour average: ₹${Math.round(categoryPattern.averageAmount)}`,
                confidence: 0.9
            }
        }

        // Intervention Rule 2: Multiple transactions in short time
        const recentTxns = categoryPattern.transactions
            .filter(t => {
                const diff = new Date(date) - new Date(t.date)
                return diff < 3600000 // Last 1 hour
            })

        if (recentTxns.length >= 3) {
            return {
                intervene: true,
                reason: 'RAPID_SPENDING',
                message: '⚠️ This is your 3rd purchase in 1 hour. Take a breath?',
                confidence: 0.85
            }
        }

        // Intervention Rule 3: Known trigger detected
        const activeTrigger = patterns.triggers.find(t => {
            const txDate = new Date(date)
            if (t.type === 'WEEKEND_FOOD_SPLURGE' && (txDate.getDay() === 0 || txDate.getDay() === 6)) {
                return true
            }
            if (t.type === 'LATE_NIGHT_IMPULSE' && (txDate.getHours() >= 20 || txDate.getHours() <= 2)) {
                return true
            }
            return false
        })

        if (activeTrigger) {
            return {
                intervene: true,
                reason: 'TRIGGER_DETECTED',
                trigger: activeTrigger,
                message: activeTrigger.intervention.message,
                suggestion: activeTrigger.intervention.suggestion,
                confidence: activeTrigger.confidence
            }
        }

        return { intervene: false }
    }

    /**
     * Proactive intervention
     */
    async proactiveIntervention(transaction, interventionData) {
        const { userId, amount, category } = transaction

        console.log('🚨 PROACTIVE INTERVENTION TRIGGERED!')

        // Emit intervention alert
        eventBus.emit(EVENTS.AGENT_ALERT, {
            agent: 'SpendingPatternAgent',
            userId,
            type: 'PROACTIVE_INTERVENTION',
            priority: 'HIGH',
            intervention: {
                transaction,
                reason: interventionData.reason,
                message: interventionData.message,
                suggestion: interventionData.suggestion,
                alternatives: this.suggestAlternatives(transaction),
                timestamp: new Date()
            }
        })

        return {
            type: 'PROACTIVE_ALERT',
            message: interventionData.message,
            suggestion: interventionData.suggestion,
            timing: 'BEFORE_CONFIRMATION',
            alternatives: this.suggestAlternatives(transaction)
        }
    }

    /**
     * Suggest cheaper alternatives
     */
    suggestAlternatives(transaction) {
        const { category, amount } = transaction

        const alternatives = []

        if (category === 'food_dining') {
            alternatives.push(
                { action: 'Cook at home', savings: Math.round(amount * 0.7), effort: 'Medium', impact: 'High' },
                { action: 'Eat at local dhaba/mess', savings: Math.round(amount * 0.5), effort: 'Low', impact: 'Medium' },
                { action: 'Order smaller portion', savings: Math.round(amount * 0.3), effort: 'Low', impact: 'Low' }
            )
        } else if (category === 'transportation') {
            alternatives.push(
                { action: 'Take public transport', savings: Math.round(amount * 0.6), effort: 'Low', impact: 'High' },
                { action: 'Carpool/bike pool', savings: Math.round(amount * 0.4), effort: 'Medium', impact: 'Medium' }
            )
        } else if (category === 'shopping') {
            alternatives.push(
                { action: 'Wait 24 hours (impulse check)', savings: amount, effort: 'Low', impact: 'High' },
                { action: 'Buy during sale/discount', savings: Math.round(amount * 0.3), effort: 'Medium', impact: 'Medium' },
                { action: 'Buy used/refurbished', savings: Math.round(amount * 0.5), effort: 'Medium', impact: 'High' }
            )
        }

        return alternatives
    }

    /**
     * Detect anomalies
     */
    async detectAnomaly(transaction) {
        const { userId, amount, category } = transaction
        const patterns = this.patterns.get(userId)

        if (!patterns || !patterns.byCategory[category]) {
            return { isAnomaly: false }
        }

        const categoryPattern = patterns.byCategory[category]
        const average = categoryPattern.averageAmount
        const transactions = categoryPattern.transactions.map(t => t.amount)

        // Calculate standard deviation
        const variance = transactions.reduce((sum, val) =>
            sum + Math.pow(val - average, 2), 0) / transactions.length
        const stdDev = Math.sqrt(variance)

        // Z-score method: More than 2 standard deviations is anomaly
        const zScore = (amount - average) / stdDev

        if (Math.abs(zScore) > 2) {
            console.log(`🚨 ANOMALY DETECTED: ₹${amount} on ${category} (Z-score: ${zScore.toFixed(2)})`)

            return {
                isAnomaly: true,
                severity: Math.abs(zScore) > 3 ? 'HIGH' : 'MEDIUM',
                zScore,
                message: `⚠️ Unusual spending detected!\n₹${amount} on ${category}\nYour average: ₹${Math.round(average)}`,
                requireConfirmation: true,
                possibleReasons: this.getPossibleReasons(category, amount, average)
            }
        }

        return { isAnomaly: false }
    }

    /**
     * Get possible reasons for anomaly
     */
    getPossibleReasons(category, amount, average) {
        const multiplier = amount / average

        const reasons = []

        if (multiplier > 3) {
            reasons.push('One-time expense (Wedding/Emergency)')
            reasons.push('Bulk purchase')
            reasons.push('Multiple items in one transaction')
        } else if (multiplier > 2) {
            reasons.push('Special occasion')
            reasons.push('Impulse purchase')
            reasons.push('Necessary upgrade')
        }

        return reasons
    }

    /**
     * Handle voice expense (higher priority)
     */
    async handleVoiceExpense(data) {
        console.log('🎤 SpendingPatternAgent: Voice expense detected - priority check')

        // Voice expenses get immediate pattern check
        await this.handleExpenseAdded({
            ...data.extracted,
            userId: data.userId,
            source: 'voice'
        })
    }

    /**
     * Get time slot
     */
    getTimeSlot(hour) {
        if (hour >= 6 && hour < 12) return 'morning'
        if (hour >= 12 && hour < 17) return 'afternoon'
        if (hour >= 17 && hour < 21) return 'evening'
        return 'night'
    }

    /**
     * Get day name
     */
    getDayName(dayNum) {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        return days[dayNum]
    }

    /**
     * Get user patterns
     */
    getUserPatterns(userId) {
        return this.patterns.get(userId) || null
    }

    /**
     * Get pattern summary
     */
    getPatternSummary(userId) {
        const patterns = this.patterns.get(userId)

        if (!patterns) {
            return { message: 'No patterns detected yet' }
        }

        return {
            categories: Object.keys(patterns.byCategory).map(cat => ({
                category: cat,
                average: Math.round(patterns.byCategory[cat].averageAmount),
                count: patterns.byCategory[cat].count
            })),
            triggers: patterns.triggers.map(t => ({
                type: t.type,
                description: t.description,
                confidence: t.confidence
            })),
            insights: this.generateInsights(patterns)
        }
    }

    /**
     * Generate insights from patterns
     */
    generateInsights(patterns) {
        const insights = []

        // Find most expensive day
        const daySpending = Object.entries(patterns.byDayOfWeek)
            .sort((a, b) => b[1].averageAmount - a[1].averageAmount)

        if (daySpending.length > 0) {
            insights.push({
                type: 'EXPENSIVE_DAY',
                message: `Your most expensive day is ${this.getDayName(parseInt(daySpending[0][0]))} (Avg: ₹${Math.round(daySpending[0][1].averageAmount)})`
            })
        }

        // Find most frequent category
        const categorySpending = Object.entries(patterns.byCategory)
            .sort((a, b) => b[1].count - a[1].count)

        if (categorySpending.length > 0) {
            insights.push({
                type: 'FREQUENT_CATEGORY',
                message: `You spend most often on ${categorySpending[0][0]} (${categorySpending[0][1].count} transactions)`
            })
        }

        return insights
    }

    /**
     * Get required fields
     */
    getRequiredFields() {
        return ['userId', 'amount', 'category', 'date']
    }
}

// Singleton instance
export const spendingPatternAgent = new SpendingPatternAgent()
