// lib/agents/IncomeAgent.js - Autonomous Income Variability Handler
import { BaseAgent } from './BaseAgent.js'
import { eventBus, EVENTS } from '../events/EventBus.js'

/**
 * Income Agent - Handles income variability for gig workers
 * Autonomous Features:
 * - Detects income variability patterns
 * - Creates adaptive "flex budgets"
 * - Predicts low-income periods
 * - Proactively adjusts spending limits
 */
export class IncomeAgent extends BaseAgent {
    constructor(config = {}) {
        super('IncomeAgent', config)
        this.variabilityThreshold = config.variabilityThreshold || 0.3
        this.predictionWindow = config.predictionWindow || 90 // days
    }

    /**
     * Register event handlers
     */
    registerEventHandlers() {
        // Listen for new income entries
        eventBus.on(EVENTS.INCOME_ADDED, (data) => this.handleIncomeAdded(data))

        // Listen for budget creation to analyze income patterns
        eventBus.on(EVENTS.BUDGET_CREATED, (data) => this.analyzeBudgetIncome(data))
    }

    /**
     * Handle new income entry
     */
    async handleIncomeAdded(data) {
        console.log('💰 IncomeAgent: Processing new income entry', data)

        // Emit user-friendly activity
        eventBus.emit(EVENTS.AGENT_ACTION, {
            agent: 'Income Agent',
            action: `Recorded income of ₹${data.amount.toLocaleString('en-IN')}${data.source ? ` from ${data.source}` : ''}. Analyzing income stability...`,
            confidence: 0.95,
            timestamp: new Date()
        })

        const analysis = await this.analyzeIncomeVariability(data.userId)

        if (analysis.isVariable) {
            // Emit variability detection event
            eventBus.emit(EVENTS.INCOME_VARIABILITY_DETECTED, {
                userId: data.userId,
                variabilityScore: analysis.variabilityScore,
                recommendation: analysis.recommendation
            })

            // User-friendly insight
            const variabilityPercent = Math.round(analysis.variabilityScore * 100)
            eventBus.emit(EVENTS.AGENT_RECOMMENDATION, {
                agent: 'Income Agent',
                recommendation: `Your income varies by ${variabilityPercent}% month-to-month${variabilityPercent > 30 ? ' (high variability)' : ' (moderate)'}. ${analysis.recommendation}`,
                impact: variabilityPercent > 30 ? 'high' : 'medium',
                timestamp: new Date()
            })

            // Take autonomous action if high variability
            if (analysis.variabilityScore > 0.5) {
                await this.createFlexBudget(data.userId, analysis)
            }
        } else {
            // Stable income - positive feedback
            eventBus.emit(EVENTS.AGENT_RECOMMENDATION, {
                agent: 'Income Agent',
                recommendation: `Great! Your income is stable. This makes budgeting easier. Consider automating your savings.`,
                impact: 'low',
                timestamp: new Date()
            })
        }
    }

    /**
     * Analyze income variability for a user
     */
    async analyzeIncomeVariability(userId) {
        try {
            // Fetch income history (last 90 days)
            const incomeHistory = await this.getIncomeHistory(userId, this.predictionWindow)

            if (incomeHistory.length < 3) {
                return {
                    isVariable: false,
                    variabilityScore: 0,
                    message: 'Not enough income data to analyze'
                }
            }

            // Calculate variability metrics
            const amounts = incomeHistory.map(i => i.amount)
            const mean = amounts.reduce((a, b) => a + b, 0) / amounts.length
            const variance = amounts.reduce((sum, val) =>
                sum + Math.pow(val - mean, 2), 0) / amounts.length
            const stdDev = Math.sqrt(variance)

            // Coefficient of variation (CV) - standard measure of variability
            const variabilityScore = stdDev / mean

            const isVariable = variabilityScore > this.variabilityThreshold

            console.log(`📊 Income Analysis:
        Mean: ₹${Math.round(mean)}
        Std Dev: ₹${Math.round(stdDev)}
        Variability Score: ${(variabilityScore * 100).toFixed(1)}%
        Status: ${isVariable ? 'VARIABLE (Gig Worker Pattern)' : 'STABLE'}
      `)

            return {
                isVariable,
                variabilityScore,
                mean,
                stdDev,
                min: Math.min(...amounts),
                max: Math.max(...amounts),
                incomeHistory,
                recommendation: this.getRecommendation(variabilityScore, mean)
            }
        } catch (error) {
            console.error('IncomeAgent: Error analyzing variability:', error)
            return { isVariable: false, variabilityScore: 0, error: error.message }
        }
    }

    /**
     * Get recommendation based on variability
     */
    getRecommendation(variabilityScore, meanIncome) {
        if (variabilityScore > 0.5) {
            return {
                type: 'HIGH_VARIABILITY',
                title: 'Income Highly Variable Detected',
                message: `Your income varies significantly (${(variabilityScore * 100).toFixed(0)}% variability). 
                  I've activated Flex Budget mode to adapt to your income patterns.`,
                actions: [
                    {
                        action: 'Build Emergency Buffer',
                        target: meanIncome * 0.5, // 2 weeks of average income
                        priority: 'CRITICAL'
                    },
                    {
                        action: 'Save Extra in High-Income Weeks',
                        target: meanIncome * 0.3,
                        priority: 'HIGH'
                    },
                    {
                        action: 'Reduce Discretionary in Low-Income Weeks',
                        percentage: 40,
                        priority: 'MEDIUM'
                    }
                ]
            }
        } else if (variabilityScore > 0.3) {
            return {
                type: 'MODERATE_VARIABILITY',
                title: 'Moderate Income Variability',
                message: `Your income has some variation. Consider building a small buffer.`,
                actions: [
                    {
                        action: 'Build 1-Week Emergency Buffer',
                        target: meanIncome * 0.25,
                        priority: 'MEDIUM'
                    }
                ]
            }
        } else {
            return {
                type: 'STABLE',
                title: 'Stable Income Detected',
                message: 'Your income is stable. Standard budgeting recommended.',
                actions: []
            }
        }
    }

    /**
     * Create adaptive flex budget
     */
    async createFlexBudget(userId, analysis) {
        console.log('🌊 Creating Flex Budget for variable income...')

        const { mean, min, max, variabilityScore } = analysis

        // Flex budget allocations (conservative for variable income)
        const flexBudget = {
            type: 'FLEX_BUDGET',
            strategy: 'income_based_allocation',
            baseIncome: mean,
            incomeRange: { min, max },
            variabilityScore,

            // Core allocations (% of actual income, not budgeted amount)
            allocations: {
                essentials: {
                    percentage: 50, // Fixed essentials (rent, utilities, groceries)
                    description: 'Must-pay items - highest priority',
                    categories: ['housing', 'food_dining', 'healthcare', 'transportation']
                },
                savings: {
                    percentage: 20, // Aggressive savings in good weeks
                    description: 'Emergency buffer + goals',
                    adjustable: true,
                    minPercentage: 10 // Minimum even in low-income weeks
                },
                discretionary: {
                    percentage: 30, // Flexible spending
                    description: 'Entertainment, shopping, etc.',
                    adjustable: true,
                    cutFirst: true // Cut this first in low-income weeks
                }
            },

            // Week-by-week adjustment rules
            weeklyRules: {
                highIncomeWeek: {
                    threshold: mean * 1.2, // 20% above average
                    action: 'SAVE_EXTRA',
                    savingsBoost: 10, // Save extra 10%
                    message: '🎉 Great week! Saving extra for slower weeks ahead'
                },
                lowIncomeWeek: {
                    threshold: mean * 0.7, // 30% below average
                    action: 'REDUCE_DISCRETIONARY',
                    discretionaryCut: 50, // Cut discretionary by 50%
                    message: '⚠️ Low income week. Using buffer. Essentials covered ✅'
                }
            },

            // Proactive alerts
            alerts: [
                {
                    type: 'INCOME_PREDICTION',
                    message: 'Based on your patterns, income may drop next week. Save extra this week!',
                    triggerDays: 7
                }
            ],

            createdAt: new Date(),
            updatedAt: new Date()
        }

        // Emit flex budget creation event
        eventBus.emit(EVENTS.BUDGET_UPDATED, {
            userId,
            budgetType: 'FLEX',
            flexBudget,
            autonomous: true
        })

        console.log('✅ Flex Budget Created:', flexBudget)

        return flexBudget
    }

    /**
     * Predict low-income periods
     */
    async predictLowIncomePeriod(userId) {
        const incomeHistory = await this.getIncomeHistory(userId, 90)

        if (incomeHistory.length < 8) {
            return null
        }

        // Simple pattern detection: Check for weekly/monthly cycles
        const weeklyAverages = this.calculateWeeklyAverages(incomeHistory)
        const prediction = this.detectDownwardTrend(weeklyAverages)

        if (prediction.confidence > 0.75) {
            // Emit prediction event
            eventBus.emit(EVENTS.LOW_INCOME_PERIOD_PREDICTED, {
                userId,
                prediction,
                autonomous: true
            })

            return {
                alert: `⚠️ Next ${prediction.duration} may have ${prediction.drop}% lower income`,
                action: `Save extra ₹${Math.round(prediction.bufferNeeded)} this week as buffer`,
                reasoning: prediction.reasoning,
                confidence: prediction.confidence
            }
        }

        return null
    }

    /**
     * Calculate weekly income averages
     */
    calculateWeeklyAverages(incomeHistory) {
        const weeks = {}

        incomeHistory.forEach(income => {
            const weekNum = this.getWeekNumber(income.date)
            if (!weeks[weekNum]) {
                weeks[weekNum] = { total: 0, count: 0 }
            }
            weeks[weekNum].total += income.amount
            weeks[weekNum].count += 1
        })

        return Object.entries(weeks).map(([week, data]) => ({
            week: parseInt(week),
            average: data.total / data.count,
            total: data.total
        }))
    }

    /**
     * Detect downward trend in income
     */
    detectDownwardTrend(weeklyData) {
        if (weeklyData.length < 4) {
            return { confidence: 0 }
        }

        const recent = weeklyData.slice(-2)
        const previous = weeklyData.slice(-4, -2)

        const recentAvg = recent.reduce((sum, w) => sum + w.average, 0) / recent.length
        const previousAvg = previous.reduce((sum, w) => sum + w.average, 0) / previous.length

        const drop = ((previousAvg - recentAvg) / previousAvg) * 100

        if (drop > 15) {
            return {
                confidence: 0.8,
                drop: Math.round(drop),
                duration: '1-2 weeks',
                bufferNeeded: recentAvg * 0.3,
                reasoning: 'Your income has dropped 15%+ in recent weeks based on historical pattern'
            }
        }

        return { confidence: 0 }
    }

    /**
     * Get week number from date
     */
    getWeekNumber(date) {
        const d = new Date(date)
        d.setHours(0, 0, 0, 0)
        d.setDate(d.getDate() + 4 - (d.getDay() || 7))
        const yearStart = new Date(d.getFullYear(), 0, 1)
        return Math.ceil((((d - yearStart) / 86400000) + 1) / 7)
    }

    /**
     * Get income history from database
     * TODO: Connect to actual database
     */
    async getIncomeHistory(userId, days = 90) {
        // Mock data for demo - replace with actual DB query
        // In production: await Income.find({ userId, date: { $gte: startDate } })

        // For hackathon: Generate realistic gig worker income pattern
        const history = []
        const now = new Date()

        for (let i = 0; i < days; i += 7) {
            const weekDate = new Date(now.getTime() - i * 24 * 60 * 60 * 1000)

            // Simulate variable weekly income (₹6,000 to ₹12,000)
            const baseIncome = 8000
            const variation = (Math.random() - 0.5) * 6000
            const seasonalFactor = Math.sin(i / 30) * 2000 // Seasonal variation

            history.push({
                userId,
                amount: Math.max(4000, baseIncome + variation + seasonalFactor),
                date: weekDate,
                source: 'Gig Work',
                type: 'weekly'
            })
        }

        return history.reverse()
    }

    /**
     * Analyze budget income
     */
    async analyzeBudgetIncome(data) {
        console.log('📊 IncomeAgent: Analyzing budget income...')
        await this.analyzeIncomeVariability(data.userId)
    }

    /**
     * Get required data fields
     */
    getRequiredFields() {
        return ['userId', 'amount', 'date']
    }
}

// Singleton instance
export const incomeAgent = new IncomeAgent()
