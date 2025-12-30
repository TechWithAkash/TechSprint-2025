// lib/notificationService.js
/**
 * Comprehensive Notification Service
 * Handles notification creation, categorization, prioritization, and smart triggers
 * Now includes EMERGENCY priority with email alerts
 *
 * Note: Email sending is handled via API calls to avoid importing server-side
 * modules (nodemailer) in client context.
 */

import { eventBus, EVENTS } from './events'

// Notification Types
export const NOTIFICATION_TYPES = {
    // Financial Alerts
    OVERSPENDING: 'overspending',
    BUDGET_WARNING: 'budget_warning',
    SAVINGS_MILESTONE: 'savings_milestone',
    GOAL_ACHIEVED: 'goal_achieved',
    GOAL_PROGRESS: 'goal_progress',

    // Income & Bills
    INCOME_RECEIVED: 'income_received',
    BILL_DUE: 'bill_due',
    BILL_OVERDUE: 'bill_overdue',
    LOW_BALANCE: 'low_balance',

    // Emergency Alerts (NEW)
    EMERGENCY_LOW_BALANCE: 'emergency_low_balance',
    EMERGENCY_BUDGET_EXCEEDED: 'emergency_budget_exceeded',
    EMERGENCY_UNUSUAL_EXPENSE: 'emergency_unusual_expense',
    EMERGENCY_EMI_RISK: 'emergency_emi_risk',

    // AI Insights
    AI_INSIGHT: 'ai_insight',
    AI_RECOMMENDATION: 'ai_recommendation',
    AI_WARNING: 'ai_warning',
    ANOMALY_DETECTED: 'anomaly_detected',

    // System
    SYSTEM: 'system',
    SUCCESS: 'success',
    INFO: 'info',
    ERROR: 'error'
}

// Notification Priority Levels
export const PRIORITY = {
    EMERGENCY: 'emergency', // Red flashing, sends email, bypasses quiet hours for critical
    CRITICAL: 'critical',    // Red, requires immediate attention
    HIGH: 'high',           // Orange, important but not urgent
    MEDIUM: 'medium',       // Blue, informational
    LOW: 'low'             // Gray, nice to know
}

// Notification Categories
export const CATEGORIES = {
    SPENDING: 'spending',
    SAVINGS: 'savings',
    GOALS: 'goals',
    BILLS: 'bills',
    AI_INSIGHTS: 'ai_insights',
    EMERGENCY: 'emergency',
    SYSTEM: 'system'
}

class NotificationService {
    constructor() {
        this.notifications = []
        this.listeners = []
        this.rules = this.initializeRules()
        this.alertCooldowns = new Map() // Track cooldowns for emergency alerts
        this.setupEventListeners()
    }

    /**
     * Initialize smart notification rules
     */
    initializeRules() {
        return {
            // Spending Rules
            overspendingThreshold: 0.8, // Alert at 80% of budget
            criticalSpendingThreshold: 0.95, // Critical at 95%

            // Goal Rules
            goalMilestones: [0.25, 0.5, 0.75, 1.0], // Celebrate at 25%, 50%, 75%, 100%

            // Bill Rules
            billDueDays: 3, // Alert 3 days before bill due
            billOverdueDays: 1, // Alert after 1 day overdue

            // Balance Rules
            lowBalanceThreshold: 1000, // Alert if balance below ₹1000
            criticalBalanceThreshold: 500, // Critical if below ₹500

            // AI Insight Rules
            anomalyConfidenceThreshold: 0.7, // Show anomalies with >70% confidence
            insightRelevanceThreshold: 0.6, // Show insights with >60% relevance

            // Emergency Alert Rules (NEW)
            emergency: {
                lowBalanceThreshold: 5000,      // Default: Alert if below ₹5000
                criticalBalanceThreshold: 1000, // Default: Critical if below ₹1000
                budgetExceededThreshold: 100,   // Default: Alert when budget is 100% exceeded
                unusualExpenseMultiplier: 3,    // Default: Alert if expense is 3x average
                alertCooldownHours: 4,          // Don't repeat same alert for 4 hours
                quietHoursStart: 22,            // 10 PM
                quietHoursEnd: 7,               // 7 AM
                quietHoursEnabled: true
            }
        }
    }

    /**
     * Setup event listeners for automatic notifications
     */
    setupEventListeners() {
        // Expense added - check for overspending
        eventBus.on(EVENTS.EXPENSE_ADDED, (data) => {
            this.handleExpenseAdded(data)
        })

        // Income received
        eventBus.on(EVENTS.INCOME_RECEIVED, (data) => {
            this.handleIncomeReceived(data)
        })

        // Goal progress
        eventBus.on(EVENTS.GOAL_UPDATED, (data) => {
            this.handleGoalUpdated(data)
        })

        // AI recommendations
        eventBus.on(EVENTS.AGENT_RECOMMENDATION, (data) => {
            this.handleAIRecommendation(data)
        })

        // AI actions
        eventBus.on(EVENTS.AGENT_ACTION, (data) => {
            this.handleAIAction(data)
        })

        // Anomaly detected
        eventBus.on(EVENTS.ANOMALY_DETECTED, (data) => {
            this.handleAnomalyDetected(data)
        })
    }

    /**
     * Handle expense added - check for overspending
     */
    async handleExpenseAdded(data) {
        const { category, amount, monthlyTotal, budgetAmount, userId } = data

        if (!budgetAmount || budgetAmount === 0) return

        const spentPercentage = (monthlyTotal / budgetAmount) * 100

        // Critical overspending (95%+)
        if (spentPercentage >= this.rules.criticalSpendingThreshold * 100) {
            await this.create({
                userId,
                type: NOTIFICATION_TYPES.OVERSPENDING,
                priority: PRIORITY.CRITICAL,
                category: CATEGORIES.SPENDING,
                title: `🚨 Critical: ${category} Budget Exceeded!`,
                message: `You've spent ₹${monthlyTotal.toLocaleString('en-IN')} (${spentPercentage.toFixed(0)}%) of your ₹${budgetAmount.toLocaleString('en-IN')} ${category} budget. Immediate action needed!`,
                actionLabel: 'Review Spending',
                actionUrl: '/dashboard/budget',
                metadata: {
                    category,
                    amount,
                    monthlyTotal,
                    budgetAmount,
                    spentPercentage
                }
            })
        }
        // High overspending warning (80-95%)
        else if (spentPercentage >= this.rules.overspendingThreshold * 100) {
            await this.create({
                userId,
                type: NOTIFICATION_TYPES.BUDGET_WARNING,
                priority: PRIORITY.HIGH,
                category: CATEGORIES.SPENDING,
                title: `⚠️ ${category} Budget Alert`,
                message: `You've used ${spentPercentage.toFixed(0)}% of your ${category} budget. ₹${(budgetAmount - monthlyTotal).toLocaleString('en-IN')} remaining.`,
                actionLabel: 'View Budget',
                actionUrl: '/dashboard/budget',
                metadata: {
                    category,
                    amount,
                    monthlyTotal,
                    budgetAmount,
                    spentPercentage
                }
            })
        }
    }

    /**
     * Handle income received
     */
    async handleIncomeReceived(data) {
        const { amount, source, userId } = data

        await this.create({
            userId,
            type: NOTIFICATION_TYPES.INCOME_RECEIVED,
            priority: PRIORITY.MEDIUM,
            category: CATEGORIES.SAVINGS,
            title: `💰 Income Received`,
            message: `₹${amount.toLocaleString('en-IN')} received from ${source}. Great! Consider allocating to savings.`,
            actionLabel: 'Update Budget',
            actionUrl: '/dashboard/budget',
            metadata: {
                amount,
                source
            }
        })
    }

    /**
     * Handle goal updated - celebrate milestones
     */
    async handleGoalUpdated(data) {
        const { goalName, currentAmount, targetAmount, previousAmount, userId } = data

        const progress = (currentAmount / targetAmount) * 100
        const previousProgress = (previousAmount / targetAmount) * 100

        // Check if we crossed a milestone
        for (const milestone of this.rules.goalMilestones) {
            const milestonePercentage = milestone * 100

            if (progress >= milestonePercentage && previousProgress < milestonePercentage) {
                let emoji = '🎯'
                let title = ''
                let priority = PRIORITY.MEDIUM

                if (milestone === 1.0) {
                    emoji = '🎉'
                    title = 'Goal Achieved!'
                    priority = PRIORITY.HIGH
                } else if (milestone === 0.75) {
                    emoji = '🔥'
                    title = '75% Complete!'
                } else if (milestone === 0.5) {
                    emoji = '💪'
                    title = 'Halfway There!'
                } else if (milestone === 0.25) {
                    emoji = '🌟'
                    title = '25% Complete!'
                }

                await this.create({
                    userId,
                    type: milestone === 1.0 ? NOTIFICATION_TYPES.GOAL_ACHIEVED : NOTIFICATION_TYPES.GOAL_PROGRESS,
                    priority,
                    category: CATEGORIES.GOALS,
                    title: `${emoji} ${title}`,
                    message: `Amazing progress on "${goalName}"! You've saved ₹${currentAmount.toLocaleString('en-IN')} of ₹${targetAmount.toLocaleString('en-IN')}.`,
                    actionLabel: 'View Goals',
                    actionUrl: '/dashboard/goals',
                    metadata: {
                        goalName,
                        currentAmount,
                        targetAmount,
                        progress: milestonePercentage
                    }
                })

                break // Only show one milestone notification at a time
            }
        }
    }

    /**
     * Handle AI recommendation
     */
    async handleAIRecommendation(data) {
        const { title, message, confidence, userId, agentName } = data

        if (confidence && confidence < this.rules.insightRelevanceThreshold) {
            return // Skip low-relevance recommendations
        }

        await this.create({
            userId,
            type: NOTIFICATION_TYPES.AI_RECOMMENDATION,
            priority: PRIORITY.MEDIUM,
            category: CATEGORIES.AI_INSIGHTS,
            title: `🤖 ${agentName}: ${title}`,
            message,
            actionLabel: 'View AI Insights',
            actionUrl: '/dashboard?tab=ai-agents',
            metadata: {
                agentName,
                confidence
            }
        })
    }

    /**
     * Handle AI action
     */
    async handleAIAction(data) {
        const { title, message, userId, agentName, actionType } = data

        let priority = PRIORITY.LOW
        if (actionType === 'alert') priority = PRIORITY.HIGH
        else if (actionType === 'warning') priority = PRIORITY.MEDIUM

        await this.create({
            userId,
            type: NOTIFICATION_TYPES.AI_INSIGHT,
            priority,
            category: CATEGORIES.AI_INSIGHTS,
            title: `${agentName}: ${title}`,
            message,
            actionLabel: 'View Details',
            actionUrl: '/dashboard?tab=ai-agents',
            metadata: {
                agentName,
                actionType
            }
        })
    }

    /**
     * Handle anomaly detected
     */
    async handleAnomalyDetected(data) {
        const { type, message, confidence, userId, details } = data

        if (confidence < this.rules.anomalyConfidenceThreshold) {
            return // Skip low-confidence anomalies
        }

        await this.create({
            userId,
            type: NOTIFICATION_TYPES.ANOMALY_DETECTED,
            priority: confidence > 0.9 ? PRIORITY.HIGH : PRIORITY.MEDIUM,
            category: CATEGORIES.AI_INSIGHTS,
            title: `🔍 Unusual Activity Detected`,
            message,
            actionLabel: 'Review',
            actionUrl: '/dashboard/expenses',
            metadata: {
                anomalyType: type,
                confidence,
                details
            }
        })
    }

    // ============================================
    // Emergency Alert Handlers (NEW)
    // ============================================

    /**
     * Check if we're in quiet hours
     */
    isQuietHours(settings = {}) {
        if (!settings.quietHoursEnabled && !this.rules.emergency.quietHoursEnabled) {
            return false
        }

        const now = new Date()
        const currentHour = now.getHours()
        const start = settings.quietHoursStart ?? this.rules.emergency.quietHoursStart
        const end = settings.quietHoursEnd ?? this.rules.emergency.quietHoursEnd

        // Handle overnight quiet hours (e.g., 22:00 - 07:00)
        if (start > end) {
            return currentHour >= start || currentHour < end
        }
        return currentHour >= start && currentHour < end
    }

    /**
     * Check if alert is in cooldown period
     */
    isInCooldown(alertKey, cooldownHours = 4) {
        const lastAlert = this.alertCooldowns.get(alertKey)
        if (!lastAlert) return false

        const hoursSinceLastAlert = (Date.now() - lastAlert) / (1000 * 60 * 60)
        return hoursSinceLastAlert < cooldownHours
    }

    /**
     * Set cooldown for an alert
     */
    setCooldown(alertKey) {
        this.alertCooldowns.set(alertKey, Date.now())
    }

    /**
     * Trigger emergency low balance alert
     */
    async triggerLowBalanceAlert({ user, currentBalance, accountName, settings = {} }) {
        const threshold = settings.lowBalanceThreshold ?? this.rules.emergency.lowBalanceThreshold
        const criticalThreshold = settings.criticalBalanceThreshold ?? this.rules.emergency.criticalBalanceThreshold

        // Check if alert should be triggered
        if (currentBalance >= threshold) return null

        const isCritical = currentBalance < criticalThreshold
        const alertKey = `low_balance_${user._id || user.id}`
        const cooldownHours = settings.alertCooldownHours ?? this.rules.emergency.alertCooldownHours

        // Check cooldown (critical alerts have shorter cooldown)
        if (this.isInCooldown(alertKey, isCritical ? cooldownHours / 2 : cooldownHours)) {
            console.log('Low balance alert in cooldown, skipping...')
            return null
        }

        // Create notification
        const notification = await this.create({
            userId: user._id || user.id,
            type: NOTIFICATION_TYPES.EMERGENCY_LOW_BALANCE,
            priority: isCritical ? PRIORITY.EMERGENCY : PRIORITY.CRITICAL,
            category: CATEGORIES.EMERGENCY,
            title: isCritical ? '🚨 Critical Balance Alert!' : '⚠️ Low Balance Warning',
            message: `Your balance is ₹${currentBalance.toLocaleString('en-IN')}${accountName ? ` (${accountName})` : ''}, below your threshold of ₹${threshold.toLocaleString('en-IN')}.`,
            actionLabel: 'Review Finances',
            actionUrl: '/dashboard',
            metadata: {
                currentBalance,
                threshold,
                criticalThreshold,
                accountName,
                isCritical
            }
        })

        // Send email if enabled (skip quiet hours for critical)
        const shouldSendEmail = settings.emailAlertsEnabled !== false
        const skipQuietHours = isCritical // Critical alerts bypass quiet hours

        if (shouldSendEmail && (skipQuietHours || !this.isQuietHours(settings))) {
            this.sendEmergencyEmail('low_balance', {
                user,
                currentBalance,
                threshold,
                accountName
            })
        }

        this.setCooldown(alertKey)
        return notification
    }

    /**
     * Trigger emergency budget exceeded alert
     */
    async triggerBudgetExceededAlert({ user, categoryName, budgetAmount, spentAmount, settings = {} }) {
        const thresholdPercent = settings.budgetCriticalPercent ?? this.rules.emergency.budgetExceededThreshold
        const percentage = Math.round((spentAmount / budgetAmount) * 100)

        // Check if alert should be triggered
        if (percentage < thresholdPercent) return null

        const alertKey = `budget_exceeded_${user._id || user.id}_${categoryName}`
        const cooldownHours = settings.alertCooldownHours ?? this.rules.emergency.alertCooldownHours

        // Check cooldown
        if (this.isInCooldown(alertKey, cooldownHours)) {
            console.log('Budget exceeded alert in cooldown, skipping...')
            return null
        }

        // Create notification
        const notification = await this.create({
            userId: user._id || user.id,
            type: NOTIFICATION_TYPES.EMERGENCY_BUDGET_EXCEEDED,
            priority: PRIORITY.EMERGENCY,
            category: CATEGORIES.EMERGENCY,
            title: `📊 Budget Exceeded: ${categoryName}`,
            message: `You've spent ₹${spentAmount.toLocaleString('en-IN')} (${percentage}%) of your ₹${budgetAmount.toLocaleString('en-IN')} ${categoryName} budget.`,
            actionLabel: 'Review Budget',
            actionUrl: '/dashboard/budget',
            metadata: {
                categoryName,
                budgetAmount,
                spentAmount,
                percentage
            }
        })

        // Send email if enabled
        const shouldSendEmail = settings.emailAlertsEnabled !== false
        if (shouldSendEmail && !this.isQuietHours(settings)) {
            this.sendEmergencyEmail('budget_exceeded', {
                user,
                categoryName,
                budgetAmount,
                spentAmount,
                percentage
            })
        }

        this.setCooldown(alertKey)
        return notification
    }

    /**
     * Trigger unusual expense alert
     */
    async triggerUnusualExpenseAlert({ user, expenseAmount, categoryName, averageAmount, settings = {} }) {
        const multiplierThreshold = settings.unusualExpenseMultiplier ?? this.rules.emergency.unusualExpenseMultiplier
        const actualMultiplier = Math.round((expenseAmount / averageAmount) * 10) / 10

        // Check if alert should be triggered
        if (actualMultiplier < multiplierThreshold) return null

        const alertKey = `unusual_expense_${user._id || user.id}_${Date.now()}`

        // Create notification
        const notification = await this.create({
            userId: user._id || user.id,
            type: NOTIFICATION_TYPES.EMERGENCY_UNUSUAL_EXPENSE,
            priority: PRIORITY.HIGH,
            category: CATEGORIES.EMERGENCY,
            title: `🔍 Unusual Expense Detected`,
            message: `₹${expenseAmount.toLocaleString('en-IN')} spent on ${categoryName} - this is ${actualMultiplier}x your average of ₹${averageAmount.toLocaleString('en-IN')}.`,
            actionLabel: 'Review Expense',
            actionUrl: '/dashboard/expenses',
            metadata: {
                expenseAmount,
                categoryName,
                averageAmount,
                multiplier: actualMultiplier
            }
        })

        // Send email if enabled
        const shouldSendEmail = settings.emailAlertsEnabled !== false
        if (shouldSendEmail && !this.isQuietHours(settings)) {
            this.sendEmergencyEmail('unusual_expense', {
                user,
                expenseAmount,
                categoryName,
                averageAmount,
                multiplier: actualMultiplier
            })
        }

        return notification
    }

    /**
     * Trigger EMI at risk alert
     */
    async triggerEMIRiskAlert({ user, emiAmount, emiName, dueDate, currentBalance, settings = {} }) {
        // Check if balance is below EMI amount
        if (currentBalance >= emiAmount) return null

        const alertKey = `emi_risk_${user._id || user.id}_${emiName}`
        const cooldownHours = settings.alertCooldownHours ?? this.rules.emergency.alertCooldownHours

        // Check cooldown
        if (this.isInCooldown(alertKey, cooldownHours / 2)) { // Shorter cooldown for EMI alerts
            console.log('EMI risk alert in cooldown, skipping...')
            return null
        }

        // Create notification
        const notification = await this.create({
            userId: user._id || user.id,
            type: NOTIFICATION_TYPES.EMERGENCY_EMI_RISK,
            priority: PRIORITY.EMERGENCY,
            category: CATEGORIES.EMERGENCY,
            title: `🏦 EMI Payment At Risk!`,
            message: `Your ${emiName} EMI of ₹${emiAmount.toLocaleString('en-IN')} is due on ${new Date(dueDate).toLocaleDateString('en-IN')}, but your balance is only ₹${currentBalance.toLocaleString('en-IN')}.`,
            actionLabel: 'Manage Finances',
            actionUrl: '/dashboard',
            metadata: {
                emiAmount,
                emiName,
                dueDate,
                currentBalance,
                shortfall: emiAmount - currentBalance
            }
        })

        // Send email - EMI risks always send emails (bypass quiet hours)
        const shouldSendEmail = settings.emailAlertsEnabled !== false
        if (shouldSendEmail) {
            this.sendEmergencyEmail('emi_risk', {
                user,
                emiAmount,
                emiName,
                dueDate,
                currentBalance
            })
        }

        this.setCooldown(alertKey)
        return notification
    }

    /**
     * Send emergency email via API (to avoid importing server-side modules in client)
     */
    async sendEmergencyEmail(alertType, data) {
        try {
            const response = await fetch('/api/notifications/emergency-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alertType, data })
            })

            if (response.ok) {
                console.log(`Emergency email (${alertType}) sent successfully`)
            } else {
                console.error(`Failed to send emergency email (${alertType})`)
            }
        } catch (error) {
            console.error(`Error sending emergency email (${alertType}):`, error)
        }
    }

    /**
     * Update emergency alert settings for a user
     */
    updateEmergencySettings(userSettings) {
        // Merge user settings with defaults
        this.rules.emergency = {
            ...this.rules.emergency,
            ...userSettings
        }
    }

    /**
     * Create a new notification
     */
    async create(notification) {
        const newNotification = {
            id: this.generateId(),
            ...notification,
            timestamp: new Date().toISOString(),
            read: false,
            dismissed: false,
            createdAt: new Date().toISOString()
        }

        this.notifications.unshift(newNotification)

        // Emit notification created event
        this.notifyListeners('created', newNotification)

        // Persist to database
        try {
            await this.saveToDatabase(newNotification)
        } catch (error) {
            console.error('Failed to save notification to database:', error)
        }

        return newNotification
    }

    /**
     * Mark notification as read
     */
    async markAsRead(notificationId, userId) {
        const notification = this.notifications.find(n => n.id === notificationId && n.userId === userId)

        if (notification && !notification.read) {
            notification.read = true
            notification.readAt = new Date().toISOString()

            this.notifyListeners('read', notification)

            try {
                await this.updateInDatabase(notificationId, { read: true, readAt: notification.readAt })
            } catch (error) {
                console.error('Failed to update notification in database:', error)
            }
        }

        return notification
    }

    /**
     * Mark all notifications as read
     */
    async markAllAsRead(userId) {
        const userNotifications = this.notifications.filter(n => n.userId === userId && !n.read)

        for (const notification of userNotifications) {
            notification.read = true
            notification.readAt = new Date().toISOString()
        }

        this.notifyListeners('allRead', userNotifications)

        try {
            await this.bulkUpdateInDatabase(userId, { read: true })
        } catch (error) {
            console.error('Failed to bulk update notifications:', error)
        }

        return userNotifications
    }

    /**
     * Dismiss notification
     */
    async dismiss(notificationId, userId) {
        const notification = this.notifications.find(n => n.id === notificationId && n.userId === userId)

        if (notification) {
            notification.dismissed = true
            notification.dismissedAt = new Date().toISOString()

            this.notifyListeners('dismissed', notification)

            try {
                await this.updateInDatabase(notificationId, { dismissed: true, dismissedAt: notification.dismissedAt })
            } catch (error) {
                console.error('Failed to dismiss notification in database:', error)
            }
        }

        return notification
    }

    /**
     * Get notifications for user
     */
    getForUser(userId, options = {}) {
        const {
            limit = 50,
            includeRead = true,
            includeDismissed = false,
            category = null,
            priority = null
        } = options

        let notifications = this.notifications.filter(n => n.userId === userId)

        if (!includeRead) {
            notifications = notifications.filter(n => !n.read)
        }

        if (!includeDismissed) {
            notifications = notifications.filter(n => !n.dismissed)
        }

        if (category) {
            notifications = notifications.filter(n => n.category === category)
        }

        if (priority) {
            notifications = notifications.filter(n => n.priority === priority)
        }

        // Sort by priority and timestamp
        notifications.sort((a, b) => {
            const priorityOrder = {
                [PRIORITY.CRITICAL]: 0,
                [PRIORITY.HIGH]: 1,
                [PRIORITY.MEDIUM]: 2,
                [PRIORITY.LOW]: 3
            }

            const priorityDiff = priorityOrder[a.priority] - priorityOrder[b.priority]
            if (priorityDiff !== 0) return priorityDiff

            return new Date(b.timestamp) - new Date(a.timestamp)
        })

        return notifications.slice(0, limit)
    }

    /**
     * Get unread count
     */
    getUnreadCount(userId) {
        return this.notifications.filter(n =>
            n.userId === userId && !n.read && !n.dismissed
        ).length
    }

    /**
     * Subscribe to notification updates
     */
    subscribe(callback) {
        this.listeners.push(callback)

        return () => {
            this.listeners = this.listeners.filter(l => l !== callback)
        }
    }

    /**
     * Notify all listeners
     */
    notifyListeners(event, data) {
        this.listeners.forEach(callback => {
            try {
                callback(event, data)
            } catch (error) {
                console.error('Notification listener error:', error)
            }
        })
    }

    /**
     * Generate unique ID
     */
    generateId() {
        return `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    }

    /**
     * Save notification to database
     */
    async saveToDatabase(notification) {
        try {
            // Skip if no userId (guest user)
            if (!notification.userId) {
                console.warn('Skipping database save: No userId provided')
                return null
            }

            const response = await fetch('/api/notifications', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(notification)
            })

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}))
                console.error('Failed to save notification:', errorData)
                return null // Return null instead of throwing
            }

            return await response.json()
        } catch (error) {
            console.error('Database save error:', error)
            // Don't throw - gracefully handle the error
            return null
        }
    }

    /**
     * Update notification in database
     */
    async updateInDatabase(notificationId, updates) {
        try {
            const response = await fetch(`/api/notifications/${notificationId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updates)
            })

            if (!response.ok) {
                throw new Error('Failed to update notification')
            }

            return await response.json()
        } catch (error) {
            console.error('Database update error:', error)
            throw error
        }
    }

    /**
     * Bulk update notifications in database
     */
    async bulkUpdateInDatabase(userId, updates) {
        try {
            const response = await fetch(`/api/notifications/bulk`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId, updates })
            })

            if (!response.ok) {
                throw new Error('Failed to bulk update notifications')
            }

            return await response.json()
        } catch (error) {
            console.error('Database bulk update error:', error)
            throw error
        }
    }

    /**
     * Load notifications from database
     */
    async loadFromDatabase(userId) {
        try {
            const response = await fetch(`/api/notifications?userId=${userId}`)

            if (!response.ok) {
                throw new Error('Failed to load notifications')
            }

            const data = await response.json()

            if (data.success && data.notifications) {
                this.notifications = data.notifications
                this.notifyListeners('loaded', this.notifications)
            }

            return data.notifications || []
        } catch (error) {
            console.error('Database load error:', error)
            return []
        }
    }
}

// Create singleton instance
const notificationService = new NotificationService()

export default notificationService
