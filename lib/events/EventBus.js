// lib/events/EventBus.js - Central event system for agent communication

/**
 * Event Bus for Agent Communication
 * Enables decoupled, event-driven architecture
 */
class EventBus {
    constructor() {
        this.listeners = new Map()
        this.eventHistory = []
        this.maxHistorySize = 100
    }

    /**
     * Subscribe to an event
     */
    on(event, callback, options = {}) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, [])
        }

        const listener = {
            callback,
            priority: options.priority || 0,
            once: options.once || false,
            id: `${event}_${Date.now()}_${Math.random()}`
        }

        this.listeners.get(event).push(listener)

        // Sort by priority (higher priority first)
        this.listeners.get(event).sort((a, b) => b.priority - a.priority)

        return listener.id
    }

    /**
     * Subscribe to event once
     */
    once(event, callback, options = {}) {
        return this.on(event, callback, { ...options, once: true })
    }

    /**
     * Unsubscribe from event
     */
    off(event, listenerId) {
        if (!this.listeners.has(event)) return

        const listeners = this.listeners.get(event)
        const index = listeners.findIndex(l => l.id === listenerId)

        if (index !== -1) {
            listeners.splice(index, 1)
        }
    }

    /**
     * Emit an event
     */
    emit(event, data) {
        // Record event
        this.recordEvent(event, data)

        if (!this.listeners.has(event)) {
            return
        }

        const listeners = this.listeners.get(event)
        const toRemove = []

        listeners.forEach(listener => {
            try {
                listener.callback(data)

                // Mark for removal if once
                if (listener.once) {
                    toRemove.push(listener.id)
                }
            } catch (error) {
                console.error(`EventBus: Error in listener for ${event}:`, error)
            }
        })

        // Remove one-time listeners
        toRemove.forEach(id => this.off(event, id))
    }

    /**
     * Emit event asynchronously
     */
    async emitAsync(event, data) {
        this.recordEvent(event, data)

        if (!this.listeners.has(event)) {
            return []
        }

        const listeners = this.listeners.get(event)
        const results = []
        const toRemove = []

        for (const listener of listeners) {
            try {
                const result = await listener.callback(data)
                results.push(result)

                if (listener.once) {
                    toRemove.push(listener.id)
                }
            } catch (error) {
                console.error(`EventBus: Error in async listener for ${event}:`, error)
                results.push({ error })
            }
        }

        toRemove.forEach(id => this.off(event, id))

        return results
    }

    /**
     * Record event in history
     */
    recordEvent(event, data) {
        this.eventHistory.push({
            event,
            data,
            timestamp: new Date()
        })

        // Maintain max history size
        if (this.eventHistory.length > this.maxHistorySize) {
            this.eventHistory.shift()
        }
    }

    /**
     * Get recent events
     */
    getRecentEvents(count = 10) {
        return this.eventHistory.slice(-count)
    }

    /**
     * Clear all listeners
     */
    clearAll() {
        this.listeners.clear()
    }

    /**
     * Get listener count for event
     */
    getListenerCount(event) {
        return this.listeners.has(event) ? this.listeners.get(event).length : 0
    }

    /**
     * Get all registered events
     */
    getRegisteredEvents() {
        return Array.from(this.listeners.keys())
    }

    /**
     * Get all listeners with counts
     */
    getAllListeners() {
        const result = {}
        this.listeners.forEach((listeners, event) => {
            result[event] = listeners
        })
        return result
    }
}

// Singleton instance
export const eventBus = new EventBus()

// Event type constants
export const EVENTS = {
    // User Events
    USER_LOGIN: 'USER_LOGIN',
    USER_LOGOUT: 'USER_LOGOUT',

    // Transaction Events
    EXPENSE_ADDED: 'EXPENSE_ADDED',
    INCOME_ADDED: 'INCOME_ADDED',
    EXPENSE_UPDATED: 'EXPENSE_UPDATED',
    EXPENSE_DELETED: 'EXPENSE_DELETED',

    // Budget Events
    BUDGET_CREATED: 'BUDGET_CREATED',
    BUDGET_UPDATED: 'BUDGET_UPDATED',
    BUDGET_EXCEEDED: 'BUDGET_EXCEEDED',

    // Goal Events
    GOAL_CREATED: 'GOAL_CREATED',
    GOAL_UPDATED: 'GOAL_UPDATED',
    GOAL_ACHIEVED: 'GOAL_ACHIEVED',

    // Agent Events
    AGENT_ACTION: 'AGENT_ACTION',
    AGENT_RECOMMENDATION: 'AGENT_RECOMMENDATION',
    AGENT_ALERT: 'AGENT_ALERT',

    // Voice Events
    VOICE_EXPENSE_DETECTED: 'VOICE_EXPENSE_DETECTED',
    VOICE_COMMAND: 'VOICE_COMMAND',

    // Pattern Events
    PATTERN_DETECTED: 'PATTERN_DETECTED',
    ANOMALY_DETECTED: 'ANOMALY_DETECTED',

    // Bill Events
    BILL_DUE_SOON: 'BILL_DUE_SOON',
    BILL_PREDICTED: 'BILL_PREDICTED',

    // Income Events
    INCOME_VARIABILITY_DETECTED: 'INCOME_VARIABILITY_DETECTED',
    LOW_INCOME_PERIOD_PREDICTED: 'LOW_INCOME_PERIOD_PREDICTED'
}
