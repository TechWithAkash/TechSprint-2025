/**
 * Simple Event Bus for Application-Wide Events
 * Used for decoupled communication between components, APIs, and services
 */

class EventBus {
    constructor() {
        this.listeners = new Map()
    }

    /**
     * Subscribe to an event
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
     * @returns {Function} Unsubscribe function
     */
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, [])
        }

        this.listeners.get(event).push(callback)

        // Return unsubscribe function
        return () => {
            const callbacks = this.listeners.get(event)
            if (callbacks) {
                const index = callbacks.indexOf(callback)
                if (index > -1) {
                    callbacks.splice(index, 1)
                }
            }
        }
    }

    /**
     * Emit an event
     * @param {string} event - Event name
     * @param {any} data - Event data
     */
    emit(event, data) {
        const callbacks = this.listeners.get(event)

        if (!callbacks || callbacks.length === 0) {
            console.log(`📢 EventBus: ${event} emitted (no listeners)`)
            return
        }

        console.log(`📢 EventBus: ${event} emitted to ${callbacks.length} listener(s)`)

        // Execute all callbacks asynchronously
        callbacks.forEach(callback => {
            try {
                // Use setTimeout to prevent blocking
                setTimeout(() => {
                    callback(data)
                }, 0)
            } catch (error) {
                console.error(`❌ EventBus error in listener for ${event}:`, error)
            }
        })
    }

    /**
     * Remove all listeners for an event
     * @param {string} event - Event name
     */
    off(event) {
        this.listeners.delete(event)
    }

    /**
     * Remove all listeners
     */
    clear() {
        this.listeners.clear()
    }

    /**
     * Get listener count for an event
     * @param {string} event - Event name
     * @returns {number} Number of listeners
     */
    listenerCount(event) {
        const callbacks = this.listeners.get(event)
        return callbacks ? callbacks.length : 0
    }
}

// Event name constants
export const EVENTS = {
    // Expense Events
    EXPENSE_ADDED: 'EXPENSE_ADDED',
    EXPENSE_UPDATED: 'EXPENSE_UPDATED',
    EXPENSE_DELETED: 'EXPENSE_DELETED',

    // Income Events
    INCOME_RECEIVED: 'INCOME_RECEIVED',
    INCOME_UPDATED: 'INCOME_UPDATED',
    INCOME_DELETED: 'INCOME_DELETED',

    // Goal Events
    GOAL_CREATED: 'GOAL_CREATED',
    GOAL_UPDATED: 'GOAL_UPDATED',
    GOAL_ACHIEVED: 'GOAL_ACHIEVED',
    GOAL_DELETED: 'GOAL_DELETED',

    // Budget Events
    BUDGET_CREATED: 'BUDGET_CREATED',
    BUDGET_UPDATED: 'BUDGET_UPDATED',
    BUDGET_WARNING: 'BUDGET_WARNING',
    BUDGET_EXCEEDED: 'BUDGET_EXCEEDED',

    // AI Agent Events
    AGENT_RECOMMENDATION: 'AGENT_RECOMMENDATION',
    AGENT_ACTION: 'AGENT_ACTION',
    AGENT_ERROR: 'AGENT_ERROR',
    ANOMALY_DETECTED: 'ANOMALY_DETECTED',

    // User Events
    USER_REGISTERED: 'USER_REGISTERED',
    USER_LOGGED_IN: 'USER_LOGGED_IN',
    USER_PROFILE_UPDATED: 'USER_PROFILE_UPDATED',

    // Notification Events
    NOTIFICATION_CREATED: 'NOTIFICATION_CREATED',
    NOTIFICATION_READ: 'NOTIFICATION_READ',
    NOTIFICATION_DISMISSED: 'NOTIFICATION_DISMISSED',

    // Bill Events
    BILL_CREATED: 'BILL_CREATED',
    BILL_DUE: 'BILL_DUE',
    BILL_OVERDUE: 'BILL_OVERDUE',
    BILL_PAID: 'BILL_PAID',

    // Investment Events
    INVESTMENT_ADDED: 'INVESTMENT_ADDED',
    INVESTMENT_UPDATED: 'INVESTMENT_UPDATED',
    PORTFOLIO_REBALANCED: 'PORTFOLIO_REBALANCED',

    // Transaction Events
    TRANSACTION_PROCESSED: 'TRANSACTION_PROCESSED',
    TRANSACTION_FAILED: 'TRANSACTION_FAILED',

    // Statement Events
    STATEMENT_UPLOADED: 'STATEMENT_UPLOADED',
    STATEMENT_PARSED: 'STATEMENT_PARSED',
    STATEMENT_ERROR: 'STATEMENT_ERROR'
}

// Create singleton instance
const eventBus = new EventBus()

// Export singleton
export default eventBus

// Named export for convenience
export { eventBus }
