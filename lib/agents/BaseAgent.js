// lib/agents/BaseAgent.js - Base class for all autonomous agents
import { eventBus } from '../events/EventBus.js'

/**
 * Base Agent Class
 * All autonomous agents inherit from this class
 */
export class BaseAgent {
    constructor(name, config = {}) {
        this.name = name
        this.enabled = config.enabled ?? true
        this.priority = config.priority ?? 1
        this.lastAction = null
        this.actionHistory = []
        this.confidence = 0

        // Register with event bus
        this.registerEventHandlers()
    }

    /**
     * Process data autonomously
     * Override in child classes
     */
    async process(data) {
        throw new Error(`${this.name}: process() must be implemented`)
    }

    /**
     * Determine if agent should take action
     * Override in child classes
     */
    shouldTakeAction(data) {
        return this.enabled
    }

    /**
     * Execute action autonomously
     */
    async execute(action) {
        if (!this.enabled) {
            console.log(`${this.name}: Agent disabled, skipping action`)
            return null
        }

        try {
            console.log(`${this.name}: Executing action:`, action.type)

            const result = await action.execute()

            // Record action
            this.lastAction = {
                type: action.type,
                timestamp: new Date(),
                result,
                confidence: this.confidence
            }

            this.actionHistory.push(this.lastAction)

            // Emit event for other agents
            eventBus.emit('AGENT_ACTION', {
                agent: this.name,
                action: this.lastAction
            })

            return result
        } catch (error) {
            console.error(`${this.name}: Action failed:`, error)
            return null
        }
    }

    /**
     * Register event handlers
     * Override in child classes to listen to specific events
     */
    registerEventHandlers() {
        // Base implementation - child classes override
    }

    /**
     * Calculate confidence score for action
     */
    calculateConfidence(data) {
        // Simple default: based on data completeness
        const requiredFields = this.getRequiredFields()
        const providedFields = Object.keys(data).filter(key => data[key] != null)

        this.confidence = providedFields.length / requiredFields.length
        return this.confidence
    }

    /**
     * Get required data fields
     * Override in child classes
     */
    getRequiredFields() {
        return []
    }

    /**
     * Get agent status
     */
    getStatus() {
        return {
            name: this.name,
            enabled: this.enabled,
            lastAction: this.lastAction,
            totalActions: this.actionHistory.length,
            confidence: this.confidence
        }
    }

    /**
     * Enable/disable agent
     */
    setEnabled(enabled) {
        this.enabled = enabled
        console.log(`${this.name}: ${enabled ? 'Enabled' : 'Disabled'}`)
    }
}
