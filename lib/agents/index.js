// lib/agents/index.js
import { incomeAgent } from './IncomeAgent.js'
import { spendingPatternAgent } from './SpendingPatternAgent.js'

// Initialize all agents
export function initializeAgents() {
    if (typeof window !== 'undefined') {
        console.log('🤖 Initializing Autonomous Agents...')

        // Agents auto-register with event bus in their constructors
        const agents = {
            income: incomeAgent,
            spending: spendingPatternAgent
        }

        console.log('✅ Agents initialized:', Object.keys(agents))

        return agents
    }

    return {}
}

export { incomeAgent, spendingPatternAgent }
