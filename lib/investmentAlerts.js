// Investment Alert System with Market Simulation
import { GoogleGenerativeAI } from '@google/generative-ai'

export class InvestmentAlertSystem {
  constructor() {
    this.genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
    // Use gemini-2.5-flash as the stable model
    this.model = this.genAI.getGenerativeModel({ model: "gemini-2.5-flash" })

    // Simulated market data - in real app this would come from API
    this.marketData = {
      nifty50: { current: 19247, change: -2.1, volume: 'High', trend: 'Bearish' },
      sensex: { current: 64835, change: -1.8, volume: 'High', trend: 'Bearish' },
      gold: { current: 62450, change: +0.5, volume: 'Medium', trend: 'Bullish' },
      bitcoin: { current: 4250000, change: -3.2, volume: 'Very High', trend: 'Volatile' }
    }

    this.lastAlertTime = null
    this.minAlertGap = 2 * 60 * 60 * 1000 // 2 hours in milliseconds
  }

  // Check if user qualifies for investment opportunity alert
  checkInvestmentOpportunity(userSavings, userProfile) {
    const triggers = {
      hasMinSavings: userSavings >= 500,
      marketOpportunity: this.isMarketOpportunity(),
      timeGapMet: this.isTimeGapMet(),
      userActive: this.isUserActive(userProfile)
    }

    console.log('Investment opportunity triggers:', triggers)

    if (Object.values(triggers).every(trigger => trigger)) {
      return this.generateInvestmentAlert(userSavings, userProfile)
    }

    return null
  }

  // Detect market opportunity based on simulated data
  isMarketOpportunity() {
    const niftyDrop = this.marketData.nifty50.change <= -1.5
    const sensexDrop = this.marketData.sensex.change <= -1.5
    const highVolume = this.marketData.nifty50.volume === 'High'

    return niftyDrop || sensexDrop || highVolume
  }

  // Check if enough time has passed since last alert
  isTimeGapMet() {
    if (!this.lastAlertTime) return true
    return (Date.now() - this.lastAlertTime) > this.minAlertGap
  }

  // Check if user is active (has recent expenses or budget activity)
  isUserActive(userProfile) {
    // Simple check - in real app this would be more sophisticated
    return userProfile && userProfile.lastBudgetGenerated
  }

  // Generate personalized investment alert
  async generateInvestmentAlert(userSavings, userProfile) {
    try {
      const marketContext = this.getMarketContext()
      const opportunityScore = this.calculateOpportunityScore()

      const prompt = `
Generate a personalized investment opportunity alert for an Indian user with ₹${userSavings} savings.

Market Context: ${marketContext}
Opportunity Score: ${opportunityScore}/10

Create a compelling but responsible alert that:
1. Explains the market opportunity in simple terms
2. Shows potential returns over 2, 5, and 10 years (simulation only)
3. Emphasizes this is educational simulation
4. Includes a call-to-action for learning

Format as JSON:
{
  "title": "Investment Opportunity Alert",
  "message": "Short compelling message",
  "marketCondition": "Brief market description",
  "opportunityScore": ${opportunityScore},
  "projectedReturns": {
    "2027": "₹amount (+percentage%)",
    "2030": "₹amount (+percentage%)", 
    "2035": "₹amount (+percentage%)"
  },
  "riskDisclaimer": "Educational disclaimer",
  "actionText": "Call to action button text",
  "learningTip": "Educational insight"
}

Keep amounts realistic for Indian market (12-18% annual returns for equity).
`

      const result = await this.model.generateContent(prompt)
      const response = await result.response
      const aiText = response.text()

      const jsonMatch = aiText.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        throw new Error('No JSON found in AI response')
      }

      const alertData = JSON.parse(jsonMatch[0])

      // Add metadata
      alertData.metadata = {
        userSavings: userSavings,
        marketData: this.marketData,
        generatedAt: new Date(),
        alertId: `alert_${Date.now()}`,
        type: 'market_opportunity'
      }

      this.lastAlertTime = Date.now()

      return {
        success: true,
        alert: alertData
      }

    } catch (error) {
      console.error('Error generating investment alert:', error)
      return this.generateFallbackAlert(userSavings)
    }
  }

  // Fallback alert when AI fails
  generateFallbackAlert(userSavings) {
    const opportunityScore = this.calculateOpportunityScore()

    return {
      success: true,
      alert: {
        title: "Market Opportunity Alert 🚨",
        message: `Perfect timing! Market is down ${Math.abs(this.marketData.nifty50.change)}% - Great opportunity to invest your ₹${userSavings} savings!`,
        marketCondition: `Nifty 50 down ${Math.abs(this.marketData.nifty50.change)}% with high volume`,
        opportunityScore: opportunityScore,
        projectedReturns: {
          "2027": `₹${Math.round(userSavings * 1.3)} (+30%)`,
          "2030": `₹${Math.round(userSavings * 1.7)} (+70%)`,
          "2035": `₹${Math.round(userSavings * 2.4)} (+140%)`
        },
        riskDisclaimer: "This is educational simulation only. Past performance doesn't guarantee future results.",
        actionText: "Simulate Investment Now",
        learningTip: "Market drops often present the best long-term investment opportunities!",
        metadata: {
          userSavings: userSavings,
          marketData: this.marketData,
          generatedAt: new Date(),
          alertId: `fallback_${Date.now()}`,
          type: 'market_opportunity'
        }
      }
    }
  }

  // Calculate opportunity score based on market conditions
  calculateOpportunityScore() {
    let score = 5 // Base score

    // Market drop increases score
    if (this.marketData.nifty50.change <= -2) score += 2
    else if (this.marketData.nifty50.change <= -1) score += 1

    // High volume increases score
    if (this.marketData.nifty50.volume === 'High') score += 1
    else if (this.marketData.nifty50.volume === 'Very High') score += 2

    // Multiple markets down increases score
    const marketsDown = Object.values(this.marketData)
      .filter(market => market.change < -1).length
    score += marketsDown

    return Math.min(score, 10) // Cap at 10
  }

  // Get market context for AI prompt
  getMarketContext() {
    const contexts = []

    if (this.marketData.nifty50.change <= -2) {
      contexts.push(`Nifty 50 down ${Math.abs(this.marketData.nifty50.change)}% (significant drop)`)
    }

    if (this.marketData.sensex.change <= -1.5) {
      contexts.push(`Sensex also declining ${Math.abs(this.marketData.sensex.change)}%`)
    }

    if (this.marketData.nifty50.volume === 'High') {
      contexts.push('High trading volume indicates strong investor interest')
    }

    return contexts.join('. ') || 'Normal market conditions'
  }

  // Simulate market data changes (for demo purposes)
  updateMarketData() {
    // Simulate real-time market changes
    this.marketData.nifty50.change = -2.5 + (Math.random() * 2) // -2.5 to -0.5
    this.marketData.sensex.change = -2.0 + (Math.random() * 1.5) // -2.0 to -0.5
    this.marketData.gold.change = -1 + (Math.random() * 2) // -1 to +1

    console.log('Market data updated:', this.marketData)
  }

  // Voice-triggered investment check
  async checkVoiceTriggeredInvestment(voiceText, userSavings) {
    const savingsKeywords = ['bachaya', 'saved', 'बचत', 'savings', 'बचाया']
    const hasSavingsMention = savingsKeywords.some(keyword =>
      voiceText.toLowerCase().includes(keyword)
    )

    if (hasSavingsMention && userSavings >= 500) {
      return await this.generateInvestmentAlert(userSavings, { active: true })
    }

    return null
  }
}

// Singleton instance
export const investmentAlertSystem = new InvestmentAlertSystem()
