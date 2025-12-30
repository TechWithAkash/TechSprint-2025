// lib/budgetGenerator.js
import {
  BUDGET_CATEGORIES,
  CITY_ADJUSTMENTS,
  getFamilySizeAdjustment,
  getIncomeAdjustments,
  getAgeAdjustments
} from './budgetConfig.js'
import { advancedBudgetEngine } from './advancedBudgetEngine.js'
import { seasonalPlanner } from './seasonalPlanner.js'
import { getUpcomingEvents } from './indianFinancialCalendar.js'

export class AIBudgetGenerator {
  constructor() {
    this.categories = BUDGET_CATEGORIES
    this.cityAdjustments = CITY_ADJUSTMENTS
    this.geminiApiKey = process.env.GEMINI_API_KEY
    this.advancedEngine = advancedBudgetEngine
  }

  /**
   * Generate personalized budget based on user profile using AI
   * @param {Object} userProfile - User profile data
   * @returns {Object} Generated budget with categories and explanations
   */
  async generateBudget(userProfile) {
    const {
      monthlyIncome,
      city,
      familySize,
      age,
      occupation = '',
      budgetPreferences = {},
      incomeSources = [],
      seasonalEvents = [],
      seasonalPlanningPreferences = {}
    } = userProfile

    console.log('💡 Using ADVANCED Budget Generation Engine...')

    // Calculate income stability ratio from multiple income sources
    const incomeStabilityData = this.calculateIncomeStability(incomeSources, monthlyIncome)
    console.log('📊 Income Stability Ratio:', incomeStabilityData.stabilityRatio + '%')

    // Calculate seasonal reserve if seasonal planning is enabled
    const seasonalReserveData = this.calculateSeasonalReserve(
      monthlyIncome,
      seasonalPlanningPreferences,
      seasonalEvents,
      familySize
    )
    console.log('🎉 Seasonal Reserve:', seasonalReserveData.monthlyReserve)

    try {
      // Use advanced budget engine for realistic allocations
      const advancedBudget = this.advancedEngine.generateRealisticBudget({
        monthlyIncome,
        city,
        familySize,
        age,
        occupation,
        hasHome: userProfile.hasHome || false,
        hasVehicle: userProfile.hasVehicle || false,
        hasChildren: familySize > 2,
        spendingStyle: budgetPreferences.spendingStyle || 'moderate',
        // New: Income stability data
        incomeStability: incomeStabilityData,
        // New: Seasonal reserve data
        seasonalReserve: seasonalReserveData
      })

      console.log('✅ Advanced budget generated successfully')
      console.log('📊 Budget Health Score:', advancedBudget.insights.budgetHealth.score)
      console.log('💰 Savings Rate:', advancedBudget.insights.savingsAnalysis.currentRate + '%')

      // Generate AI-powered explanations and tips
      const aiInsights = await this.generateAIInsights(userProfile, advancedBudget)

      // Combine advanced engine insights with AI insights
      return {
        categories: advancedBudget.categories,
        totalBudget: monthlyIncome,
        totalAllocated: monthlyIncome,
        savings: advancedBudget.categories.savings,

        // AI-generated content
        explanations: aiInsights.explanations,
        tips: aiInsights.tips,
        recommendations: aiInsights.recommendations,
        aiGenerated: aiInsights.aiGenerated || false,
        confidence: aiInsights.confidence || 0.85,

        // Advanced engine insights
        budgetHealth: advancedBudget.insights.budgetHealth,
        savingsAnalysis: advancedBudget.insights.savingsAnalysis,
        housingAnalysis: advancedBudget.insights.housingAnalysis,
        lifestyleBalance: advancedBudget.insights.lifestyleBalance,
        actionItems: advancedBudget.insights.actionItems,
        benchmarks: advancedBudget.insights.benchmarks,

        // Metadata
        generatedAt: new Date(),
        framework: advancedBudget.framework,
        incomeBracket: advancedBudget.incomeBracket,
        lifeStage: advancedBudget.lifeStage,

        // New: Income stability analysis
        incomeStability: incomeStabilityData,

        // New: Seasonal reserve planning
        seasonalReserve: seasonalReserveData,

        metadata: {
          city,
          familySize,
          age,
          occupation,
          cityData: advancedBudget.metadata.realExpenses,
          savingsTarget: advancedBudget.metadata.savingsTarget,
          riskProfile: advancedBudget.metadata.riskProfile,
          // New metadata fields
          incomeSourcesCount: incomeSources.length,
          hasMultipleIncome: incomeSources.length > 1,
          stabilityRatio: incomeStabilityData.stabilityRatio,
          seasonalReserveEnabled: seasonalReserveData.enabled
        }
      }
    } catch (error) {
      console.error('❌ Advanced budget generation failed, using fallback:', error.message)
      // Fallback to original method
      return this.generateBudgetFallback(userProfile)
    }
  }

  /**
   * Fallback budget generation using original method
   */
  async generateBudgetFallback(userProfile) {
    const {
      monthlyIncome,
      city,
      familySize,
      age,
      occupation = '',
      budgetPreferences = {}
    } = userProfile

    console.log('⚠️ Using fallback budget generation method')

    // Get all adjustment factors
    const cityAdjustment = this.getCityAdjustment(city)
    const familyAdjustment = getFamilySizeAdjustment(familySize)
    const incomeAdjustment = getIncomeAdjustments(monthlyIncome)
    const ageAdjustment = getAgeAdjustments(age)

    // Calculate adjusted budget
    const adjustedBudget = this.calculateAdjustedBudget(
      monthlyIncome,
      cityAdjustment,
      familyAdjustment,
      incomeAdjustment,
      ageAdjustment
    )

    // Validate budget before proceeding
    const budgetValidation = this.validateBudgetAllocations(adjustedBudget.categories, monthlyIncome)
    console.log('📊 Budget validation:', budgetValidation)

    if (!budgetValidation.isValid) {
      console.warn('⚠️ Budget validation failed, applying corrections...')
    }

    // Generate AI-powered explanations and tips
    const aiInsights = await this.generateAIInsights(userProfile, adjustedBudget)

    return {
      categories: adjustedBudget.categories,
      totalBudget: monthlyIncome,
      totalAllocated: adjustedBudget.totalAllocated,
      savings: adjustedBudget.categories.savings,
      explanations: aiInsights.explanations,
      tips: aiInsights.tips,
      recommendations: aiInsights.recommendations,
      aiGenerated: aiInsights.aiGenerated || false,
      confidence: aiInsights.confidence || 0.75,
      validationScore: budgetValidation.score,
      generatedAt: new Date(),
      metadata: {
        city,
        familySize,
        age,
        occupation,
        adjustmentFactors: {
          city: cityAdjustment,
          family: familyAdjustment,
          income: incomeAdjustment,
          age: ageAdjustment
        },
        validationWarnings: budgetValidation.warnings
      }
    }
  }

  /**
   * Get city-specific adjustments
   */
  getCityAdjustment(city) {
    const normalizedCity = city.charAt(0).toUpperCase() + city.slice(1).toLowerCase()
    return this.cityAdjustments[normalizedCity] || this.cityAdjustments.default
  }

  /**
   * Calculate budget with all adjustments applied
   */
  calculateAdjustedBudget(income, cityAdj, familyAdj, incomeAdj, ageAdj) {
    const categories = {}
    let totalAllocated = 0

    // Apply all adjustments to each category
    if (this.categories && typeof this.categories === 'object') {
      Object.entries(this.categories).forEach(([categoryKey, categoryData]) => {
        const baseAmount = income * categoryData.basePercentage

        // Apply all adjustment factors
        const adjustmentFactor =
          (cityAdj[categoryKey] || 1) *
          (familyAdj[categoryKey] || 1) *
          (incomeAdj[categoryKey] || 1) *
          (ageAdj[categoryKey] || 1)

        const adjustedAmount = Math.round(baseAmount * adjustmentFactor)
        const percentage = Math.round((adjustedAmount / income) * 100)

        categories[categoryKey] = {
          amount: adjustedAmount,
          percentage,
          hindiName: categoryData.hindiName,
          englishName: categoryData.englishName,
          hinglishName: categoryData.hinglishName,
          emoji: categoryData.emoji,
          description: categoryData.description?.english || categoryData.description || categoryData.englishName
        }

        totalAllocated += adjustedAmount
      })
    }

    // Ensure budget balances to 100% of income
    this.balanceBudget(categories, income, totalAllocated)

    return { categories, totalAllocated: income }
  }

  /**
   * Balance budget to ensure it adds up to 100% of income
   */
  balanceBudget(categories, income, currentTotal) {
    const difference = income - currentTotal

    if (Math.abs(difference) < 100) return // Small differences are acceptable

    // If there's a significant difference, adjust savings category
    if (categories.savings) {
      categories.savings.amount += difference
      categories.savings.percentage = Math.round((categories.savings.amount / income) * 100)

      // Ensure savings doesn't go negative
      if (categories.savings.amount < 0) {
        const deficit = Math.abs(categories.savings.amount)
        categories.savings.amount = Math.round(income * 0.05) // Minimum 5% savings

        // Reduce other categories proportionally
        this.reduceOtherCategories(categories, deficit, income)
      }
    }
  }

  /**
   * Reduce other categories proportionally when savings would go negative
   */
  reduceOtherCategories(categories, deficit, income) {
    const excludeKeys = ['savings']
    const reducibleCategories = Object.keys(categories).filter(key => !excludeKeys.includes(key))

    const totalReducible = reducibleCategories.reduce((sum, key) => sum + categories[key].amount, 0)

    reducibleCategories.forEach(key => {
      const reductionRatio = categories[key].amount / totalReducible
      const reduction = Math.round(deficit * reductionRatio)

      categories[key].amount = Math.max(categories[key].amount - reduction, Math.round(income * 0.02)) // Minimum 2% per category
      categories[key].percentage = Math.round((categories[key].amount / income) * 100)
    })
  }

  /**
   * Generate AI-powered insights using Gemini API with enhanced prompting
   */
  async generateAIInsights(userProfile, budget) {
    // Try AI first with enhanced prompting, fallback if needed
    if (!this.geminiApiKey) {
      console.log('⚠️ No Gemini API key found, using fallback')
      return this.generateFallbackInsights(userProfile, budget)
    }

    try {
      console.log('🤖 Generating AI insights with enhanced prompting...')
      const prompt = this.createEnhancedPromptForGemini(userProfile, budget)

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${this.geminiApiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: prompt
            }]
          }],
          generationConfig: {
            temperature: 0.7,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 2048,
          }
        })
      })

      if (!response.ok) {
        console.error(`❌ Gemini API error: ${response.status}`)
        throw new Error(`Gemini API error: ${response.status}`)
      }

      const data = await response.json()
      const aiResponse = data.candidates?.[0]?.content?.parts?.[0]?.text

      if (!aiResponse) {
        throw new Error('No response from Gemini API')
      }

      // Parse and validate the AI response
      let parsedResponse
      try {
        const cleanResponse = aiResponse.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim()
        parsedResponse = JSON.parse(cleanResponse)

        // Validate AI response structure
        const validation = this.validateAIResponse(parsedResponse, userProfile, budget)

        if (!validation.isValid) {
          console.warn('⚠️ AI response validation failed:', validation.issues)
          throw new Error('AI response validation failed')
        }

        console.log('✅ AI insights generated successfully with confidence:', validation.confidence)

        return {
          explanations: parsedResponse.explanations || this.generateFallbackExplanations(userProfile, budget),
          tips: parsedResponse.tips || this.generateFallbackTips(userProfile, budget),
          recommendations: parsedResponse.recommendations || this.generateFallbackRecommendations(userProfile, budget),
          aiGenerated: true,
          confidence: validation.confidence
        }

      } catch (parseError) {
        console.warn('Failed to parse AI response:', parseError.message)
        throw parseError
      }

    } catch (error) {
      console.error('❌ AI insights generation failed:', error.message)
      console.log('📋 Using enhanced fallback system...')
      // Fallback to enhanced traditional explanations
      return this.generateFallbackInsights(userProfile, budget)
    }
  }

  /**
   * Consolidated fallback insights generator
   */
  generateFallbackInsights(userProfile, budget) {
    return {
      explanations: this.generateFallbackExplanations(userProfile, budget),
      tips: this.generateFallbackTips(userProfile, budget),
      recommendations: this.generateFallbackRecommendations(userProfile, budget),
      aiGenerated: false,
      confidence: 0.75
    }
  }

  /**
   * Create enhanced prompt for Gemini AI with financial expertise
   */
  createEnhancedPromptForGemini(userProfile, budget) {
    const { monthlyIncome, city, familySize, age, occupation, lifestyleAnswers = {} } = userProfile

    // Get budget categories safely
    const categories = budget.categories || {}
    const budgetHealth = budget.insights?.budgetHealth || {}
    const savingsAnalysis = budget.insights?.savingsAnalysis || {}
    const incomeBracket = budget.incomeBracket || 'Middle class professional'
    const lifeStage = budget.lifeStage || 'Working professional'

    // Get city-specific data
    const cityData = this.getCitySpecificData(city, monthlyIncome, familySize)

    // Get occupation-specific insights
    const occupationData = this.getOccupationInsights(occupation, monthlyIncome)

    // Process lifestyle insights from quiz
    const lifestyleInsights = this.processLifestyleInsights(lifestyleAnswers)

    return `You are an expert Indian Certified Financial Planner (CFP) with 15+ years of experience specializing in personal finance for Indian middle-class families.

🎯 USER PROFILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💰 Monthly Income: ₹${monthlyIncome.toLocaleString('en-IN')} (${occupationData.stability})
   Income Bracket: ${incomeBracket}
   Life Stage: ${lifeStage}
🏙️ City: ${city} (${cityData.costLevel})
   • Typical Rent (${familySize}-member): ₹${cityData.avgRent.toLocaleString('en-IN')}
   • Average Transport/month: ₹${cityData.avgTransport.toLocaleString('en-IN')}
   • Grocery Budget (${familySize}-member): ₹${cityData.avgFood.toLocaleString('en-IN')}
👨‍👩‍👧‍👦 Family: ${familySize} members
👤 Age: ${age} years | Occupation: ${occupation || 'Professional'}

${lifestyleInsights ? `🎯 LIFESTYLE INSIGHTS (Based on user survey):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${lifestyleInsights}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

` : ''}📊 GENERATED BUDGET ALLOCATION (Using Advanced Algorithm):
${Object.entries(categories).map(([key, cat]) =>
      `${cat.emoji} ${cat.englishName}: ₹${cat.amount.toLocaleString('en-IN')} (${cat.percentage}%)`
    ).join('\n')}

📈 BUDGET HEALTH ANALYSIS:
• Overall Score: ${budgetHealth.score || 85}/100 (${budgetHealth.grade || 'A'})
• Savings Rate: ${savingsAnalysis.currentRate || 15}% (Target: ${savingsAnalysis.targetRate || 20}%)
• Status: ${budgetHealth.status || 'Healthy'}
${budgetHealth.strengths ? '\n• Strengths: ' + budgetHealth.strengths.join(', ') : ''}
${budgetHealth.issues ? '\n• Areas to Improve: ' + budgetHealth.issues.join(', ') : ''}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 YOUR TASK AS A CFP:
This budget was generated using advanced financial algorithms with real cost-of-living data for ${city}. 
Your role is to provide expert validation and personalized advice to make it actionable.

💡 CONSIDER THESE FACTORS:
• ${city} cost of living is ${cityData.costLevel}
• ${familySize}-member families typically need ₹${cityData.avgTotalExpense.toLocaleString('en-IN')} for basic expenses
• At age ${age}, ${this.getAgeSpecificAdvice(age)}
• ${occupationData.insight}
• Current savings: ₹${savingsAnalysis.monthlyAmount?.toLocaleString('en-IN') || 'Unknown'}/month
${lifestyleInsights ? `• User lifestyle patterns: Review the lifestyle insights section above for personalized recommendations` : ''}

🎯 PROVIDE JSON OUTPUT:
{
  "explanations": {
    "overall": "Expert validation of this budget (2-3 sentences, mention specific strengths${lifestyleInsights ? ' and incorporate lifestyle insights' : ''})",
    "categories": {
      "food_dining": "Why ₹${categories.food_dining?.amount || 0} is realistic for ${familySize} members in ${city}${lifestyleInsights ? ' based on their eating habits' : ''}",
      "home_utilities": "Housing allocation analysis (₹${categories.home_utilities?.amount || 0} is ${categories.home_utilities?.percentage || 0}% - good/high/optimal)",
      "transportation": "Transport budget assessment for ${city}",
      "entertainment": "Lifestyle balance commentary${lifestyleInsights ? ' considering their subscription and entertainment habits' : ''}",
      "shopping": "Personal spending allocation reasoning",
      "healthcare": "Health coverage adequacy for age ${age}",
      "savings": "Savings strategy evaluation (${savingsAnalysis.currentRate || 0}% vs ${savingsAnalysis.targetRate || 20}% target)"
    }
  },
  "tips": [
    "💰 Specific savings tip with exact rupee amount to increase",
    "🏠 ${city}-specific cost reduction strategy",
    "👨‍👩‍👧‍👦 Family-size optimization for ${familySize} members",
    "📊 Age ${age} financial planning advice",
    "🎯 One actionable habit to start this month${lifestyleInsights ? ' based on their lifestyle patterns' : ''}"
  ],
  "recommendations": [
    {
      "type": "Emergency Fund",
      "amount": ${monthlyIncome * 6},
      "description": "Build ₹${(monthlyIncome * 6).toLocaleString('en-IN')} emergency fund (6 months expenses)",
      "priority": "Critical",
      "icon": "🛡️"
    },
    {
      "type": "Investment",
      "amount": ${Math.round((savingsAnalysis.monthlyAmount || monthlyIncome * 0.15) * 0.7)},
      "description": "Age-appropriate equity/debt allocation for ${age}-year-old",
      "priority": "High",
      "icon": "📈"
    },
    {
      "type": "Insurance",
      "amount": ${monthlyIncome * 120},
      "description": "Term insurance ₹${((monthlyIncome * 120) / 100000).toFixed(0)}L + health ₹${Math.max(5, familySize * 3)}L",
      "priority": "Critical",
      "icon": "🛡️"
    }
  ]
}

⚠️ CRITICAL RULES:
1. All amounts MUST be realistic for Indian context (2024-2025)
2. Tips must be specific and actionable (not generic)
3. Consider actual ${city} living costs
4. Be encouraging but honest about financial reality
5. Use Indian financial terminology (SIP, EPF, PPF, ELSS)
${lifestyleInsights ? '6. INCORPORATE lifestyle insights to provide hyper-personalized recommendations\n7. ' : '6. '}Return ONLY valid JSON, no markdown or extra text

🎯 OUTPUT ONLY THE JSON, NOTHING ELSE.`
  }

  /**
   * Get city-specific financial data
   */
  getCitySpecificData(city, income, familySize) {
    const cityData = {
      'Mumbai': {
        avgRent: Math.min(income * 0.35, 25000 + (familySize - 1) * 5000),
        avgTransport: Math.min(5000 + (familySize * 500), 8000),
        avgFood: 8000 + (familySize * 4000),
        costLevel: 'among the highest in India',
        avgTotalExpense: 50000 + (familySize * 10000)
      },
      'Delhi': {
        avgRent: Math.min(income * 0.32, 20000 + (familySize - 1) * 4000),
        avgTransport: Math.min(4000 + (familySize * 500), 7000),
        avgFood: 7000 + (familySize * 3500),
        costLevel: 'high, especially in South Delhi',
        avgTotalExpense: 45000 + (familySize * 9000)
      },
      'Bangalore': {
        avgRent: Math.min(income * 0.30, 18000 + (familySize - 1) * 3500),
        avgTransport: Math.min(4000 + (familySize * 400), 6000),
        avgFood: 6500 + (familySize * 3500),
        costLevel: 'moderate to high',
        avgTotalExpense: 42000 + (familySize * 8500)
      },
      'Hyderabad': {
        avgRent: Math.min(income * 0.28, 15000 + (familySize - 1) * 3000),
        avgTransport: Math.min(3500 + (familySize * 400), 5500),
        avgFood: 6000 + (familySize * 3000),
        costLevel: 'moderate and affordable',
        avgTotalExpense: 38000 + (familySize * 7500)
      },
      'Chennai': {
        avgRent: Math.min(income * 0.28, 16000 + (familySize - 1) * 3000),
        avgTransport: Math.min(3500 + (familySize * 400), 5500),
        avgFood: 6000 + (familySize * 3000),
        costLevel: 'moderate',
        avgTotalExpense: 38000 + (familySize * 7500)
      },
      'Pune': {
        avgRent: Math.min(income * 0.28, 15000 + (familySize - 1) * 3000),
        avgTransport: Math.min(3500 + (familySize * 400), 5500),
        avgFood: 6000 + (familySize * 3000),
        costLevel: 'moderate',
        avgTotalExpense: 38000 + (familySize * 7500)
      },
      'Kolkata': {
        avgRent: Math.min(income * 0.25, 12000 + (familySize - 1) * 2500),
        avgTransport: Math.min(3000 + (familySize * 300), 4500),
        avgFood: 5500 + (familySize * 2800),
        costLevel: 'relatively affordable',
        avgTotalExpense: 32000 + (familySize * 6500)
      }
    }

    return cityData[city] || {
      avgRent: Math.min(income * 0.25, 12000 + (familySize - 1) * 2500),
      avgTransport: 3500 + (familySize * 400),
      avgFood: 6000 + (familySize * 3000),
      costLevel: 'moderate',
      avgTotalExpense: 35000 + (familySize * 7000)
    }
  }

  /**
   * Get occupation-specific insights
   */
  getOccupationInsights(occupation, income) {
    const occupationMap = {
      'software': { stability: 'Stable IT income', insight: 'Consider SIP investments and ESOP planning' },
      'engineer': { stability: 'Stable engineering income', insight: 'Focus on long-term equity investments' },
      'teacher': { stability: 'Stable education sector', insight: 'Government pension benefits, focus on PPF' },
      'business': { stability: 'Variable business income', insight: 'Maintain higher emergency fund (9-12 months)' },
      'freelance': { stability: 'Variable freelance income', insight: 'Build 12-month emergency fund, irregular income planning' },
      'doctor': { stability: 'Stable medical profession', insight: 'High income potential, consider real estate and mutual funds' },
      'default': { stability: 'Regular monthly income', insight: 'Balanced approach to savings and investments' }
    }

    const occupationLower = (occupation || '').toLowerCase()
    for (const [key, value] of Object.entries(occupationMap)) {
      if (occupationLower.includes(key)) {
        return value
      }
    }

    return occupationMap.default
  }

  /**
   * Get age-specific financial advice
   */
  getAgeSpecificAdvice(age) {
    if (age < 30) {
      return 'you should focus on aggressive wealth building through equity investments and skill development'
    } else if (age < 40) {
      return 'balance between growth (equity) and stability (debt) is important, with focus on insurance'
    } else if (age < 50) {
      return 'shift focus to capital preservation while maintaining some growth investments'
    } else {
      return 'prioritize capital preservation, adequate health insurance, and retirement corpus'
    }
  }

  /**
   * Validate AI response for realistic budget recommendations
   */
  validateAIResponse(aiResponse, userProfile, budget) {
    const issues = []
    let confidence = 1.0

    try {
      // Check if response has required structure
      if (!aiResponse.explanations) {
        issues.push('Missing explanations')
        confidence -= 0.3
      }

      if (!aiResponse.tips || !Array.isArray(aiResponse.tips) || aiResponse.tips.length < 3) {
        issues.push('Insufficient tips')
        confidence -= 0.2
      }

      if (!aiResponse.recommendations || !Array.isArray(aiResponse.recommendations)) {
        issues.push('Missing recommendations')
        confidence -= 0.2
      }

      // Validate explanations structure
      if (aiResponse.explanations) {
        if (!aiResponse.explanations.overall) {
          issues.push('Missing overall explanation')
          confidence -= 0.1
        }

        if (!aiResponse.explanations.categories) {
          issues.push('Missing category explanations')
          confidence -= 0.2
        }
      }

      // Validate recommendations have required fields
      if (aiResponse.recommendations && Array.isArray(aiResponse.recommendations)) {
        for (const rec of aiResponse.recommendations) {
          if (!rec.type || !rec.description || !rec.priority) {
            issues.push(`Invalid recommendation structure: ${JSON.stringify(rec)}`)
            confidence -= 0.1
          }

          // Check if amounts are realistic
          if (rec.amount) {
            if (rec.amount < 0 || rec.amount > userProfile.monthlyIncome * 200) {
              issues.push(`Unrealistic recommendation amount: ₹${rec.amount}`)
              confidence -= 0.1
            }
          }
        }
      }

      // Validate tips quality
      if (aiResponse.tips && Array.isArray(aiResponse.tips)) {
        for (const tip of aiResponse.tips) {
          if (typeof tip !== 'string' || tip.length < 20) {
            issues.push('Tips are too short or invalid')
            confidence -= 0.05
          }
        }
      }

    } catch (error) {
      issues.push(`Validation error: ${error.message}`)
      confidence = 0
    }

    return {
      isValid: issues.length === 0 || confidence > 0.6,
      issues,
      confidence: Math.max(confidence, 0)
    }
  }

  /**
   * Validate budget allocations are within realistic ranges
   */
  validateBudgetAllocations(categories, monthlyIncome) {
    const rules = {
      savings: { min: 10, max: 40, ideal: 20, name: 'Savings' },
      home_utilities: { min: 20, max: 45, ideal: 30, name: 'Housing' },
      food_dining: { min: 15, max: 35, ideal: 25, name: 'Food' },
      transportation: { min: 5, max: 20, ideal: 10, name: 'Transport' },
      healthcare: { min: 3, max: 15, ideal: 7, name: 'Healthcare' },
      entertainment: { min: 2, max: 15, ideal: 8, name: 'Entertainment' },
      shopping: { min: 2, max: 15, ideal: 5, name: 'Shopping' }
    }

    const issues = []
    const warnings = []
    let score = 100

    for (const [key, category] of Object.entries(categories)) {
      const rule = rules[key]
      if (!rule) continue

      const percentage = category.percentage

      if (percentage < rule.min) {
        issues.push(`${rule.name} too low: ${percentage}% (minimum ${rule.min}%)`)
        score -= 10
      } else if (percentage > rule.max) {
        issues.push(`${rule.name} too high: ${percentage}% (maximum ${rule.max}%)`)
        score -= 15
      } else if (Math.abs(percentage - rule.ideal) > 10) {
        warnings.push(`${rule.name}: ${percentage}% (ideal: ${rule.ideal}%)`)
        score -= 3
      }
    }

    // Check total adds to 100%
    const total = Object.values(categories).reduce((sum, cat) => sum + (cat.percentage || 0), 0)
    if (Math.abs(total - 100) > 1) {
      issues.push(`Total allocation ${total.toFixed(1)}% doesn't equal 100%`)
      score -= 20
    }

    return {
      isValid: issues.length === 0,
      issues,
      warnings,
      score: Math.max(score, 0),
      confidence: score / 100
    }
  }

  /**
   * Generate fallback explanations in English
   */
  generateFallbackExplanations(userProfile, budget) {
    const { city, familySize, monthlyIncome, age } = userProfile

    const explanations = {
      overall: `This budget is designed for your monthly income of ₹${monthlyIncome.toLocaleString('en-IN')} for a family of ${familySize} members living in ${city}. It's optimized for Indian spending patterns and local cost considerations.`,
      categories: {}
    }

    // Generate category-specific explanations
    if (budget.categories && typeof budget.categories === 'object') {
      Object.entries(budget.categories).forEach(([categoryKey, categoryData]) => {
        explanations.categories[categoryKey] = this.getCategoryExplanation(categoryKey, categoryData, userProfile)
      })
    }

    return explanations
  }

  /**
   * Generate enhanced fallback tips in English with specific actionable advice
   */
  generateFallbackTips(userProfile, budget) {
    const { monthlyIncome, familySize, age, city } = userProfile
    const savingsPercentage = budget.categories?.savings?.percentage || 0
    const housingPercentage = budget.categories?.home_utilities?.percentage || 0
    const foodPercentage = budget.categories?.food_dining?.percentage || 0
    const tips = []

    // 1. Savings-specific actionable tips
    if (savingsPercentage < 15) {
      const targetSavings = monthlyIncome * 0.15
      const currentSavings = budget.categories?.savings?.amount || 0
      const additionalNeeded = targetSavings - currentSavings
      tips.push(`💰 Increase your savings by ₹${Math.round(additionalNeeded).toLocaleString('en-IN')}/month to reach the healthy 15% mark (₹${Math.round(targetSavings).toLocaleString('en-IN')}). Start by cutting one restaurant meal per week - saves ~₹2,000/month!`)
    } else if (savingsPercentage >= 20) {
      const monthlySavings = budget.categories?.savings?.amount || 0
      const yearlyTotal = monthlySavings * 12
      tips.push(`🎉 Excellent ${savingsPercentage}% savings rate! That's ₹${yearlyTotal.toLocaleString('en-IN')}/year. Invest 70% in equity mutual funds and 30% in PPF for optimal growth + safety.`)
    } else {
      tips.push(`💰 Your ${savingsPercentage}% savings rate is good! Aim for 20% by reducing discretionary spending. Even saving an extra ₹1,000/month = ₹12,000/year!`)
    }

    // 2. Age-specific actionable tips
    if (age < 30) {
      const sipAmount = Math.round(monthlyIncome * 0.15)
      const futureValue = Math.round(sipAmount * 12 * 30 * 3) // Approx 12% CAGR
      tips.push(`🚀 At ${age}, start a ₹${sipAmount.toLocaleString('en-IN')}/month SIP in Nifty 50 index fund. In 30 years, this could grow to ₹${(futureValue / 10000000).toFixed(1)} crores! Time is your biggest asset.`)
    } else if (age >= 30 && age < 40) {
      tips.push(`📈 Perfect age for wealth building! Allocate 60% to equity, 30% to debt, and 10% to gold. Review your portfolio quarterly and rebalance if needed.`)
    } else if (age >= 40 && age < 50) {
      tips.push(`🎯 At ${age}, shift to 50-50 equity-debt allocation. Ensure you have term insurance (10x annual income) and ₹10L+ health insurance for family security.`)
    } else if (age >= 50) {
      tips.push(`🛡️ At ${age}, focus on capital preservation. Move to 30% equity, 60% debt, 10% gold. Ensure adequate health coverage - medical costs rise 15% annually!`)
    }

    // 3. Family-size specific tips
    if (familySize === 1) {
      tips.push(`👤 As a single person, you can save aggressively! Aim for 30% savings rate and build a 6-month emergency fund of ₹${(monthlyIncome * 6).toLocaleString('en-IN')}.`)
    } else if (familySize === 2) {
      tips.push(`👫 With 2 members, get health insurance (₹5L family floater) and term insurance. Cost: ~₹1,500/month for comprehensive coverage.`)
    } else if (familySize > 3) {
      const healthCover = familySize * 300000
      tips.push(`👨‍👩‍👧‍👦 With ${familySize} members, prioritize ₹${(healthCover / 100000).toFixed(0)}L health insurance and ₹${((monthlyIncome * 120) / 100000).toFixed(0)}L term insurance. Don't risk your family's future!`)
    }

    // 4. City-specific optimization tips
    if (city === 'Mumbai' && housingPercentage > 35) {
      tips.push(`🏠 In Mumbai, your housing cost is ${housingPercentage}%! Consider suburbs like Thane/Navi Mumbai to reduce rent by 30-40% without compromising lifestyle.`)
    } else if (city === 'Delhi' || city === 'Bangalore') {
      tips.push(`🚗 In ${city}, use metro/bus instead of cab daily. Switching from Ola/Uber (₹200/day) to metro (₹60/day) saves ₹4,200/month = ₹50,400/year!`)
    } else if (city === 'Kolkata' || city === 'Hyderabad') {
      tips.push(`💰 ${city} has lower living costs - use this advantage to save aggressively! Aim for 25% savings rate while maintaining quality of life.`)
    }

    // 5. Income-based tax optimization
    if (monthlyIncome > 50000) {
      const taxSaved = Math.min(46800, monthlyIncome * 3 * 0.312) // 30% tax + cess
      tips.push(`💼 Your income bracket allows tax savings! Invest ₹12,500/month in ELSS + PPF to save up to ₹${Math.round(taxSaved).toLocaleString('en-IN')}/year in taxes under Section 80C.`)
    } else if (monthlyIncome > 25000) {
      tips.push(`📊 Start small: ₹500/month ELSS SIP grows to ₹15+ lakhs in 20 years (12% CAGR) + you save taxes. Every rupee saved is a rupee earned!`)
    }

    // 6. Food expense optimization
    if (foodPercentage > 30) {
      const currentFood = budget.categories?.food_dining?.amount || 0
      const targetFood = monthlyIncome * 0.25
      const savings = currentFood - targetFood
      tips.push(`🍽️ Food expenses are ${foodPercentage}% - reduce eating out from 10 times to 5 times/month. Save ₹${Math.round(savings).toLocaleString('en-IN')}/month by cooking at home!`)
    } else if (foodPercentage < 20 && familySize > 2) {
      tips.push(`🍽️ Your food budget seems tight for ${familySize} members. Ensure nutritious meals - health is wealth! Consider increasing by ₹1,000-2,000/month.`)
    }

    // 7. Emergency fund urgency
    const hasEmergencyFund = false // This should come from actual data
    if (!hasEmergencyFund) {
      const emergencyTarget = monthlyIncome * 6
      const monthlySaving = emergencyTarget / 12
      tips.push(`🆘 Build emergency fund FIRST! Save ₹${Math.round(monthlySaving).toLocaleString('en-IN')}/month for 12 months to create ₹${emergencyTarget.toLocaleString('en-IN')} safety net. Life is unpredictable!`)
    }

    // 8. Automation tip (always useful)
    tips.push(`🤖 Automate your savings! Set up auto-debit on salary day for SIP, insurance, and savings. "Pay yourself first" - what's left is for expenses.`)

    // Return top 5 most relevant tips
    return tips.slice(0, 5)
  }

  /**
   * Generate fallback recommendations in English with enhanced specificity
   */
  generateFallbackRecommendations(userProfile, budget) {
    const { monthlyIncome, familySize, age, city } = userProfile
    const recommendations = []

    console.log('Generating enhanced fallback recommendations for:', { monthlyIncome, age, city, familySize })

    // 1. Emergency fund (Critical priority)
    const emergencyFund = monthlyIncome * 6
    const monthlyEmergencySaving = emergencyFund / 12 // Assuming 1-year goal
    recommendations.push({
      type: 'Emergency Fund',
      amount: emergencyFund,
      description: `Build an emergency fund of ₹${emergencyFund.toLocaleString('en-IN')} (6 months of expenses) in a high-interest savings account or liquid mutual fund. Save ₹${monthlyEmergencySaving.toLocaleString('en-IN')}/month to reach this goal in 12 months.`,
      priority: 'Critical',
      icon: '🛡️',
      timeline: '12 months',
      actionable: `Open a liquid fund account and set up auto-debit of ₹${monthlyEmergencySaving.toLocaleString('en-IN')}`
    })

    // 2. Age-appropriate investment recommendations
    if (age < 30) {
      const sipAmount = Math.round(budget.categories?.savings?.amount * 0.7 || monthlyIncome * 0.15)
      recommendations.push({
        type: 'Aggressive Equity Investment',
        amount: sipAmount,
        description: `At age ${age}, invest ₹${sipAmount.toLocaleString('en-IN')}/month in equity mutual funds through SIP. With 20-25 years of compounding, this could grow to ₹${(sipAmount * 12 * 25 * 2.5).toLocaleString('en-IN')} (assuming 12% CAGR).`,
        priority: 'High',
        icon: '📈',
        timeline: 'Long-term (20+ years)',
        actionable: 'Start SIP in 2-3 large-cap or index funds'
      })
    } else if (age < 40) {
      const sipAmount = Math.round(budget.categories?.savings?.amount * 0.6 || monthlyIncome * 0.12)
      recommendations.push({
        type: 'Balanced Investment Portfolio',
        amount: sipAmount,
        description: `Invest ₹${sipAmount.toLocaleString('en-IN')}/month: 60% in equity mutual funds and 40% in debt instruments for balanced growth with moderate risk.`,
        priority: 'High',
        icon: '📊',
        timeline: 'Medium to Long-term (10-15 years)',
        actionable: 'Diversify across equity and debt mutual funds'
      })
    } else if (age < 50) {
      const conservativeAmount = Math.round(budget.categories?.savings?.amount * 0.5 || monthlyIncome * 0.10)
      recommendations.push({
        type: 'Capital Preservation',
        amount: conservativeAmount,
        description: `Focus on capital preservation: Invest ₹${conservativeAmount.toLocaleString('en-IN')}/month in balanced advantage funds (40% equity, 60% debt) for stable returns.`,
        priority: 'High',
        icon: '💰',
        timeline: 'Medium-term (5-10 years)',
        actionable: 'Shift to conservative hybrid funds'
      })
    } else {
      const retirementAmount = Math.round(budget.categories?.savings?.amount * 0.4 || monthlyIncome * 0.08)
      recommendations.push({
        type: 'Retirement Corpus',
        amount: retirementAmount,
        description: `At age ${age}, focus on retirement planning: Invest ₹${retirementAmount.toLocaleString('en-IN')}/month in senior citizen schemes and debt funds for regular income.`,
        priority: 'Critical',
        icon: '🏖️',
        timeline: 'Short to Medium-term (5 years)',
        actionable: 'Consider Senior Citizens Savings Scheme (SCSS) and debt funds'
      })
    }

    // 3. Insurance recommendations (Family protection)
    const lifeInsuranceCover = monthlyIncome * 120 // 10 years of income
    const termInsurancePremium = Math.round(lifeInsuranceCover / 1000) // Approx ₹1/thousand
    recommendations.push({
      type: 'Term Life Insurance',
      amount: lifeInsuranceCover,
      description: `Get term life insurance coverage of ₹${(lifeInsuranceCover / 100000).toFixed(0)} lakhs to protect your ${familySize}-member family. Premium: ~₹${termInsurancePremium.toLocaleString('en-IN')}/month.`,
      priority: 'Critical',
      icon: '🛡️',
      timeline: 'Immediate',
      actionable: `Compare term plans online and buy ₹${(lifeInsuranceCover / 100000).toFixed(0)}L cover this week`
    })

    // 4. Health Insurance (Family coverage)
    const healthCover = Math.max(500000, familySize * 300000) // Min 5L, 3L per member
    const healthPremium = Math.round(healthCover / 100) // Approx calculation
    recommendations.push({
      type: 'Health Insurance',
      amount: healthCover,
      description: `Ensure ₹${(healthCover / 100000).toFixed(0)} lakhs health insurance for your ${familySize}-member family. Medical inflation is 12-15% annually in ${city}. Premium: ~₹${healthPremium.toLocaleString('en-IN')}/month.`,
      priority: 'High',
      icon: '🏥',
      timeline: 'Immediate',
      actionable: 'Get family floater health insurance with ₹5L+ coverage'
    })

    // 5. Tax-saving recommendations (if income > 50k)
    if (monthlyIncome > 50000) {
      const taxSavingAmount = Math.min(150000, monthlyIncome * 3) // Max 80C limit
      const monthlySaving = Math.round(taxSavingAmount / 12)
      recommendations.push({
        type: 'Tax Optimization (80C)',
        amount: taxSavingAmount,
        description: `Save up to ₹46,800/year in taxes by investing ₹${monthlySaving.toLocaleString('en-IN')}/month in ELSS, PPF, or NPS. Your tax bracket: ${monthlyIncome > 150000 ? '30%' : monthlyIncome > 100000 ? '20%' : '10%'}.`,
        priority: 'High',
        icon: '💰',
        timeline: 'Annual (before March)',
        actionable: `Start ELSS SIP of ₹${monthlySaving.toLocaleString('en-IN')} immediately`
      })
    }

    // 6. City-specific recommendations
    if (city === 'Mumbai' || city === 'Delhi' || city === 'Bangalore') {
      const rentVsEmi = monthlyIncome * 0.35
      recommendations.push({
        type: 'Real Estate Planning',
        amount: Math.round(rentVsEmi * 80), // Approx home loan amount
        description: `In ${city}, consider home loan if rent > ₹${rentVsEmi.toLocaleString('en-IN')}. EMI could be similar to rent with tax benefits under Section 80C and 24(b).`,
        priority: 'Medium',
        icon: '🏠',
        timeline: 'Long-term planning',
        actionable: 'Calculate rent vs EMI with tax benefits'
      })
    }

    console.log('Generated recommendations:', recommendations)
    console.log('Recommendations count:', recommendations.length)

    return recommendations
  }

  /**
   * Get category-specific explanations in English
   */
  getCategoryExplanation(categoryKey, categoryData, userProfile) {
    const { familySize, city, monthlyIncome } = userProfile

    const explanationTemplates = {
      food_dining: `₹${categoryData.amount.toLocaleString('en-IN')} for food & dining is appropriate for a ${familySize}-member family. This includes home cooking, groceries, and occasional dining out.`,

      home_utilities: `₹${categoryData.amount.toLocaleString('en-IN')} for housing and utilities considering the living costs in ${city}. This covers rent/EMI, electricity, water, gas, and maintenance.`,

      transportation: `₹${categoryData.amount.toLocaleString('en-IN')} for transportation includes fuel, public transport, maintenance, and occasional cab rides for your daily commute.`,

      savings: `₹${categoryData.amount.toLocaleString('en-IN')} (${categoryData.percentage}%) savings rate is ${categoryData.percentage >= 20 ? 'excellent' : categoryData.percentage >= 15 ? 'good' : 'needs improvement'}. Consider investing this amount for long-term wealth building.`,

      healthcare: `₹${categoryData.amount.toLocaleString('en-IN')} allocated for healthcare including regular checkups, medicines, and health insurance premiums for your family's well-being.`,

      entertainment: `₹${categoryData.amount.toLocaleString('en-IN')} for entertainment and leisure activities helps maintain work-life balance while staying within budget.`,

      education: `₹${categoryData.amount.toLocaleString('en-IN')} for education and skill development is an investment in your future earning potential.`,

      personal_care: `₹${categoryData.amount.toLocaleString('en-IN')} for personal care, clothing, and grooming expenses to maintain your personal and professional appearance.`,

      miscellaneous: `₹${categoryData.amount.toLocaleString('en-IN')} kept aside for unexpected expenses and miscellaneous costs that aren't covered in other categories.`
    }

    return explanationTemplates[categoryKey] || `₹${categoryData.amount.toLocaleString('en-IN')} allocated for ${categoryData.englishName} based on your income and family needs.`
  }

  /**
   * Validate user input for budget generation
   */
  static validateInput(userProfile) {
    const errors = []

    if (!userProfile.monthlyIncome || userProfile.monthlyIncome < 1000) {
      errors.push('Monthly income must be at least ₹1,000')
    }

    if (userProfile.monthlyIncome > 10000000) {
      errors.push('Monthly income seems unusually high. Please verify the amount.')
    }

    if (!userProfile.city || userProfile.city.trim().length < 2) {
      errors.push('Please provide a valid city name')
    }

    if (!userProfile.familySize || userProfile.familySize < 1 || userProfile.familySize > 20) {
      errors.push('Family size must be between 1 and 20')
    }

    if (!userProfile.age || userProfile.age < 18 || userProfile.age > 100) {
      errors.push('Age must be between 18 and 100')
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  /**
   * Get budget health score
   */
  getBudgetHealthScore(budget) {
    let score = 0
    const categories = budget.categories

    // Savings rate scoring (40% of total score)
    const savingsRate = categories.savings.percentage
    if (savingsRate >= 20) score += 40
    else if (savingsRate >= 15) score += 30
    else if (savingsRate >= 10) score += 20
    else score += 10

    // Housing cost scoring (25% of total score)
    const housingRate = categories.home_utilities.percentage
    if (housingRate <= 30) score += 25
    else if (housingRate <= 40) score += 20
    else if (housingRate <= 50) score += 15
    else score += 5

    // Food expense scoring (20% of total score)
    const foodRate = categories.food_dining.percentage
    if (foodRate <= 25) score += 20
    else if (foodRate <= 35) score += 15
    else score += 10

    // Emergency fund readiness (15% of total score)
    if (categories.miscellaneous && categories.miscellaneous.percentage >= 5) {
      score += 15
    } else {
      score += 5
    }

    return Math.min(score, 100)
  }

  /**
   * Process lifestyle insights from quiz answers
   * Converts quiz answers into actionable insights for AI
   */
  processLifestyleInsights(lifestyleAnswers) {
    if (!lifestyleAnswers || Object.keys(lifestyleAnswers).length === 0) {
      return null
    }

    const insights = []

    // Additional income sources
    if (lifestyleAnswers.additional_income) {
      const incomeMap = {
        'freelance': '💼 Has freelance/side gig income (variable income consideration)',
        'rent': '🏠 Receives rental income (passive income stream)',
        'investment': '📈 Has investment returns/dividends (active investor)',
        'business': '🏢 Has family business income (entrepreneurial)',
        'none': '💰 Single primary income source (higher emergency fund priority)'
      }
      insights.push(incomeMap[lifestyleAnswers.additional_income] || '')
    }

    // Living situation
    if (lifestyleAnswers.living_situation) {
      const livingMap = {
        'family': '🏡 Living with family (no rent, lower housing costs)',
        'renting_alone': '🏠 Renting alone (higher privacy costs)',
        'sharing': '👥 Sharing rent with roommates (cost-conscious)',
        'emi': '🏦 Paying home loan EMI (asset building, fixed commitment)'
      }
      insights.push(livingMap[lifestyleAnswers.living_situation] || '')
    }

    // Eating habits
    if (lifestyleAnswers.eating_out) {
      const eatingMap = {
        'rarely': '🍽️ Eats out rarely (1-2 times/month) - disciplined food spending',
        'sometimes': '🍔 Moderate eating out (1-2 times/week) - balanced approach',
        'frequently': '🍕 Frequent eating out (3-5 times/week) - lifestyle priority',
        'daily': '🍜 Daily eating out - significant food budget needed'
      }
      insights.push(eatingMap[lifestyleAnswers.eating_out] || '')
    }

    // Meal preference
    if (lifestyleAnswers.meal_preference) {
      const mealMap = {
        'home_cooked': '👨‍🍳 Prefers home-cooked meals (cost-effective)',
        'mixed': '🥘 Mixed cooking habits (moderate food costs)',
        'outside': '🍱 Prefers outside food (convenience over cost)'
      }
      insights.push(mealMap[lifestyleAnswers.meal_preference] || '')
    }

    // Vehicle ownership
    if (lifestyleAnswers.vehicle) {
      const vehicleMap = {
        'no': '🚇 No vehicle (public transport user, lower maintenance costs)',
        '2wheeler': '🛵 Owns 2-wheeler (moderate transport costs)',
        '4wheeler': '🚗 Owns 4-wheeler (higher fuel & maintenance)',
        'both': '🚗🛵 Owns both vehicles (significant transport investment)'
      }
      insights.push(vehicleMap[lifestyleAnswers.vehicle] || '')
    }

    // Shopping frequency
    if (lifestyleAnswers.shopping_frequency) {
      const shopMap = {
        'rarely': '🛍️ Shops rarely (minimal shopping, needs-based)',
        'monthly': '🛒 Monthly shopper (planned purchases)',
        'weekly': '💳 Weekly shopper (frequent purchases, lifestyle spending)'
      }
      insights.push(shopMap[lifestyleAnswers.shopping_frequency] || '')
    }

    // Entertainment subscriptions
    if (lifestyleAnswers.subscriptions) {
      const subMap = {
        'none': '📺 No entertainment subscriptions (minimal recurring costs)',
        '1-2': '🎬 1-2 subscriptions (Netflix, Spotify, etc.)',
        '3-5': '📱 3-5 subscriptions (multiple streaming services)',
        '5+': '💻 5+ subscriptions (heavy digital consumer)'
      }
      insights.push(subMap[lifestyleAnswers.subscriptions] || '')
    }

    // Travel habits
    if (lifestyleAnswers.travel) {
      const travelMap = {
        'rarely': '✈️ Travels rarely (once a year) - minimal travel budget',
        'occasionally': '🧳 Occasional traveler (2-3 times/year) - moderate travel fund',
        'regularly': '🌍 Regular traveler (monthly/quarterly) - significant travel allocation'
      }
      insights.push(travelMap[lifestyleAnswers.travel] || '')
    }

    // Health insurance
    if (lifestyleAnswers.health_insurance) {
      const insuranceMap = {
        'no': '🩺 No health insurance (URGENT: needs coverage)',
        'individual': '🏥 Has individual health policy (good coverage)',
        'family': '👨‍⚕️ Has family floater policy (comprehensive protection)'
      }
      insights.push(insuranceMap[lifestyleAnswers.health_insurance] || '')
    }

    // Fitness spending
    if (lifestyleAnswers.fitness_spend) {
      const fitnessMap = {
        '0-1k': '💪 Minimal fitness spending (<₹1k) - home workouts',
        '1k-3k': '🏃 Moderate fitness (₹1-3k) - gym/classes',
        '3k-5k': '🏋️ Active fitness (₹3-5k) - premium memberships',
        '5k+': '🤸 High fitness investment (₹5k+) - personal trainers/premium'
      }
      insights.push(fitnessMap[lifestyleAnswers.fitness_spend] || '')
    }

    // Learning investment
    if (lifestyleAnswers.learning_invest) {
      const learningMap = {
        'no': '📚 No learning investments (potential growth area)',
        'occasionally': '🎓 Occasional learner (periodic courses/books)',
        'regularly': '📖 Regular learner (continuous self-improvement)'
      }
      insights.push(learningMap[lifestyleAnswers.learning_invest] || '')
    }

    // Financial goal
    if (lifestyleAnswers.financial_goal) {
      const goalMap = {
        'savings': '🎯 Goal: Build savings (accumulation phase)',
        'debt': '💳 Goal: Repay debt (debt freedom priority)',
        'travel': '✈️ Goal: Save for travel (experience-focused)',
        'house': '🏡 Goal: Buy a house (major asset purchase)',
        'investment': '📈 Goal: Increase investments (wealth building)'
      }
      insights.push(goalMap[lifestyleAnswers.financial_goal] || '')
    }

    // Money mindset
    if (lifestyleAnswers.money_mindset) {
      const mindsetMap = {
        'save_first': '⚖️ Save-first mindset (high financial discipline)',
        'balanced': '⚖️ Balanced approach (moderate spending & saving)',
        'spend_first': '⚖️ Spend-first mindset (enjoy now, needs better planning)'
      }
      insights.push(mindsetMap[lifestyleAnswers.money_mindset] || '')
    }

    // Upcoming expenses
    if (lifestyleAnswers.upcoming_expenses && lifestyleAnswers.upcoming_expenses !== 'none') {
      const expenseMap = {
        'travel': '🧳 Upcoming: Travel plans (need travel fund)',
        'wedding': '💒 Upcoming: Wedding/event (major expense ahead)',
        'gadget': '📱 Upcoming: Gadget/vehicle purchase (planned purchase)',
        'renovation': '🏠 Upcoming: Home renovation (capital expense)'
      }
      insights.push(expenseMap[lifestyleAnswers.upcoming_expenses] || '')
    }

    // Dependents
    if (lifestyleAnswers.dependents) {
      const depMap = {
        '0': '👤 No financial dependents (flexible budget)',
        '1': '👨‍👩‍👧 1 dependent (moderate responsibility)',
        '2': '👨‍👩‍👧‍👦 2 dependents (family responsibilities)',
        '3+': '👨‍👩‍👧‍👦 3+ dependents (high responsibility, larger insurance needs)'
      }
      insights.push(depMap[lifestyleAnswers.dependents] || '')
    }

    return insights.length > 0 ? insights.join('\n• ') : null
  }

  /**
   * Calculate income stability ratio from multiple income sources
   * @param {Array} incomeSources - Array of income source objects
   * @param {number} fallbackIncome - Fallback monthly income if no sources
   * @returns {Object} Income stability data
   */
  calculateIncomeStability(incomeSources, fallbackIncome) {
    // If no income sources, assume stable single income
    if (!incomeSources || incomeSources.length === 0) {
      return {
        stabilityRatio: 100,
        totalMonthlyIncome: fallbackIncome,
        stableIncome: fallbackIncome,
        variableIncome: 0,
        recommendation: 'standard',
        emergencyFundMonths: 6,
        description: 'Single stable income source'
      }
    }

    // Frequency multipliers to normalize to monthly
    const frequencyMultipliers = {
      weekly: 4.33,
      'bi-weekly': 2.17,
      monthly: 1,
      quarterly: 0.33,
      annually: 0.083,
      irregular: 1
    }

    // Calculate total and stable income
    let totalMonthly = 0
    let stableMonthly = 0

    incomeSources.forEach(source => {
      if (!source.includeInBudget) return

      const multiplier = frequencyMultipliers[source.frequency] || 1
      const monthlyAmount = Math.round(source.amount * multiplier)

      totalMonthly += monthlyAmount
      if (source.isStable) {
        stableMonthly += monthlyAmount
      }
    })

    // Calculate stability ratio
    const stabilityRatio = totalMonthly > 0
      ? Math.round((stableMonthly / totalMonthly) * 100)
      : 100

    // Determine recommendation based on stability
    let recommendation = 'standard'
    let emergencyFundMonths = 6
    let description = ''

    if (stabilityRatio >= 80) {
      recommendation = 'standard'
      emergencyFundMonths = 6
      description = 'Highly stable income - standard financial planning applies'
    } else if (stabilityRatio >= 50) {
      recommendation = 'moderate_buffer'
      emergencyFundMonths = 9
      description = 'Mixed income stability - consider larger emergency buffer'
    } else {
      recommendation = 'high_buffer'
      emergencyFundMonths = 12
      description = 'Variable income dominant - prioritize larger emergency fund and conservative budgeting'
    }

    return {
      stabilityRatio,
      totalMonthlyIncome: totalMonthly || fallbackIncome,
      stableIncome: stableMonthly,
      variableIncome: totalMonthly - stableMonthly,
      recommendation,
      emergencyFundMonths,
      description,
      incomeSourcesCount: incomeSources.length,
      hasMultipleIncome: incomeSources.length > 1
    }
  }

  /**
   * Calculate seasonal reserve based on upcoming events
   * @param {number} monthlyIncome - Total monthly income
   * @param {Object} preferences - Seasonal planning preferences
   * @param {Array} userEvents - User's custom seasonal events
   * @param {number} familySize - Family size for expense estimation
   * @returns {Object} Seasonal reserve data
   */
  calculateSeasonalReserve(monthlyIncome, preferences = {}, userEvents = [], familySize = 1) {
    // Check if seasonal planning is enabled
    const enabled = preferences?.enabled !== false

    if (!enabled) {
      return {
        enabled: false,
        monthlyReserve: 0,
        percentage: 0,
        upcomingEvents: [],
        totalRequired: 0,
        description: 'Seasonal planning is disabled'
      }
    }

    try {
      // Get upcoming events from the calendar (next 12 months)
      const calendarEvents = getUpcomingEvents(12, new Date())

      // Combine with user events
      const allEvents = [
        ...calendarEvents,
        ...userEvents.filter(e => e.enabled !== false)
      ]

      // Use seasonal planner to calculate reserve
      const plannerResult = seasonalPlanner.calculateSeasonalReserve(
        monthlyIncome,
        preferences,
        allEvents
      )

      // Cap at 20% of income
      const maxReserve = monthlyIncome * 0.20
      const cappedReserve = Math.min(plannerResult.monthlyReserve || 0, maxReserve)
      const percentage = Math.round((cappedReserve / monthlyIncome) * 100)

      // Get top 3 upcoming events for display
      const topEvents = plannerResult.upcomingEvents?.slice(0, 3) || []

      return {
        enabled: true,
        monthlyReserve: Math.round(cappedReserve),
        percentage,
        upcomingEvents: topEvents,
        totalRequired: plannerResult.totalRequired || 0,
        totalEventsCount: allEvents.length,
        description: cappedReserve > 0
          ? `Save ₹${cappedReserve.toLocaleString('en-IN')}/month for upcoming festivals and events`
          : 'No immediate seasonal expenses detected'
      }
    } catch (error) {
      console.error('Error calculating seasonal reserve:', error)
      return {
        enabled: true,
        monthlyReserve: 0,
        percentage: 0,
        upcomingEvents: [],
        totalRequired: 0,
        description: 'Unable to calculate seasonal reserve',
        error: error.message
      }
    }
  }
}


// Export singleton instance
export const budgetGenerator = new AIBudgetGenerator()
