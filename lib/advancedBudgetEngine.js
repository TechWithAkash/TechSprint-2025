// lib/advancedBudgetEngine.js
/**
 * Advanced Budget Generation Engine
 * 
 * This module implements sophisticated financial planning algorithms designed
 * specifically for Indian middle-class families. It goes beyond simple percentage
 * allocation to provide realistic, actionable, and personalized budgets.
 * 
 * Key Features:
 * - Multiple budgeting frameworks (50-30-20, 80-20, Zero-based, Custom)
 * - Real cost-of-living data for Indian cities
 * - Behavioral spending pattern analysis
 * - Income-bracket specific recommendations
 * - Life-stage financial planning
 * - Dynamic allocation based on actual expenses
 */

/**
 * Real cost-of-living data for major Indian cities (2024-2025 data)
 * Based on actual market research and expense patterns
 */
export const REAL_CITY_EXPENSES = {
    'Mumbai': {
        rentRange: {
            '1BHK': { min: 18000, typical: 25000, premium: 35000 },
            '2BHK': { min: 28000, typical: 40000, premium: 60000 },
            '3BHK': { min: 45000, typical: 65000, premium: 95000 }
        },
        groceries: {
            single: 4000,
            couple: 7000,
            family3: 10000,
            family4plus: 13000
        },
        transport: {
            public: 2500,
            mixed: 4500,
            ownVehicle: 7000
        },
        utilities: 3500,
        costMultiplier: 1.0, // Base city (highest cost)
        domesticHelp: 5000
    },
    'Delhi': {
        rentRange: {
            '1BHK': { min: 12000, typical: 18000, premium: 28000 },
            '2BHK': { min: 20000, typical: 30000, premium: 45000 },
            '3BHK': { min: 32000, typical: 48000, premium: 70000 }
        },
        groceries: {
            single: 3500,
            couple: 6500,
            family3: 9500,
            family4plus: 12000
        },
        transport: {
            public: 2000,
            mixed: 3800,
            ownVehicle: 6000
        },
        utilities: 3000,
        costMultiplier: 0.85,
        domesticHelp: 4000
    },
    'Bangalore': {
        rentRange: {
            '1BHK': { min: 13000, typical: 20000, premium: 30000 },
            '2BHK': { min: 22000, typical: 32000, premium: 48000 },
            '3BHK': { min: 35000, typical: 50000, premium: 75000 }
        },
        groceries: {
            single: 3800,
            couple: 6800,
            family3: 9800,
            family4plus: 12500
        },
        transport: {
            public: 2200,
            mixed: 4000,
            ownVehicle: 6500
        },
        utilities: 2800,
        costMultiplier: 0.88,
        domesticHelp: 4500
    },
    'Hyderabad': {
        rentRange: {
            '1BHK': { min: 10000, typical: 15000, premium: 22000 },
            '2BHK': { min: 16000, typical: 24000, premium: 35000 },
            '3BHK': { min: 25000, typical: 38000, premium: 55000 }
        },
        groceries: {
            single: 3200,
            couple: 6000,
            family3: 8500,
            family4plus: 11000
        },
        transport: {
            public: 1800,
            mixed: 3200,
            ownVehicle: 5500
        },
        utilities: 2500,
        costMultiplier: 0.75,
        domesticHelp: 3500
    },
    'Chennai': {
        rentRange: {
            '1BHK': { min: 10000, typical: 16000, premium: 24000 },
            '2BHK': { min: 18000, typical: 26000, premium: 38000 },
            '3BHK': { min: 28000, typical: 42000, premium: 60000 }
        },
        groceries: {
            single: 3300,
            couple: 6200,
            family3: 9000,
            family4plus: 11500
        },
        transport: {
            public: 1900,
            mixed: 3400,
            ownVehicle: 5800
        },
        utilities: 2600,
        costMultiplier: 0.78,
        domesticHelp: 3800
    },
    'Pune': {
        rentRange: {
            '1BHK': { min: 11000, typical: 16000, premium: 24000 },
            '2BHK': { min: 18000, typical: 26000, premium: 38000 },
            '3BHK': { min: 28000, typical: 40000, premium: 58000 }
        },
        groceries: {
            single: 3400,
            couple: 6300,
            family3: 9200,
            family4plus: 11800
        },
        transport: {
            public: 2000,
            mixed: 3500,
            ownVehicle: 6000
        },
        utilities: 2700,
        costMultiplier: 0.80,
        domesticHelp: 3800
    },
    'Kolkata': {
        rentRange: {
            '1BHK': { min: 8000, typical: 12000, premium: 18000 },
            '2BHK': { min: 14000, typical: 20000, premium: 30000 },
            '3BHK': { min: 22000, typical: 32000, premium: 48000 }
        },
        groceries: {
            single: 2800,
            couple: 5500,
            family3: 8000,
            family4plus: 10500
        },
        transport: {
            public: 1500,
            mixed: 2800,
            ownVehicle: 5000
        },
        utilities: 2200,
        costMultiplier: 0.68,
        domesticHelp: 3000
    }
}

/**
 * Income bracket definitions with realistic expense patterns
 * Based on actual spending behavior in India
 * Enhanced with peer insights, tax optimization, and investment guidance
 */
export const INCOME_BRACKETS = {
    // Lower Middle Class (₹25k - ₹40k)
    'lower_middle': {
        range: { min: 25000, max: 40000 },
        profile: 'Cost-conscious, needs-based spending',
        typicalExpenses: {
            housing: 0.35, // Often 1BHK or shared accommodation
            food: 0.28,
            transport: 0.08,
            utilities: 0.06,
            healthcare: 0.05,
            education: 0.03,
            entertainment: 0.04,
            savings: 0.11
        },
        savingsTarget: { min: 10, ideal: 15, max: 20 },
        recommendations: [
            'Focus on building 3-month emergency fund first',
            'Use public transport to save costs',
            'Cook at home to reduce food expenses',
            'Start micro-SIPs (₹500-1000/month)',
            'Get basic health insurance (₹3-5L cover)'
        ],
        // Enhanced income insights
        incomeInsights: {
            savingsRateTarget: 15,
            targetEmergencyFund: 3, // months
            investmentAllocation: { equity: 60, debt: 30, gold: 10 },
            benchmarks: {
                averageSavingsRate: 12,
                topPerformerSavingsRate: 20
            },
            peerInsights: {
                commonGoals: ['Emergency fund', 'Basic insurance', 'Debt clearance'],
                commonChallenges: ['High living costs', 'Limited savings capacity', 'Irregular expenses'],
                successStrategies: [
                    'Automate savings at month start (pay yourself first)',
                    'Use cash envelope system for discretionary spending',
                    'Build skills to increase income potential',
                    'Avoid lifestyle inflation when getting raises'
                ]
            },
            taxOptimization: {
                applicable: false,
                taxBracket: '0% (Below taxable limit)',
                tips: [
                    'Focus on building corpus rather than tax saving',
                    'Start PPF for long-term tax-free growth',
                    'Avoid tax-saving instruments with lock-in if liquidity needed'
                ]
            }
        }
    },

    // Middle Class (₹40k - ₹75k)
    'middle': {
        range: { min: 40000, max: 75000 },
        profile: 'Balanced lifestyle, moderate savings',
        typicalExpenses: {
            housing: 0.32,
            food: 0.25,
            transport: 0.10,
            utilities: 0.05,
            healthcare: 0.06,
            education: 0.04,
            entertainment: 0.06,
            savings: 0.12
        },
        savingsTarget: { min: 15, ideal: 20, max: 25 },
        recommendations: [
            'Build 6-month emergency fund',
            'Start SIP investments (₹3000-5000/month)',
            'Get term insurance (50-75L cover)',
            'Increase health insurance to ₹5-10L',
            'Consider tax-saving investments (80C)'
        ],
        // Enhanced income insights
        incomeInsights: {
            savingsRateTarget: 20,
            targetEmergencyFund: 6, // months
            investmentAllocation: { equity: 65, debt: 25, gold: 10 },
            benchmarks: {
                averageSavingsRate: 16,
                topPerformerSavingsRate: 28
            },
            peerInsights: {
                commonGoals: ['Home ownership', 'Child education', 'Retirement corpus'],
                commonChallenges: ['Balancing EMIs with savings', 'Rising education costs', 'Lifestyle expenses'],
                successStrategies: [
                    'Follow 50-30-20 budgeting rule strictly',
                    'Increase SIP by 10% annually with salary hike',
                    'Use tax-saving instruments strategically',
                    'Maintain discipline despite peer pressure'
                ]
            },
            taxOptimization: {
                applicable: true,
                taxBracket: '5-20% (Old regime) / New regime beneficial',
                tips: [
                    'Maximize 80C deductions (₹1.5L) through ELSS/PPF',
                    'Get health insurance for 80D benefits (₹25k-50k)',
                    'Compare old vs new tax regime annually',
                    'Consider NPS for additional 80CCD(1B) benefit (₹50k)'
                ]
            }
        }
    },

    // Upper Middle Class (₹75k - ₹1.5L)
    'upper_middle': {
        range: { min: 75000, max: 150000 },
        profile: 'Comfortable lifestyle, good savings potential',
        typicalExpenses: {
            housing: 0.28,
            food: 0.22,
            transport: 0.12,
            utilities: 0.04,
            healthcare: 0.07,
            education: 0.05,
            entertainment: 0.08,
            savings: 0.14
        },
        savingsTarget: { min: 20, ideal: 25, max: 35 },
        recommendations: [
            'Build 9-12 month emergency fund',
            'Invest in diversified portfolio (₹10k-20k/month)',
            'Get comprehensive term insurance (₹1-2Cr)',
            'Super top-up health insurance (₹20L+)',
            'Max out 80C benefits (₹1.5L/year)',
            'Consider NPS for additional tax benefits'
        ],
        // Enhanced income insights
        incomeInsights: {
            savingsRateTarget: 25,
            targetEmergencyFund: 9, // months
            investmentAllocation: { equity: 60, debt: 30, gold: 10 },
            benchmarks: {
                averageSavingsRate: 22,
                topPerformerSavingsRate: 35
            },
            peerInsights: {
                commonGoals: ['Wealth accumulation', 'Premium lifestyle', 'Early retirement', 'Children abroad education'],
                commonChallenges: ['Lifestyle inflation', 'Multiple financial goals', 'Tax optimization'],
                successStrategies: [
                    'Create separate SIPs for each financial goal',
                    'Use bucket strategy for investments',
                    'Diversify across asset classes including international',
                    'Review portfolio quarterly with rebalancing'
                ]
            },
            taxOptimization: {
                applicable: true,
                taxBracket: '20-30% (Maximize all deductions)',
                tips: [
                    'Old tax regime often more beneficial at this income',
                    'Maximize all Chapter VI-A deductions',
                    'Use HRA + home loan interest for dual benefit',
                    'Consider salary restructuring (food coupons, LTA, NPS)',
                    'Invest in ELSS over PPF for better returns + tax saving'
                ]
            }
        }
    },

    // Affluent (₹1.5L+)
    'affluent': {
        range: { min: 150000, max: Infinity },
        profile: 'Premium lifestyle, high savings capacity',
        typicalExpenses: {
            housing: 0.25,
            food: 0.18,
            transport: 0.12,
            utilities: 0.03,
            healthcare: 0.08,
            education: 0.06,
            entertainment: 0.10,
            savings: 0.18
        },
        savingsTarget: { min: 25, ideal: 30, max: 40 },
        recommendations: [
            'Maintain 12-month emergency fund',
            'Aggressive wealth creation (₹30k-50k/month)',
            'Term insurance ₹2-5Cr + whole life insurance',
            'Premium health insurance (₹50L+ family floater)',
            'Tax optimization through multiple instruments',
            'Consider real estate and alternative investments',
            'Estate planning and wealth management'
        ],
        // Enhanced income insights
        incomeInsights: {
            savingsRateTarget: 30,
            targetEmergencyFund: 12, // months
            investmentAllocation: { equity: 55, debt: 25, gold: 10, alternatives: 10 },
            benchmarks: {
                averageSavingsRate: 28,
                topPerformerSavingsRate: 45
            },
            peerInsights: {
                commonGoals: ['Financial independence', 'Generational wealth', 'Multiple income streams', 'International diversification'],
                commonChallenges: ['Capital gains tax optimization', 'Asset allocation complexity', 'Finding quality advice'],
                successStrategies: [
                    'Work with fee-only financial advisor',
                    'Create family office structure for wealth management',
                    'Diversify internationally (US/global funds)',
                    'Consider alternative investments (REITs, AIFs, P2P)',
                    'Implement tax-loss harvesting annually'
                ]
            },
            taxOptimization: {
                applicable: true,
                taxBracket: '30% + surcharge (Aggressive tax planning needed)',
                tips: [
                    'New tax regime may be beneficial above ₹15L',
                    'Maximize equity investments for LTCG benefits',
                    'Use ELSS for tax saving + wealth creation',
                    'Consider family wealth transfer strategies',
                    'Explore tax-efficient investment vehicles (ULIP for HNI)',
                    'Utilize home loan interest for rental income offset'
                ]
            }
        }
    }
}

/**
 * Multiple budgeting frameworks for different user preferences
 */
export const BUDGETING_FRAMEWORKS = {
    // 50-30-20 Rule (Needs-Wants-Savings)
    'rule_50_30_20': {
        name: '50-30-20 Rule',
        description: 'Popular framework: 50% needs, 30% wants, 20% savings',
        allocation: {
            needs: 0.50, // Essential expenses
            wants: 0.30, // Discretionary spending
            savings: 0.20  // Savings & investments
        },
        suitableFor: ['Middle class', 'Beginners', 'Balanced lifestyle'],
        breakdown: {
            needs: ['Housing', 'Food', 'Transportation', 'Utilities', 'Healthcare'],
            wants: ['Entertainment', 'Shopping', 'Dining out', 'Hobbies'],
            savings: ['Emergency fund', 'Investments', 'Retirement', 'Goals']
        }
    },

    // 80-20 Rule (Pay Yourself First)
    'rule_80_20': {
        name: '80-20 Rule',
        description: 'Simple approach: Save 20% first, spend remaining 80%',
        allocation: {
            expenses: 0.80,
            savings: 0.20
        },
        suitableFor: ['Young professionals', 'High earners', 'Aggressive savers'],
        breakdown: {
            expenses: ['All living expenses'],
            savings: ['Automated savings', 'Investments', 'Goals']
        }
    },

    // Zero-Based Budget (Every rupee assigned)
    'zero_based': {
        name: 'Zero-Based Budget',
        description: 'Assign every rupee a purpose, track meticulously',
        allocation: 'custom', // Calculated based on actual needs
        suitableFor: ['Detail-oriented', 'Variable income', 'Debt repayment'],
        breakdown: 'Detailed category-by-category allocation'
    },

    // Envelope System (Category limits)
    'envelope_system': {
        name: 'Envelope System',
        description: 'Set strict limits for each spending category',
        allocation: 'strict_limits',
        suitableFor: ['Overspenders', 'Cash-based spending', 'Discipline building'],
        breakdown: 'Fixed amount per category, no rollover'
    }
}

/**
 * Life stage financial priorities
 */
export const LIFE_STAGES = {
    'young_professional': {
        age: [22, 30],
        priorities: ['Career growth', 'Skill development', 'Aggressive investing'],
        riskTolerance: 'High',
        investmentHorizon: '25-35 years',
        focusAreas: {
            savings: 20,
            investments: 70, // Higher equity allocation
            insurance: 10
        },
        recommendations: [
            'Build emergency fund (3-6 months)',
            '80% equity, 20% debt allocation',
            'Term insurance (10x annual income)',
            'Basic health insurance',
            'Invest in skills and certifications'
        ]
    },

    'early_family': {
        age: [30, 40],
        priorities: ['Family security', 'Home planning', 'Child education'],
        riskTolerance: 'Moderate-High',
        investmentHorizon: '20-30 years',
        focusAreas: {
            savings: 15,
            investments: 60,
            insurance: 25
        },
        recommendations: [
            'Build 6-9 month emergency fund',
            '60-70% equity, 30-40% debt',
            'Comprehensive insurance (term + health)',
            'Start child education fund',
            'Consider home loan planning'
        ]
    },

    'established_family': {
        age: [40, 50],
        priorities: ['Wealth preservation', 'Retirement planning', 'Education'],
        riskTolerance: 'Moderate',
        investmentHorizon: '15-20 years',
        focusAreas: {
            savings: 10,
            investments: 55,
            insurance: 35
        },
        recommendations: [
            'Maintain 9-12 month emergency fund',
            '50% equity, 50% debt allocation',
            'Maximize insurance coverage',
            'Active retirement corpus building',
            'Review and rebalance portfolio annually'
        ]
    },

    'pre_retirement': {
        age: [50, 60],
        priorities: ['Capital preservation', 'Income generation', 'Healthcare'],
        riskTolerance: 'Low-Moderate',
        investmentHorizon: '10-15 years',
        focusAreas: {
            savings: 10,
            investments: 40,
            insurance: 50
        },
        recommendations: [
            'Maintain 12+ month emergency fund',
            '30-40% equity, 60-70% debt',
            'Comprehensive health coverage',
            'Shift to income-generating assets',
            'Estate planning and will preparation'
        ]
    }
}

/**
 * Advanced Budget Engine Class
 */
export class AdvancedBudgetEngine {
    constructor() {
        this.cityExpenses = REAL_CITY_EXPENSES
        this.incomeBrackets = INCOME_BRACKETS
        this.frameworks = BUDGETING_FRAMEWORKS
        this.lifeStages = LIFE_STAGES
    }

    /**
     * Generate realistic budget using advanced algorithms
     */
    generateRealisticBudget(userProfile) {
        const {
            monthlyIncome,
            city,
            familySize,
            age,
            occupation,
            hasHome = false,
            hasVehicle = false,
            hasChildren = false,
            spendingStyle = 'moderate' // conservative, moderate, liberal
        } = userProfile

        console.log('🎯 Generating advanced realistic budget for:', {
            income: monthlyIncome,
            city,
            familySize,
            age
        })

        // Step 1: Determine income bracket and life stage
        const incomeBracket = this.getIncomeBracket(monthlyIncome)
        const lifeStage = this.getLifeStage(age, familySize)

        // Step 2: Get real city expenses
        const cityData = this.getRealCityExpenses(city, familySize, hasHome, hasVehicle)

        // Step 3: Calculate realistic allocations
        const baseAllocations = this.calculateBaseAllocations(
            monthlyIncome,
            incomeBracket,
            lifeStage,
            cityData,
            spendingStyle
        )

        // Step 4: Apply behavioral adjustments
        const behavioralBudget = this.applyBehavioralAdjustments(
            baseAllocations,
            {
                familySize,
                hasChildren,
                age,
                occupation,
                spendingStyle
            }
        )

        // Step 5: Validate and optimize
        const optimizedBudget = this.validateAndOptimize(
            behavioralBudget,
            monthlyIncome,
            incomeBracket
        )

        // Step 6: Generate insights and recommendations
        const insights = this.generateAdvancedInsights(
            optimizedBudget,
            userProfile,
            incomeBracket,
            lifeStage,
            cityData
        )

        return {
            categories: optimizedBudget,
            totalBudget: monthlyIncome,
            framework: 'Advanced Realistic Model',
            incomeBracket: incomeBracket.profile,
            lifeStage: lifeStage.name,
            insights,
            metadata: {
                city,
                cityMultiplier: cityData.costMultiplier,
                realExpenses: cityData,
                savingsTarget: incomeBracket.savingsTarget,
                riskProfile: lifeStage.riskTolerance
            }
        }
    }

    /**
     * Determine income bracket
     */
    getIncomeBracket(monthlyIncome) {
        for (const [key, bracket] of Object.entries(this.incomeBrackets)) {
            if (monthlyIncome >= bracket.range.min && monthlyIncome < bracket.range.max) {
                return { ...bracket, key }
            }
        }
        return this.incomeBrackets.affluent
    }

    /**
     * Determine life stage
     */
    getLifeStage(age, familySize) {
        if (age >= 22 && age < 30) {
            return { ...this.lifeStages.young_professional, name: 'Young Professional' }
        } else if (age >= 30 && age < 40) {
            return { ...this.lifeStages.early_family, name: 'Early Family' }
        } else if (age >= 40 && age < 50) {
            return { ...this.lifeStages.established_family, name: 'Established Family' }
        } else {
            return { ...this.lifeStages.pre_retirement, name: 'Pre-Retirement' }
        }
    }

    /**
     * Get real city expenses based on actual cost data
     */
    getRealCityExpenses(city, familySize, hasHome, hasVehicle) {
        const cityData = this.cityExpenses[city] || this.cityExpenses['Pune']

        // Determine housing type based on family size
        let housingType = '1BHK'
        if (familySize >= 4) housingType = '3BHK'
        else if (familySize >= 2) housingType = '2BHK'

        // Get appropriate rent/EMI
        const housing = hasHome ?
            cityData.rentRange[housingType].typical * 0.6 : // EMI typically lower than rent
            cityData.rentRange[housingType].typical

        // Get appropriate grocery budget
        let groceries = cityData.groceries.single
        if (familySize >= 4) groceries = cityData.groceries.family4plus
        else if (familySize === 3) groceries = cityData.groceries.family3
        else if (familySize === 2) groceries = cityData.groceries.couple

        // Get transport cost
        const transport = hasVehicle ?
            cityData.transport.ownVehicle :
            cityData.transport.mixed

        return {
            ...cityData,
            estimatedHousing: housing,
            estimatedGroceries: groceries,
            estimatedTransport: transport,
            estimatedUtilities: cityData.utilities,
            housingType
        }
    }

    /**
     * Calculate base allocations using real expense data
     */
    calculateBaseAllocations(monthlyIncome, incomeBracket, lifeStage, cityData, spendingStyle) {
        const allocations = {}

        // Start with income bracket's typical expenses as base
        const baseExpenses = incomeBracket.typicalExpenses

        // Calculate actual amounts based on real costs
        const housingAmount = Math.min(
            cityData.estimatedHousing,
            monthlyIncome * 0.40 // Cap at 40% of income
        )

        const foodAmount = Math.min(
            cityData.estimatedGroceries + (monthlyIncome * 0.08), // Groceries + dining out
            monthlyIncome * 0.30 // Cap at 30%
        )

        const transportAmount = Math.min(
            cityData.estimatedTransport,
            monthlyIncome * 0.15 // Cap at 15%
        )

        const utilitiesAmount = cityData.estimatedUtilities

        // Calculate healthcare based on age and life stage
        const healthcareAmount = monthlyIncome * (lifeStage.age[0] >= 40 ? 0.08 : 0.06)

        // Entertainment and shopping based on spending style
        const discretionaryMultiplier = {
            conservative: 0.8,
            moderate: 1.0,
            liberal: 1.2
        }[spendingStyle]

        const entertainmentAmount = monthlyIncome * baseExpenses.entertainment * discretionaryMultiplier
        const shoppingAmount = monthlyIncome * 0.05 * discretionaryMultiplier

        // Calculate total expenses so far
        const totalExpenses = housingAmount + foodAmount + transportAmount +
            utilitiesAmount + healthcareAmount +
            entertainmentAmount + shoppingAmount

        // Savings is what's left, but ensure it meets minimum target
        const remainingForSavings = monthlyIncome - totalExpenses
        const minSavings = monthlyIncome * (incomeBracket.savingsTarget.min / 100)

        let savingsAmount = Math.max(remainingForSavings, minSavings)

        // If savings is too low, we need to adjust expenses
        if (savingsAmount < minSavings) {
            // Reduce discretionary expenses proportionally
            const deficit = minSavings - savingsAmount
            const adjustmentFactor = deficit / (entertainmentAmount + shoppingAmount)

            allocations.entertainment = Math.round(entertainmentAmount * (1 - adjustmentFactor))
            allocations.shopping = Math.round(shoppingAmount * (1 - adjustmentFactor))
            savingsAmount = minSavings
        } else {
            allocations.entertainment = Math.round(entertainmentAmount)
            allocations.shopping = Math.round(shoppingAmount)
        }

        // Combine housing and utilities
        allocations.home_utilities = Math.round(housingAmount + utilitiesAmount)
        allocations.food_dining = Math.round(foodAmount)
        allocations.transportation = Math.round(transportAmount)
        allocations.healthcare = Math.round(healthcareAmount)
        allocations.savings = Math.round(savingsAmount)

        return allocations
    }

    /**
     * Apply behavioral spending adjustments
     */
    applyBehavioralAdjustments(baseAllocations, userContext) {
        const { familySize, hasChildren, age, occupation, spendingStyle } = userContext
        const adjusted = { ...baseAllocations }

        // Family with children needs more healthcare and education budget
        if (hasChildren) {
            adjusted.healthcare = Math.round(adjusted.healthcare * 1.2)
            // Take from entertainment
            adjusted.entertainment = Math.round(adjusted.entertainment * 0.85)
        }

        // Younger people tend to spend more on entertainment and transport
        if (age < 30) {
            adjusted.entertainment = Math.round(adjusted.entertainment * 1.15)
            adjusted.transportation = Math.round(adjusted.transportation * 1.1)
            // Compensate from food
            adjusted.food_dining = Math.round(adjusted.food_dining * 0.95)
        }

        // Occupation-based adjustments
        if (occupation && occupation.toLowerCase().includes('business')) {
            // Business owners need higher emergency funds
            adjusted.savings = Math.round(adjusted.savings * 1.15)
            // Take from entertainment
            adjusted.entertainment = Math.round(adjusted.entertainment * 0.90)
        }

        return adjusted
    }

    /**
     * Validate budget and optimize allocations
     */
    validateAndOptimize(allocations, monthlyIncome, incomeBracket) {
        const optimized = { ...allocations }

        // Calculate total allocated
        const totalAllocated = Object.values(optimized).reduce((sum, val) => sum + val, 0)
        const difference = monthlyIncome - totalAllocated

        // If there's a significant difference, adjust savings
        if (Math.abs(difference) > 100) {
            optimized.savings += difference
        }

        // Ensure savings doesn't fall below minimum
        const minSavings = monthlyIncome * (incomeBracket.savingsTarget.min / 100)
        if (optimized.savings < minSavings) {
            const deficit = minSavings - optimized.savings

            // Reduce discretionary categories
            optimized.entertainment = Math.max(
                Math.round(optimized.entertainment - deficit * 0.5),
                Math.round(monthlyIncome * 0.03)
            )
            optimized.shopping = Math.max(
                Math.round(optimized.shopping - deficit * 0.5),
                Math.round(monthlyIncome * 0.02)
            )

            optimized.savings = minSavings
        }

        // Calculate percentages
        const result = {}
        for (const [key, amount] of Object.entries(optimized)) {
            result[key] = {
                amount: Math.round(amount),
                percentage: Math.round((amount / monthlyIncome) * 100),
                englishName: this.getCategoryName(key),
                emoji: this.getCategoryEmoji(key),
                description: this.getCategoryDescription(key)
            }
        }

        return result
    }

    /**
     * Generate advanced insights with specific, actionable advice
     */
    generateAdvancedInsights(budget, userProfile, incomeBracket, lifeStage, cityData) {
        const { monthlyIncome, city, familySize, age } = userProfile
        const savingsRate = budget.savings.percentage

        const insights = {
            budgetHealth: this.assessBudgetHealth(budget, incomeBracket),
            savingsAnalysis: this.analyzeSavingsRate(savingsRate, monthlyIncome, incomeBracket),
            housingAnalysis: this.analyzeHousingCost(budget.home_utilities, monthlyIncome, cityData),
            lifestyleBalance: this.assessLifestyleBalance(budget, incomeBracket),
            recommendations: this.generateTargetedRecommendations(
                budget,
                userProfile,
                incomeBracket,
                lifeStage,
                cityData
            ),
            actionItems: this.generateActionItems(budget, userProfile, incomeBracket),
            benchmarks: this.provideBenchmarks(budget, monthlyIncome, city, familySize)
        }

        return insights
    }

    /**
     * Assess overall budget health
     */
    assessBudgetHealth(budget, incomeBracket) {
        const savingsRate = budget.savings.percentage
        const housingRate = budget.home_utilities.percentage
        const foodRate = budget.food_dining.percentage

        let score = 100
        let grade = 'A+'
        const issues = []
        const strengths = []

        // Check savings rate
        if (savingsRate < incomeBracket.savingsTarget.min) {
            score -= 20
            issues.push(`Savings at ${savingsRate}% is below recommended ${incomeBracket.savingsTarget.min}%`)
        } else if (savingsRate >= incomeBracket.savingsTarget.ideal) {
            strengths.push(`Excellent savings rate of ${savingsRate}%`)
        }

        // Check housing cost
        if (housingRate > 40) {
            score -= 15
            issues.push(`Housing cost at ${housingRate}% is quite high`)
        } else if (housingRate <= 30) {
            strengths.push(`Efficient housing cost at ${housingRate}%`)
        }

        // Check food expenses
        if (foodRate > 35) {
            score -= 10
            issues.push(`Food expenses at ${foodRate}% seem high`)
        }

        // Assign grade
        if (score >= 90) grade = 'A+'
        else if (score >= 80) grade = 'A'
        else if (score >= 70) grade = 'B+'
        else if (score >= 60) grade = 'B'
        else grade = 'C'

        return {
            score,
            grade,
            status: score >= 70 ? 'Healthy' : score >= 50 ? 'Needs Improvement' : 'Concerning',
            issues,
            strengths
        }
    }

    /**
     * Analyze savings rate
     */
    analyzeSavingsRate(savingsRate, monthlyIncome, incomeBracket) {
        const monthlySavings = monthlyIncome * (savingsRate / 100)
        const yearlySavings = monthlySavings * 12
        const tenYearProjection = Math.round(yearlySavings * 10 * 1.8) // Assuming 12% CAGR

        return {
            currentRate: savingsRate,
            targetRate: incomeBracket.savingsTarget.ideal,
            monthlyAmount: Math.round(monthlySavings),
            yearlyAmount: Math.round(yearlySavings),
            tenYearProjection,
            status: savingsRate >= incomeBracket.savingsTarget.ideal ? 'Excellent' :
                savingsRate >= incomeBracket.savingsTarget.min ? 'Good' : 'Needs Improvement',
            recommendation: savingsRate < incomeBracket.savingsTarget.ideal ?
                `Increase savings by ₹${Math.round((monthlyIncome * (incomeBracket.savingsTarget.ideal - savingsRate) / 100))} to reach ${incomeBracket.savingsTarget.ideal}% target` :
                'Your savings rate is excellent! Focus on optimizing investment allocation'
        }
    }

    /**
     * Analyze housing cost
     */
    analyzeHousingCost(housingCategory, monthlyIncome, cityData) {
        const housingAmount = housingCategory.amount
        const housingPercentage = housingCategory.percentage
        const typicalRent = cityData.estimatedHousing

        return {
            currentAmount: housingAmount,
            percentage: housingPercentage,
            cityAverage: typicalRent,
            status: housingPercentage <= 30 ? 'Excellent' :
                housingPercentage <= 35 ? 'Good' :
                    housingPercentage <= 40 ? 'Acceptable' : 'High',
            recommendation: housingPercentage > 35 ?
                `Consider locations with lower rent to reduce housing cost from ${housingPercentage}% to 30%` :
                'Your housing cost is well-managed'
        }
    }

    /**
     * Assess lifestyle balance
     */
    assessLifestyleBalance(budget, incomeBracket) {
        const discretionary = (budget.entertainment?.percentage || 0) +
            (budget.shopping?.percentage || 0)
        const essential = 100 - discretionary - (budget.savings?.percentage || 0)

        return {
            discretionarySpending: discretionary,
            essentialSpending: essential,
            savingsRate: budget.savings?.percentage || 0,
            balance: discretionary < 15 ? 'Conservative' :
                discretionary < 25 ? 'Balanced' : 'Liberal',
            recommendation: discretionary > 25 ?
                'Consider reducing discretionary spending to boost savings' :
                'Your lifestyle spending is well-balanced'
        }
    }

    /**
     * Generate targeted, actionable recommendations
     */
    generateTargetedRecommendations(budget, userProfile, incomeBracket, lifeStage, cityData) {
        const recommendations = []
        const { monthlyIncome, age, familySize, city } = userProfile

        // 1. Emergency Fund Recommendation
        const emergencyFundTarget = monthlyIncome * 6
        recommendations.push({
            category: 'Emergency Fund',
            priority: 'Critical',
            action: `Build emergency fund of ₹${emergencyFundTarget.toLocaleString('en-IN')}`,
            timeframe: '12 months',
            monthlySIP: Math.round(emergencyFundTarget / 12),
            why: 'Essential safety net for unexpected expenses or income loss',
            howTo: [
                'Open high-interest savings account or liquid fund',
                `Set up auto-debit of ₹${Math.round(emergencyFundTarget / 12).toLocaleString('en-IN')}/month`,
                'Keep in easily accessible account',
                'Use only for genuine emergencies'
            ]
        })

        // 2. Insurance Recommendation
        const termCover = monthlyIncome * 120
        const healthCover = Math.max(500000, familySize * 300000)
        recommendations.push({
            category: 'Insurance Protection',
            priority: 'Critical',
            action: `Get ₹${(termCover / 100000).toFixed(0)}L term + ₹${(healthCover / 100000)}L health insurance`,
            cost: Math.round((termCover / 1000) + (healthCover / 100)),
            why: 'Protect your family from financial devastation',
            howTo: [
                `Compare term insurance online for ₹${(termCover / 100000).toFixed(0)}L cover`,
                `Get family floater health insurance ₹${(healthCover / 100000)}L`,
                'Buy before age 35 for lower premiums',
                'Review coverage annually'
            ]
        })

        // 3. Investment Strategy
        const investmentAmount = Math.round(budget.savings.amount * 0.7)
        const equityAllocation = age < 35 ? 70 : age < 45 ? 60 : 50
        recommendations.push({
            category: 'Investment Strategy',
            priority: 'High',
            action: `Invest ₹${investmentAmount.toLocaleString('en-IN')}/month`,
            allocation: `${equityAllocation}% equity, ${100 - equityAllocation}% debt`,
            expectedReturn: '10-12% CAGR',
            tenYearValue: Math.round(investmentAmount * 12 * 10 * 1.8).toLocaleString('en-IN'),
            howTo: [
                'Start SIP in 2-3 index funds (Nifty 50, Nifty Next 50)',
                'Use debt mutual funds for stable returns',
                'Rebalance portfolio annually',
                'Stay invested for long term (7+ years)'
            ]
        })

        // 4. Tax Optimization (if applicable)
        if (monthlyIncome > 50000) {
            const taxSavingPotential = Math.min(46800, monthlyIncome * 3 * 0.312)
            recommendations.push({
                category: 'Tax Optimization',
                priority: 'High',
                action: 'Maximize Section 80C benefits',
                savings: Math.round(taxSavingPotential).toLocaleString('en-IN'),
                howTo: [
                    'Invest ₹1.5L in ELSS mutual funds',
                    'Contribute to PPF (₹1.5L limit)',
                    'Consider NPS for additional ₹50k deduction',
                    'Get tax deduction on home loan interest (₹2L)'
                ]
            })
        }

        // 5. City-specific cost optimization
        if (budget.home_utilities.percentage > 35) {
            recommendations.push({
                category: 'Cost Optimization',
                priority: 'Medium',
                action: `Reduce housing cost in ${city}`,
                potentialSavings: Math.round((budget.home_utilities.amount - (monthlyIncome * 0.30)).toLocaleString('en-IN')),
                howTo: [
                    'Consider suburbs or affordable neighborhoods',
                    'Look for shared housing if single',
                    'Negotiate rent renewal',
                    'Consider house-sharing to split costs'
                ]
            })
        }

        // 6. Retirement Planning (for 35+)
        if (age >= 35) {
            const yearsToRetirement = 60 - age
            const retirementCorpus = monthlyIncome * 12 * 25 // 25x annual expenses
            const monthlySIP = Math.round(retirementCorpus / (yearsToRetirement * 12 * 2))

            recommendations.push({
                category: 'Retirement Planning',
                priority: 'High',
                action: 'Build retirement corpus',
                target: `₹${(retirementCorpus / 10000000).toFixed(1)} crores`,
                monthlyInvestment: monthlySIP.toLocaleString('en-IN'),
                yearsLeft: yearsToRetirement,
                howTo: [
                    `Invest ₹${monthlySIP.toLocaleString('en-IN')}/month in diversified funds`,
                    'Open NPS account for additional tax benefits',
                    'Consider EPF contributions',
                    'Review and increase SIP annually by 10%'
                ]
            })
        }

        return recommendations.slice(0, 5) // Return top 5 most relevant
    }

    /**
     * Generate specific action items for this month
     */
    generateActionItems(budget, userProfile, incomeBracket) {
        const { monthlyIncome, age } = userProfile
        const actions = []

        // Week 1: Set up emergency fund
        actions.push({
            week: 1,
            action: 'Set up emergency fund auto-debit',
            steps: [
                'Open liquid mutual fund account',
                'Link bank account',
                `Set up ₹${Math.round(monthlyIncome * 0.5).toLocaleString('en-IN')} monthly SIP`,
                'Enable auto-debit'
            ],
            timeRequired: '30 minutes'
        })

        // Week 2: Get insurance quotes
        actions.push({
            week: 2,
            action: 'Compare and buy insurance',
            steps: [
                'Compare term insurance quotes online',
                'Check health insurance options',
                'Read policy documents carefully',
                'Complete online purchase'
            ],
            timeRequired: '2 hours'
        })

        // Week 3: Start investment SIP
        actions.push({
            week: 3,
            action: 'Start investment SIP',
            steps: [
                'Download mutual fund app (Groww/Zerodha Coin)',
                'Complete KYC process',
                'Select 2-3 funds (index + flexi-cap)',
                'Set up SIP with auto-debit'
            ],
            timeRequired: '45 minutes'
        })

        // Week 4: Optimize recurring expenses
        actions.push({
            week: 4,
            action: 'Review and reduce recurring expenses',
            steps: [
                'List all subscriptions (OTT, gym, etc.)',
                'Cancel unused subscriptions',
                'Negotiate phone/internet bills',
                'Switch to annual plans for discounts'
            ],
            timeRequired: '1 hour',
            potentialSavings: '₹1,000-3,000/month'
        })

        return actions
    }

    /**
     * Provide benchmarks for comparison
     */
    provideBenchmarks(budget, monthlyIncome, city, familySize) {
        return {
            yourBudget: {
                housing: budget.home_utilities.percentage,
                food: budget.food_dining.percentage,
                transport: budget.transportation.percentage,
                savings: budget.savings.percentage
            },
            nationalAverage: {
                housing: 32,
                food: 25,
                transport: 10,
                savings: 15
            },
            idealBenchmark: {
                housing: 30,
                food: 25,
                transport: 10,
                savings: 20
            },
            yourCityAverage: {
                housing: city === 'Mumbai' ? 38 : city === 'Delhi' ? 35 : 32,
                food: 26,
                transport: city === 'Mumbai' || city === 'Delhi' ? 12 : 10,
                savings: 14
            }
        }
    }

    /**
     * Helper methods for category metadata
     */
    getCategoryName(key) {
        const names = {
            home_utilities: 'Home & Utilities',
            food_dining: 'Food & Dining',
            transportation: 'Transportation',
            healthcare: 'Healthcare',
            entertainment: 'Entertainment',
            shopping: 'Shopping',
            savings: 'Savings & Investments'
        }
        return names[key] || key
    }

    getCategoryEmoji(key) {
        const emojis = {
            home_utilities: '🏠',
            food_dining: '🍽️',
            transportation: '🚗',
            healthcare: '💊',
            entertainment: '🎬',
            shopping: '👕',
            savings: '💰'
        }
        return emojis[key] || '📊'
    }

    getCategoryDescription(key) {
        const descriptions = {
            home_utilities: 'Rent/EMI, electricity, water, gas, maintenance',
            food_dining: 'Groceries, restaurants, food delivery',
            transportation: 'Fuel, metro, bus, cab, vehicle maintenance',
            healthcare: 'Medicine, doctor visits, health insurance',
            entertainment: 'Movies, hobbies, subscriptions, outings',
            shopping: 'Clothes, shoes, accessories, personal care',
            savings: 'Emergency fund, investments, retirement planning'
        }
        return descriptions[key] || ''
    }

    /**
     * Get peer insights for user's income bracket
     * "Users like you" comparisons
     */
    getPeerInsights(monthlyIncome, userSavingsRate) {
        const bracket = this.getIncomeBracket(monthlyIncome)
        const insights = bracket.incomeInsights

        if (!insights) {
            return null
        }

        const savingsComparison = userSavingsRate >= insights.benchmarks.topPerformerSavingsRate
            ? 'top_performer'
            : userSavingsRate >= insights.benchmarks.averageSavingsRate
                ? 'above_average'
                : userSavingsRate >= insights.savingsRateTarget * 0.8
                    ? 'on_track'
                    : 'needs_improvement'

        const percentile = Math.min(99, Math.round(
            (userSavingsRate / insights.benchmarks.topPerformerSavingsRate) * 80
        ))

        return {
            incomeBracket: bracket.profile,
            userSavingsRate,
            peerAverageSavingsRate: insights.benchmarks.averageSavingsRate,
            topPerformerRate: insights.benchmarks.topPerformerSavingsRate,
            targetRate: insights.savingsRateTarget,
            savingsComparison,
            percentile,
            comparisonMessage: this.getSavingsComparisonMessage(savingsComparison, userSavingsRate, insights),
            commonGoals: insights.peerInsights.commonGoals,
            commonChallenges: insights.peerInsights.commonChallenges,
            successStrategies: insights.peerInsights.successStrategies,
            investmentAllocation: insights.investmentAllocation,
            emergencyFundTarget: {
                months: insights.targetEmergencyFund,
                amount: monthlyIncome * insights.targetEmergencyFund
            }
        }
    }

    /**
     * Get savings comparison message
     */
    getSavingsComparisonMessage(comparison, userRate, insights) {
        switch (comparison) {
            case 'top_performer':
                return `Excellent! You're saving ${userRate}%, which puts you among top performers in your income bracket. Keep it up!`
            case 'above_average':
                return `Great job! Your ${userRate}% savings rate beats the peer average of ${insights.benchmarks.averageSavingsRate}%. Aim for ${insights.benchmarks.topPerformerSavingsRate}% to be a top performer.`
            case 'on_track':
                return `You're on track with ${userRate}% savings. The peer average is ${insights.benchmarks.averageSavingsRate}% - push a bit more to beat it!`
            case 'needs_improvement':
                return `Your ${userRate}% savings rate is below the peer average of ${insights.benchmarks.averageSavingsRate}%. Consider our cost-cutting recommendations to improve.`
            default:
                return ''
        }
    }

    /**
     * Get tax optimization recommendations based on income
     */
    getTaxOptimizationRecommendations(monthlyIncome, age, hasHomeLoan = false, hasNPS = false) {
        const bracket = this.getIncomeBracket(monthlyIncome)
        const taxInsights = bracket.incomeInsights?.taxOptimization

        if (!taxInsights) {
            return null
        }

        const annualIncome = monthlyIncome * 12
        const recommendations = []

        // Section 80C recommendations
        if (taxInsights.applicable) {
            const section80CLimit = 150000
            const elssRecommendation = Math.min(section80CLimit, annualIncome * 0.10)

            recommendations.push({
                section: '80C',
                limit: section80CLimit,
                title: 'Tax Saving Investments',
                priority: 'High',
                options: [
                    {
                        name: 'ELSS Mutual Funds',
                        amount: elssRecommendation,
                        lockIn: '3 years',
                        expectedReturn: '12-15%',
                        benefit: `Save up to ₹${Math.round(elssRecommendation * 0.30).toLocaleString('en-IN')} in taxes`
                    },
                    {
                        name: 'PPF',
                        amount: Math.min(150000, annualIncome * 0.08),
                        lockIn: '15 years (partial withdrawal after 7)',
                        expectedReturn: '7.1%',
                        benefit: 'Guaranteed returns, tax-free maturity'
                    },
                    {
                        name: 'EPF (Employee Contribution)',
                        amount: Math.round(annualIncome * 0.12),
                        lockIn: 'Till retirement',
                        expectedReturn: '8.1%',
                        benefit: 'Employer matching, tax-free returns'
                    }
                ]
            })

            // Section 80D (Health Insurance)
            const healthLimit = age >= 60 ? 50000 : 25000
            const parentHealthLimit = 50000 // For senior citizen parents

            recommendations.push({
                section: '80D',
                limit: healthLimit + parentHealthLimit,
                title: 'Health Insurance Premium',
                priority: 'High',
                options: [
                    {
                        name: 'Self & Family Health Insurance',
                        amount: healthLimit,
                        benefit: `Deduction up to ₹${healthLimit.toLocaleString('en-IN')}`
                    },
                    {
                        name: 'Parents Health Insurance',
                        amount: parentHealthLimit,
                        benefit: `Additional ₹${parentHealthLimit.toLocaleString('en-IN')} if parents are senior citizens`
                    }
                ]
            })

            // Section 80CCD(1B) - NPS
            if (!hasNPS) {
                recommendations.push({
                    section: '80CCD(1B)',
                    limit: 50000,
                    title: 'National Pension System (NPS)',
                    priority: 'Medium',
                    options: [
                        {
                            name: 'NPS Contribution',
                            amount: 50000,
                            lockIn: 'Till 60',
                            expectedReturn: '9-12%',
                            benefit: 'Additional ₹50,000 deduction over 80C'
                        }
                    ]
                })
            }

            // Home Loan Interest (Section 24)
            if (hasHomeLoan) {
                recommendations.push({
                    section: '24(b)',
                    limit: 200000,
                    title: 'Home Loan Interest',
                    priority: 'High',
                    options: [
                        {
                            name: 'Home Loan Interest Deduction',
                            amount: 200000,
                            benefit: 'Deduction on interest paid for self-occupied property'
                        }
                    ]
                })
            }
        }

        // Calculate potential tax savings
        const totalDeductions = recommendations.reduce((sum, r) => sum + r.limit, 0)
        const taxBracket = this.getTaxBracketPercentage(annualIncome)
        const potentialSavings = Math.round(totalDeductions * (taxBracket / 100))

        // Old vs New regime comparison
        const regimeComparison = this.compareRegimes(annualIncome, totalDeductions)

        return {
            taxBracket: taxInsights.taxBracket,
            annualIncome,
            recommendations,
            tips: taxInsights.tips,
            potentialSavings,
            regimeComparison,
            summary: `By utilizing all tax-saving options, you can save up to ₹${potentialSavings.toLocaleString('en-IN')} in taxes annually.`
        }
    }

    /**
     * Get tax bracket percentage
     */
    getTaxBracketPercentage(annualIncome) {
        // Old regime slabs (simplified)
        if (annualIncome <= 250000) return 0
        if (annualIncome <= 500000) return 5
        if (annualIncome <= 1000000) return 20
        return 30
    }

    /**
     * Compare old vs new tax regime
     */
    compareRegimes(annualIncome, totalDeductions) {
        // Simplified calculation
        const oldRegimeTax = this.calculateOldRegimeTax(annualIncome, totalDeductions)
        const newRegimeTax = this.calculateNewRegimeTax(annualIncome)

        const betterRegime = oldRegimeTax < newRegimeTax ? 'old' : 'new'
        const savings = Math.abs(oldRegimeTax - newRegimeTax)

        return {
            oldRegimeTax,
            newRegimeTax,
            betterRegime,
            savings,
            recommendation: betterRegime === 'old'
                ? `Old tax regime saves you ₹${savings.toLocaleString('en-IN')} with your deductions`
                : `New tax regime is better for you by ₹${savings.toLocaleString('en-IN')}`
        }
    }

    /**
     * Calculate tax under old regime (simplified)
     */
    calculateOldRegimeTax(annualIncome, deductions) {
        const taxableIncome = Math.max(0, annualIncome - deductions - 50000) // Standard deduction
        if (taxableIncome <= 250000) return 0
        if (taxableIncome <= 500000) return (taxableIncome - 250000) * 0.05
        if (taxableIncome <= 1000000) return 12500 + (taxableIncome - 500000) * 0.20
        return 12500 + 100000 + (taxableIncome - 1000000) * 0.30
    }

    /**
     * Calculate tax under new regime (simplified, FY 2024-25)
     */
    calculateNewRegimeTax(annualIncome) {
        const taxableIncome = Math.max(0, annualIncome - 75000) // Standard deduction in new regime
        if (taxableIncome <= 300000) return 0
        if (taxableIncome <= 700000) return (taxableIncome - 300000) * 0.05
        if (taxableIncome <= 1000000) return 20000 + (taxableIncome - 700000) * 0.10
        if (taxableIncome <= 1200000) return 20000 + 30000 + (taxableIncome - 1000000) * 0.15
        if (taxableIncome <= 1500000) return 20000 + 30000 + 30000 + (taxableIncome - 1200000) * 0.20
        return 20000 + 30000 + 30000 + 60000 + (taxableIncome - 1500000) * 0.30
    }

    /**
     * Get income-based recommendations considering income stability
     */
    getIncomeBasedRecommendations(monthlyIncome, stabilityRatio = 100, incomeSources = []) {
        const bracket = this.getIncomeBracket(monthlyIncome)
        const insights = bracket.incomeInsights

        if (!insights) {
            return { recommendations: bracket.recommendations }
        }

        // Adjust recommendations based on income stability
        const recommendations = [...bracket.recommendations]
        const additionalRecommendations = []

        // If income is variable (stability < 70%), add specific advice
        if (stabilityRatio < 70) {
            additionalRecommendations.push(
                `With ${stabilityRatio}% income stability, build a larger emergency fund (${insights.targetEmergencyFund + 3} months)`,
                'Avoid large fixed commitments (EMIs) that depend on variable income',
                'Create a separate buffer account for lean months',
                'Consider income smoothing - save more in good months'
            )
        }

        // If mixed income (70-90% stable)
        if (stabilityRatio >= 70 && stabilityRatio < 90) {
            additionalRecommendations.push(
                'Allocate fixed expenses only to stable income portion',
                'Use variable income primarily for savings and investments',
                'Build 6-9 month buffer for variable income portion'
            )
        }

        // Multiple income source specific advice
        if (incomeSources.length > 1) {
            const stableSources = incomeSources.filter(s => s.isStable)
            const variableSources = incomeSources.filter(s => !s.isStable)

            if (variableSources.length > 0) {
                additionalRecommendations.push(
                    `Automate savings from stable income (${stableSources.map(s => s.name).join(', ')})`,
                    `Use variable income (${variableSources.map(s => s.name).join(', ')}) for bonus investments`
                )
            }

            // Tax advice for multiple incomes
            if (incomeSources.some(s => s.type === 'freelance' || s.type === 'business')) {
                additionalRecommendations.push(
                    'Consider advance tax payments for business/freelance income',
                    'Track business expenses for deductions under Section 44ADA',
                    'Maintain separate accounts for business and personal finances'
                )
            }

            if (incomeSources.some(s => s.type === 'rental')) {
                additionalRecommendations.push(
                    'Claim 30% standard deduction on rental income',
                    'Deduct property tax and home loan interest from rental income'
                )
            }
        }

        return {
            incomeBracket: bracket.key,
            profile: bracket.profile,
            stabilityRatio,
            isStableIncome: stabilityRatio >= 90,
            recommendations: [...recommendations, ...additionalRecommendations],
            savingsTarget: insights.savingsRateTarget,
            emergencyFundMonths: stabilityRatio < 70
                ? insights.targetEmergencyFund + 3
                : insights.targetEmergencyFund,
            investmentAllocation: insights.investmentAllocation,
            riskAdvice: stabilityRatio < 70
                ? 'Consider more conservative investments due to income variability'
                : stabilityRatio < 90
                    ? 'Moderate risk investments recommended'
                    : 'Can consider growth-oriented investments'
        }
    }

    /**
     * Generate comprehensive income report
     */
    generateIncomeReport(userProfile) {
        const {
            monthlyIncome,
            incomeSources = [],
            age,
            hasHomeLoan,
            hasNPS
        } = userProfile

        // Calculate stability from income sources
        let stabilityRatio = 100
        if (incomeSources.length > 0) {
            const totalIncome = incomeSources.reduce((sum, s) => sum + s.amount, 0)
            const stableIncome = incomeSources
                .filter(s => s.isStable)
                .reduce((sum, s) => sum + s.amount, 0)
            stabilityRatio = Math.round((stableIncome / totalIncome) * 100)
        }

        const bracket = this.getIncomeBracket(monthlyIncome)
        const peerInsights = this.getPeerInsights(monthlyIncome, bracket.typicalExpenses.savings * 100)
        const taxOptimization = this.getTaxOptimizationRecommendations(monthlyIncome, age, hasHomeLoan, hasNPS)
        const incomeRecommendations = this.getIncomeBasedRecommendations(monthlyIncome, stabilityRatio, incomeSources)

        return {
            summary: {
                monthlyIncome,
                annualIncome: monthlyIncome * 12,
                incomeBracket: bracket.profile,
                stabilityRatio,
                incomeSourceCount: incomeSources.length || 1
            },
            incomeSources: incomeSources.length > 0 ? incomeSources.map(s => ({
                name: s.name,
                type: s.type,
                amount: s.amount,
                isStable: s.isStable,
                monthlyNormalized: this.normalizeToMonthly(s.amount, s.frequency)
            })) : [{ name: 'Primary Income', type: 'salary', amount: monthlyIncome, isStable: true }],
            peerInsights,
            taxOptimization,
            recommendations: incomeRecommendations,
            actionPlan: this.generateIncomeActionPlan(monthlyIncome, stabilityRatio, bracket)
        }
    }

    /**
     * Normalize income to monthly
     */
    normalizeToMonthly(amount, frequency) {
        const multipliers = {
            weekly: 4.33,
            'bi-weekly': 2.17,
            monthly: 1,
            quarterly: 0.33,
            annually: 0.083,
            irregular: 1
        }
        return Math.round(amount * (multipliers[frequency] || 1))
    }

    /**
     * Generate action plan based on income profile
     */
    generateIncomeActionPlan(monthlyIncome, stabilityRatio, bracket) {
        const plan = []

        // Week 1: Emergency Fund Setup
        plan.push({
            week: 1,
            title: 'Setup Emergency Fund',
            actions: [
                `Open high-yield savings or liquid fund account`,
                `Set auto-transfer of ₹${Math.round(monthlyIncome * 0.10).toLocaleString('en-IN')}/month`,
                `Target: ${bracket.incomeInsights.targetEmergencyFund} months expenses`
            ],
            timeRequired: '30 minutes'
        })

        // Week 2: Income Protection
        plan.push({
            week: 2,
            title: 'Income Protection',
            actions: [
                `Get term insurance (₹${Math.round(monthlyIncome * 120 / 100000).toLocaleString('en-IN')}L cover)`,
                'Review health insurance coverage',
                stabilityRatio < 80 ? 'Consider income protection insurance' : 'Ensure adequate disability cover'
            ],
            timeRequired: '2 hours'
        })

        // Week 3: Investment Setup
        plan.push({
            week: 3,
            title: 'Start Systematic Investments',
            actions: [
                `Start SIP of ₹${Math.round(monthlyIncome * (bracket.incomeInsights.savingsRateTarget / 100)).toLocaleString('en-IN')}/month`,
                `Allocation: ${Object.entries(bracket.incomeInsights.investmentAllocation).map(([k, v]) => `${k}: ${v}%`).join(', ')}`,
                'Setup auto-debit for SIPs'
            ],
            timeRequired: '1 hour'
        })

        // Week 4: Tax Planning
        if (bracket.incomeInsights.taxOptimization.applicable) {
            plan.push({
                week: 4,
                title: 'Tax Optimization',
                actions: bracket.incomeInsights.taxOptimization.tips.slice(0, 3),
                timeRequired: '1 hour'
            })
        }

        return plan
    }
}

// Export singleton instance
export const advancedBudgetEngine = new AdvancedBudgetEngine()
