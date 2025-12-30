// lib/budgetConfig.js
// Budget Categories Configuration - English Only
export const BUDGET_CATEGORIES = {
  'food_dining': {
    englishName: 'Food & Dining',
    emoji: '🍽️',
    basePercentage: 0.25,
    description: 'Food, dining out, and beverages'
  },
  
  'home_utilities': {
    englishName: 'Home & Utilities',
    emoji: '🏠',
    basePercentage: 0.30,
    description: 'Rent, electricity, water, and household items'
  },
  
  'transportation': {
    englishName: 'Transportation',
    emoji: '🚗',
    basePercentage: 0.10,
    description: 'Petrol, metro, bus, and auto rickshaw'
  },
  
  'entertainment': {
    englishName: 'Entertainment',
    emoji: '🎬',
    basePercentage: 0.08,
    description: 'Movies, games, and entertainment'
  },
  
  'shopping': {
    englishName: 'Shopping',
    emoji: '👕',
    basePercentage: 0.05,
    description: 'Clothes, shoes, and personal items'
  },
  
  'healthcare': {
    englishName: 'Healthcare',
    emoji: '💊',
    basePercentage: 0.07,
    description: 'Medicine, doctor visits, and health insurance'
  },
  
  'savings': {
    englishName: 'Savings',
    emoji: '💰',
    basePercentage: 0.15,
    description: 'Savings, investments, and emergency fund'
  }
}

// City-based cost adjustments for major Indian cities
export const CITY_ADJUSTMENTS = {
  'Mumbai': {
    home_utilities: 1.4,
    transportation: 1.2,
    food_dining: 1.3,
    entertainment: 1.2,
    shopping: 1.1,
    healthcare: 1.2,
    savings: 0.85
  },
  'Delhi': {
    home_utilities: 1.3,
    transportation: 1.1,
    food_dining: 1.2,
    entertainment: 1.1,
    shopping: 1.0,
    healthcare: 1.1,
    savings: 0.9
  },
  'Bangalore': {
    home_utilities: 1.2,
    transportation: 1.0,
    food_dining: 1.1,
    entertainment: 1.0,
    shopping: 1.0,
    healthcare: 1.0,
    savings: 0.95
  },
  'Hyderabad': {
    home_utilities: 1.1,
    transportation: 0.9,
    food_dining: 1.0,
    entertainment: 0.9,
    shopping: 0.9,
    healthcare: 0.9,
    savings: 1.0
  },
  'Chennai': {
    home_utilities: 1.2,
    transportation: 0.9,
    food_dining: 1.0,
    entertainment: 0.9,
    shopping: 0.9,
    healthcare: 0.9,
    savings: 0.95
  },
  'Pune': {
    home_utilities: 1.1,
    transportation: 0.9,
    food_dining: 1.0,
    entertainment: 0.9,
    shopping: 0.9,
    healthcare: 0.9,
    savings: 1.0
  },
  'Kolkata': {
    home_utilities: 1.0,
    transportation: 0.8,
    food_dining: 0.9,
    entertainment: 0.8,
    shopping: 0.8,
    healthcare: 0.8,
    savings: 1.1
  },
  'default': {
    home_utilities: 1.0,
    transportation: 1.0,
    food_dining: 1.0,
    entertainment: 1.0,
    shopping: 1.0,
    healthcare: 1.0,
    savings: 1.0
  }
}

// Family size adjustments
export const getFamilySizeAdjustment = (familySize) => {
  const adjustments = {
    1: {
      food_dining: 0.6,
      home_utilities: 0.7,
      transportation: 0.8,
      entertainment: 0.8,
      shopping: 0.7,
      healthcare: 0.8,
      savings: 1.3
    },
    2: {
      food_dining: 0.8,
      home_utilities: 0.9,
      transportation: 0.9,
      entertainment: 0.9,
      shopping: 0.9,
      healthcare: 0.9,
      savings: 1.2
    },
    3: {
      food_dining: 1.2,
      home_utilities: 1.1,
      transportation: 1.0,
      entertainment: 1.0,
      shopping: 1.1,
      healthcare: 1.2,
      savings: 0.9
    },
    4: {
      food_dining: 1.6,
      home_utilities: 1.4,
      transportation: 1.2,
      entertainment: 1.2,
      shopping: 1.4,
      healthcare: 1.5,
      savings: 0.7
    }
  }

  if (familySize <= 4) {
    return adjustments[familySize]
  } else {
    // For families larger than 4, scale up from 4-person family
    const scaleFactor = familySize / 4
    const baseFour = adjustments[4]
    
    return {
      food_dining: Math.min(baseFour.food_dining * scaleFactor, 2.5),
      home_utilities: Math.min(baseFour.home_utilities * scaleFactor, 2.0),
      transportation: Math.min(baseFour.transportation * scaleFactor, 1.8),
      entertainment: Math.min(baseFour.entertainment * scaleFactor, 1.5),
      shopping: Math.min(baseFour.shopping * scaleFactor, 2.0),
      healthcare: Math.min(baseFour.healthcare * scaleFactor, 2.2),
      savings: Math.max(baseFour.savings * (1/scaleFactor), 0.3)
    }
  }
}

// Income-based adjustments
export const getIncomeAdjustments = (monthlyIncome) => {
  if (monthlyIncome < 25000) {
    return {
      food_dining: 1.2,
      home_utilities: 1.1,
      transportation: 0.9,
      entertainment: 0.7,
      shopping: 0.8,
      healthcare: 0.9,
      savings: 0.8
    }
  } else if (monthlyIncome < 50000) {
    return {
      food_dining: 1.0,
      home_utilities: 1.0,
      transportation: 1.0,
      entertainment: 1.0,
      shopping: 1.0,
      healthcare: 1.0,
      savings: 1.0
    }
  } else if (monthlyIncome < 100000) {
    return {
      food_dining: 0.9,
      home_utilities: 0.95,
      transportation: 1.1,
      entertainment: 1.2,
      shopping: 1.2,
      healthcare: 1.1,
      savings: 1.2
    }
  } else {
    return {
      food_dining: 0.8,
      home_utilities: 0.9,
      transportation: 1.2,
      entertainment: 1.4,
      shopping: 1.4,
      healthcare: 1.2,
      savings: 1.4
    }
  }
}

// Age-based adjustments
export const getAgeAdjustments = (age) => {
  if (age < 25) {
    return {
      food_dining: 0.9,
      home_utilities: 0.9,
      transportation: 1.1,
      entertainment: 1.3,
      shopping: 1.2,
      healthcare: 0.8,
      savings: 1.1
    }
  } else if (age < 35) {
    return {
      food_dining: 1.0,
      home_utilities: 1.0,
      transportation: 1.0,
      entertainment: 1.0,
      shopping: 1.0,
      healthcare: 1.0,
      savings: 1.0
    }
  } else if (age < 50) {
    return {
      food_dining: 1.0,
      home_utilities: 1.0,
      transportation: 0.9,
      entertainment: 0.9,
      shopping: 0.9,
      healthcare: 1.2,
      savings: 1.1
    }
  } else {
    return {
      food_dining: 0.9,
      home_utilities: 1.0,
      transportation: 0.8,
      entertainment: 0.8,
      shopping: 0.8,
      healthcare: 1.4,
      savings: 1.2
    }
  }
}
