import mongoose from 'mongoose'

const userProfileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true  // This creates the index automatically, no need for separate schema.index()
  },
  
  // Basic Demographics
  monthlyIncome: {
    type: Number,
    min: [1000, 'Monthly income must be at least ₹1,000']
    // Removed required: true to allow initial profile creation
  },
  
  incomeSource: {
    type: String,
    enum: ['salary', 'business', 'freelance', 'other'],
    default: 'salary'
  },

  // Multiple Income Sources (NEW - for semifinal feature)
  incomeSources: [{
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, 'Income source name cannot exceed 100 characters']
    },
    type: {
      type: String,
      enum: ['salary', 'business', 'freelance', 'rental', 'investment', 'pension', 'side_hustle', 'other'],
      required: true,
      default: 'salary'
    },
    amount: {
      type: Number,
      required: true,
      min: [0, 'Amount cannot be negative']
    },
    frequency: {
      type: String,
      enum: ['monthly', 'bi-weekly', 'weekly', 'quarterly', 'annually', 'irregular'],
      default: 'monthly'
    },
    isStable: {
      type: Boolean,
      default: true
    },
    includeInBudget: {
      type: Boolean,
      default: true
    },
    description: {
      type: String,
      trim: true,
      maxlength: 500
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],

  city: {
    type: String,
    trim: true
    // Removed required: true to allow initial profile creation
  },
  
  familySize: {
    type: Number,
    min: [1, 'Family size must be at least 1'],
    max: [20, 'Family size cannot exceed 20']
    // Removed required: true to allow initial profile creation
  },
  
  age: {
    type: Number,
    min: [18, 'Age must be at least 18'],
    max: [100, 'Age cannot exceed 100']
    // Removed required: true to allow initial profile creation
  },
  
  occupation: {
    type: String,
    trim: true,
    default: ''
  },

  // Enhanced Demographics (from improved onboarding)
  livingSituation: {
    type: String,
    enum: ['with_parents', 'renting_alone', 'renting_shared', 'own_home', 'home_loan', ''],
    default: ''
  },

  commuteMode: {
    type: String,
    enum: ['wfh', 'public_transport', 'two_wheeler', 'four_wheeler', 'cab_auto', ''],
    default: ''
  },

  hasKids: {
    type: Boolean,
    default: false
  },

  monthlyRent: {
    type: Number,
    default: 0
  },

  // Financial Pulse (strategic onboarding questions)
  financialPulse: {
    debtStatus: {
      type: String,
      enum: ['none', 'low', 'medium', 'high', ''],
      default: ''
    },
    savingsStatus: {
      type: String,
      enum: ['none', 'partial', 'adequate', 'strong', ''],
      default: ''
    },
    moneyStress: {
      type: String,
      enum: ['stressed', 'concerned', 'stable', 'confident', ''],
      default: ''
    },
    spendingStyle: {
      type: String,
      enum: ['impulsive', 'emotional', 'planned', 'frugal', ''],
      default: ''
    },
    primaryGoal: {
      type: String,
      enum: ['debt_free', 'emergency_fund', 'big_purchase', 'invest', 'balance', ''],
      default: ''
    }
  },

  // Additional Profile Fields
  name: {
    type: String,
    default: ''
  },
  email: {
    type: String,
    default: ''
  },
  phone: {
    type: String,
    default: ''
  },
  bio: {
    type: String,
    default: ''
  },
  dateOfBirth: {
    type: Date,
    default: null
  },
  profileImage: {
    type: String,
    default: ''
  },
  
  // Generated Budget
  generatedBudget: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },

  // Budget Health Score
  budgetHealthScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },

  // Last Budget Generated
  lastBudgetGenerated: {
    type: Date
  },
  
  // Budget Preferences
  budgetPreferences: {
    language: {
      type: String,
      enum: ['hindi', 'english', 'hinglish', 'en', 'hi'],
      default: 'hinglish'
    },
    currency: {
      type: String,
      enum: ['INR', 'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD'],
      default: 'INR'
    },
    notifications: {
      type: Boolean,
      default: true
    },
    // Enhanced localization preferences
    timezone: {
      type: String,
      default: 'Asia/Kolkata'
    },
    dateFormat: {
      type: String,
      enum: ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD'],
      default: 'DD/MM/YYYY'
    },
    numberFormat: {
      type: String,
      enum: ['indian', 'international'],
      default: 'indian' // 1,00,000 vs 100,000
    },
    theme: {
      type: String,
      enum: ['light', 'dark', 'system'],
      default: 'system'
    },
    // Notification preferences
    emailNotifications: {
      type: Boolean,
      default: true
    },
    pushNotifications: {
      type: Boolean,
      default: true
    },
    budgetAlerts: {
      type: Boolean,
      default: true
    },
    goalReminders: {
      type: Boolean,
      default: true
    },
    weeklyReports: {
      type: Boolean,
      default: true
    },
    monthlyReports: {
      type: Boolean,
      default: true
    }
  },
  
  // Expenses Data
  expenses: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },

  // Goals Data
  goals: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },

  // Seasonal Financial Planning (NEW - for semifinal feature)
  seasonalEvents: [{
    eventType: {
      type: String,
      enum: ['prebuilt', 'custom'],
      default: 'custom'
    },
    prebuiltEventId: String,
    name: {
      type: String,
      required: true,
      trim: true
    },
    description: String,
    category: {
      type: String,
      enum: ['festival', 'education', 'insurance', 'tax', 'utility', 'birthday', 'anniversary', 'vacation', 'wedding', 'custom', 'other'],
      default: 'custom'
    },
    icon: {
      type: String,
      default: '📅'
    },
    date: {
      type: Date,
      required: true
    },
    isRecurring: {
      type: Boolean,
      default: false
    },
    recurringPattern: {
      type: String,
      enum: ['yearly', 'monthly', 'quarterly', 'custom'],
      default: 'yearly'
    },
    estimatedExpense: {
      type: Number,
      required: true,
      min: 0
    },
    currentSavings: {
      type: Number,
      default: 0
    },
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    reminderSettings: {
      enabled: { type: Boolean, default: true },
      reminderDays: { type: [Number], default: [30, 14, 7, 1] }
    },
    status: {
      type: String,
      enum: ['upcoming', 'in_progress', 'completed', 'skipped'],
      default: 'upcoming'
    },
    notes: String,
    createdAt: { type: Date, default: Date.now }
  }],

  // Seasonal Planning Preferences
  seasonalPlanningPreferences: {
    autoAddPrebuiltEvents: { type: Boolean, default: true },
    selectedPrebuiltEvents: [String],
    defaultPreparationWeeks: { type: Number, default: 4 },
    seasonalReservePercentage: { type: Number, default: 10 },
    notificationPreferences: {
      emailReminders: { type: Boolean, default: true },
      pushReminders: { type: Boolean, default: true },
      reminderFrequency: {
        type: String,
        enum: ['weekly', 'bi-weekly', 'monthly'],
        default: 'weekly'
      }
    },
    regionalPreferences: [String]
  },

  // Emergency Alert Settings (NEW - for semifinal feature)
  emergencyAlertSettings: {
    enabled: { type: Boolean, default: true },
    emailAlertsEnabled: { type: Boolean, default: true },
    lowBalanceThreshold: { type: Number, default: 5000, min: 500 },
    criticalBalanceThreshold: { type: Number, default: 1000, min: 100 },
    budgetWarningPercent: { type: Number, default: 80, min: 50, max: 100 },
    budgetCriticalPercent: { type: Number, default: 100, min: 80, max: 150 },
    unusualExpenseMultiplier: { type: Number, default: 3, min: 2, max: 10 },
    emiAlertDaysBefore: { type: Number, default: 5, min: 1, max: 15 },
    quietHoursEnabled: { type: Boolean, default: false },
    quietHoursStart: { type: Number, default: 22, min: 0, max: 23 },
    quietHoursEnd: { type: Number, default: 7, min: 0, max: 23 },
    alertCategories: {
      lowBalance: { type: Boolean, default: true },
      budgetExceeded: { type: Boolean, default: true },
      unusualExpense: { type: Boolean, default: true },
      emiAtRisk: { type: Boolean, default: true }
    },
    lastAlertSent: {
      type: Map,
      of: Date,
      default: new Map()
    },
    alertCooldownHours: { type: Number, default: 4, min: 1, max: 24 }
  },

  // ============================================
  // RETENTION SYSTEM (Achievements, Tips, Activity)
  // ============================================

  // Achievement tracking
  achievements: {
    unlocked: [{
      id: {
        type: String,
        required: true
      },
      unlockedAt: {
        type: Date,
        default: Date.now
      },
      celebrated: {
        type: Boolean,
        default: false
      }
    }],
    progress: {
      // Tracking achievements
      expenseCount: { type: Number, default: 0 },
      voiceEntryCount: { type: Number, default: 0 },
      // Savings achievements
      totalSaved: { type: Number, default: 0 },
      monthsWith20PercentSavings: { type: Number, default: 0 },
      // Budget achievements
      daysUnderBudget: { type: Number, default: 0 },
      consecutiveDaysUnderBudget: { type: Number, default: 0 },
      monthsUnderBudget: { type: Number, default: 0 },
      categoriesUnderBudgetThisMonth: { type: [String], default: [] },
      // Goal achievements
      goalsCreated: { type: Number, default: 0 },
      goalsCompleted: { type: Number, default: 0 },
      goalsMilestoneReached: { type: [String], default: [] } // e.g., ['goal_id:50', 'goal_id:75']
    },
    lastChecked: {
      type: Date,
      default: Date.now
    }
  },

  // Activity tracking for retention
  activityTracking: {
    lastActiveDate: {
      type: Date,
      default: Date.now
    },
    lastExpenseDate: {
      type: Date
    },
    dailyPulseHistory: [{
      date: {
        type: Date,
        required: true
      },
      mood: {
        type: String,
        enum: ['great', 'good', 'okay', 'tough'],
        required: true
      },
      estimatedSpend: {
        type: Number,
        default: 0
      }
    }],
    weeklyReportsSent: [{
      type: Date
    }],
    tipsShown: [{
      tipId: {
        type: String,
        required: true
      },
      shownAt: {
        type: Date,
        default: Date.now
      },
      feedback: {
        type: String,
        enum: ['helpful', 'not_relevant', null],
        default: null
      }
    }],
    lastTipShownDate: {
      type: Date
    },
    nudgeHistory: [{
      type: {
        type: String,
        required: true
      },
      sentAt: {
        type: Date,
        default: Date.now
      },
      dismissed: {
        type: Boolean,
        default: false
      }
    }]
  },

  // Retention feature preferences
  retentionPreferences: {
    dailyPulseEnabled: { type: Boolean, default: true },
    weeklyEmailEnabled: { type: Boolean, default: true },
    smartNudgesEnabled: { type: Boolean, default: true },
    dailyTipsEnabled: { type: Boolean, default: true },
    achievementNotificationsEnabled: { type: Boolean, default: true },
    quietHoursStart: { type: Number, default: 22, min: 0, max: 23 },
    quietHoursEnd: { type: Number, default: 7, min: 0, max: 23 }
  },

  // Onboarding Status
  onboardingCompleted: {
    type: Boolean,
    default: false
  },
  
  onboardingStep: {
    type: String,
    enum: ['income', 'demographics', 'financial_pulse', 'budget_generation', 'review', 'completed'],
    default: 'income'
  },
  
  // Metadata
  createdAt: {
    type: Date,
    default: Date.now
  },
  
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
})

// Enhanced indexes for better query performance
userProfileSchema.index({ city: 1 })
userProfileSchema.index({ onboardingCompleted: 1 })
userProfileSchema.index({ 'budgetPreferences.language': 1 })
userProfileSchema.index({ 'budgetPreferences.currency': 1 })
userProfileSchema.index({ 'budgetPreferences.timezone': 1 })
userProfileSchema.index({ monthlyIncome: 1 })
userProfileSchema.index({ age: 1 })
userProfileSchema.index({ incomeSource: 1 })
userProfileSchema.index({ createdAt: -1 })
userProfileSchema.index({ updatedAt: -1 })
// Compound indexes for common queries
userProfileSchema.index({ city: 1, monthlyIncome: 1 })
userProfileSchema.index({ 'budgetPreferences.language': 1, onboardingCompleted: 1 })
userProfileSchema.index({ age: 1, incomeSource: 1 })

// Pre-save middleware to update timestamps
userProfileSchema.pre('save', function(next) {
  this.updatedAt = new Date()
  next()
})

// Virtual for formatted income with localization support
userProfileSchema.virtual('formattedIncome').get(function() {
  const currency = this.budgetPreferences?.currency || 'INR'
  const language = this.budgetPreferences?.language || 'hinglish'

  // Map language to locale
  let locale = 'en-IN'
  if (language === 'hindi' || language === 'hi') {
    locale = 'hi-IN'
  } else if (language === 'english' || language === 'en') {
    locale = 'en-US'
  }

  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: currency,
    maximumFractionDigits: 0
  }).format(this.monthlyIncome || 0)
})

// Helper function to normalize income to monthly amount
function normalizeToMonthly(amount, frequency) {
  const multipliers = {
    'weekly': 4.33,
    'bi-weekly': 2.17,
    'monthly': 1,
    'quarterly': 0.33,
    'annually': 0.083,
    'irregular': 1
  }
  return Math.round(amount * (multipliers[frequency] || 1))
}

// Virtual: Total monthly income from all sources
userProfileSchema.virtual('totalMonthlyIncome').get(function() {
  if (!this.incomeSources || this.incomeSources.length === 0) {
    return this.monthlyIncome || 0
  }

  return this.incomeSources
    .filter(source => source.includeInBudget)
    .reduce((total, source) => {
      return total + normalizeToMonthly(source.amount, source.frequency)
    }, 0)
})

// Virtual: Stable monthly income only (for conservative budgeting)
userProfileSchema.virtual('stableMonthlyIncome').get(function() {
  if (!this.incomeSources || this.incomeSources.length === 0) {
    return this.monthlyIncome || 0
  }

  return this.incomeSources
    .filter(source => source.includeInBudget && source.isStable)
    .reduce((total, source) => {
      return total + normalizeToMonthly(source.amount, source.frequency)
    }, 0)
})

// Virtual: Income stability ratio (stable/total)
userProfileSchema.virtual('incomeStabilityRatio').get(function() {
  const total = this.totalMonthlyIncome
  if (total === 0) return 1
  return this.stableMonthlyIncome / total
})

// Virtual: Primary income source (highest amount)
userProfileSchema.virtual('primaryIncomeSource').get(function() {
  if (!this.incomeSources || this.incomeSources.length === 0) {
    return { type: this.incomeSource || 'salary', amount: this.monthlyIncome || 0 }
  }

  return this.incomeSources.reduce((primary, source) => {
    const normalizedAmount = normalizeToMonthly(source.amount, source.frequency)
    return normalizedAmount > (primary.normalizedAmount || 0)
      ? { ...source.toObject(), normalizedAmount }
      : primary
  }, { normalizedAmount: 0 })
})

// Method to check if budget needs regeneration (if profile updated)
userProfileSchema.methods.needsBudgetRegeneration = function() {
  if (!this.generatedBudget || !this.generatedBudget.generatedAt) {
    return true
  }
  
  // Regenerate if profile updated after budget generation
  return this.updatedAt > this.generatedBudget.generatedAt
}

// Method to check if required onboarding fields are complete
userProfileSchema.methods.isOnboardingComplete = function() {
  return !!(this.monthlyIncome && this.city && this.familySize && this.age)
}

// Method to get onboarding completion percentage
userProfileSchema.methods.getOnboardingProgress = function() {
  const requiredFields = ['monthlyIncome', 'city', 'familySize', 'age']
  const completedFields = requiredFields.filter(field => this[field])
  return Math.round((completedFields.length / requiredFields.length) * 100)
}

// Enhanced method to get user's preferred language content
userProfileSchema.methods.getLocalizedContent = function(content) {
  const language = this.budgetPreferences?.language || 'hinglish'
  
  // Support both old and new language codes
  const languageMap = {
    'hindi': 'hi',
    'english': 'en',
    'hinglish': 'hinglish',
    'hi': 'hi',
    'en': 'en'
  }
  
  const mappedLanguage = languageMap[language] || 'en'
  
  return content[mappedLanguage] || content[language] || content.english || content.en || content
}

// Method to format currency with user preferences
userProfileSchema.methods.formatCurrency = function(amount) {
  const currency = this.budgetPreferences?.currency || 'INR'
  const language = this.budgetPreferences?.language || 'hinglish'
  
  let locale = 'en-IN'
  if (language === 'hindi' || language === 'hi') {
    locale = 'hi-IN'
  } else if (language === 'english' || language === 'en') {
    locale = 'en-US'
  }
  
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: currency,
    maximumFractionDigits: 0
  }).format(amount || 0)
}

// Method to format numbers with user preferences
userProfileSchema.methods.formatNumber = function(number) {
  const format = this.budgetPreferences?.numberFormat || 'indian'
  const language = this.budgetPreferences?.language || 'hinglish'
  
  let locale = 'en-IN'
  if (format === 'international') {
    locale = 'en-US'
  } else if (language === 'hindi' || language === 'hi') {
    locale = 'hi-IN'
  }
  
  return new Intl.NumberFormat(locale).format(number || 0)
}

// Method to format date with user preferences
userProfileSchema.methods.formatDate = function(date) {
  const format = this.budgetPreferences?.dateFormat || 'DD/MM/YYYY'
  const language = this.budgetPreferences?.language || 'hinglish'
  
  let locale = 'en-IN'
  if (language === 'hindi' || language === 'hi') {
    locale = 'hi-IN'
  } else if (language === 'english' || language === 'en') {
    locale = 'en-US'
  }
  
  const dateObj = new Date(date)
  
  if (format === 'MM/DD/YYYY') {
    return dateObj.toLocaleDateString('en-US')
  } else if (format === 'YYYY-MM-DD') {
    return dateObj.toISOString().split('T')[0]
  } else {
    return dateObj.toLocaleDateString(locale)
  }
}

// Method to get user's timezone
userProfileSchema.methods.getTimezone = function() {
  return this.budgetPreferences?.timezone || 'Asia/Kolkata'
}

// Method to check notification preferences
userProfileSchema.methods.shouldSendNotification = function(type) {
  const prefs = this.budgetPreferences || {}
  
  switch (type) {
    case 'email':
      return prefs.emailNotifications !== false
    case 'push':
      return prefs.pushNotifications !== false
    case 'budget':
      return prefs.budgetAlerts !== false
    case 'goal':
      return prefs.goalReminders !== false
    case 'weekly':
      return prefs.weeklyReports !== false
    case 'monthly':
      return prefs.monthlyReports !== false
    default:
      return prefs.notifications !== false
  }
}

// Clear cached model during development to pick up schema changes
if (mongoose.models.UserProfile) {
  delete mongoose.models.UserProfile
}

const UserProfile = mongoose.model('UserProfile', userProfileSchema)

export default UserProfile
