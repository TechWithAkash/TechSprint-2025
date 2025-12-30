import mongoose from 'mongoose'

const debtSchema = new mongoose.Schema({
  // User reference
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  // Debt type - taken (liability) or given (asset)
  type: {
    type: String,
    enum: ['taken', 'given'],
    required: true,
    index: true
  },
  
  // Lender name (for taken debt) or Borrower name (for given debt)
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  
  // Original debt amount
  amount: {
    type: Number,
    required: true,
    min: [0, 'Amount must be positive'],
    validate: {
      validator: function(v) {
        return v > 0
      },
      message: 'Amount must be greater than zero'
    }
  },
  
  // Interest rate per annum
  interestRate: {
    type: Number,
    default: 0,
    min: [0, 'Interest rate cannot be negative'],
    max: [100, 'Interest rate cannot exceed 100%']
  },
  
  // Duration in months
  duration: {
    type: Number,
    required: true,
    min: [1, 'Duration must be at least 1 month'],
    max: [600, 'Duration cannot exceed 600 months']
  },
  
  // Duration in months
  duration: {
    type: Number,
    required: true,
    min: [1, 'Duration must be at least 1 month'],
    max: [600, 'Duration cannot exceed 600 months']
  },
  
  // Current remaining balance
  remainingBalance: {
    type: Number,
    required: true,
    min: [0, 'Remaining balance cannot be negative']
  },
  
  // Due date for next payment or final payment
  dueDate: {
    type: Date,
    required: true,
    index: true
  },
  
  // Additional details
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  
  // Debt status
  status: {
    type: String,
    enum: ['active', 'paid', 'overdue', 'defaulted'],
    default: 'active',
    index: true
  },
  
  // Payment history
  payments: [{
    amount: {
      type: Number,
      required: true,
      min: 0
    },
    date: {
      type: Date,
      required: true
    },
    description: {
      type: String,
      trim: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Metadata
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
})

// Compound indexes for better query performance
debtSchema.index({ userId: 1, type: 1 })
debtSchema.index({ userId: 1, status: 1 })
debtSchema.index({ userId: 1, dueDate: 1 })

// Pre-save middleware to update timestamps and validate data
debtSchema.pre('save', function(next) {
  this.updatedAt = new Date()
  
  // Ensure remaining balance doesn't exceed original amount
  if (this.remainingBalance > this.amount) {
    this.remainingBalance = this.amount
  }
  
  // Auto-update status based on remaining balance
  if (this.remainingBalance === 0) {
    this.status = 'paid'
  } else if (this.dueDate < new Date() && this.status === 'active') {
    this.status = 'overdue'
  }
  
  next()
})

// Virtual for completion percentage
debtSchema.virtual('completionPercentage').get(function() {
  if (this.amount === 0) return 100
  return Math.max(0, Math.min(100, ((this.amount - this.remainingBalance) / this.amount) * 100))
})

// Virtual for monthly payment percentage of total debt
debtSchema.virtual('monthlyPaymentRatio').get(function() {
  if (this.amount === 0) return 0
  return (this.monthlyInstallment / this.amount) * 100
})

// Virtual for days until due
debtSchema.virtual('daysUntilDue').get(function() {
  const today = new Date()
  const timeDiff = this.dueDate.getTime() - today.getTime()
  return Math.ceil(timeDiff / (1000 * 3600 * 24))
})

// Instance method to add payment
debtSchema.methods.addPayment = function(amount, description = '') {
  if (amount <= 0) {
    throw new Error('Payment amount must be positive')
  }
  
  if (amount > this.remainingBalance) {
    amount = this.remainingBalance
  }
  
  this.payments.push({
    amount,
    date: new Date(),
    description
  })
  
  this.remainingBalance -= amount
  
  if (this.remainingBalance <= 0) {
    this.remainingBalance = 0
    this.status = 'paid'
  }
  
  return this.save()
}

// Instance method to calculate total interest paid
debtSchema.methods.getTotalInterestPaid = function() {
  const totalPaid = this.amount - this.remainingBalance
  const principalPaid = totalPaid
  
  // Simple calculation - in real scenario, this would be more complex
  if (this.interestRate > 0) {
    const monthsElapsed = Math.floor((new Date() - this.createdAt) / (1000 * 60 * 60 * 24 * 30))
    const estimatedInterest = (this.amount * this.interestRate * monthsElapsed) / (100 * 12)
    return Math.max(0, Math.min(estimatedInterest, totalPaid))
  }
  
  return 0
}

// Instance method to get formatted amount
debtSchema.methods.getFormattedAmount = function(field = 'amount') {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 0
  }).format(this[field])
}

// Static method to get user debt summary
debtSchema.statics.getUserDebtSummary = async function(userId) {
  const pipeline = [
    { $match: { userId: new mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: '$type',
        totalAmount: { $sum: '$amount' },
        totalRemaining: { $sum: '$remainingBalance' },
        totalMonthlyPayments: { $sum: '$monthlyInstallment' },
        count: { $sum: 1 },
        avgInterestRate: { $avg: '$interestRate' }
      }
    }
  ]
  
  const results = await this.aggregate(pipeline)
  
  const summary = {
    taken: { totalAmount: 0, totalRemaining: 0, totalMonthlyPayments: 0, count: 0, avgInterestRate: 0 },
    given: { totalAmount: 0, totalRemaining: 0, totalMonthlyPayments: 0, count: 0, avgInterestRate: 0 }
  }
  
  results.forEach(result => {
    summary[result._id] = {
      totalAmount: result.totalAmount,
      totalRemaining: result.totalRemaining,
      totalMonthlyPayments: result.totalMonthlyPayments,
      count: result.count,
      avgInterestRate: result.avgInterestRate
    }
  })
  
  return summary
}

const Debt = mongoose.models.Debt || mongoose.model('Debt', debtSchema)

export default Debt
