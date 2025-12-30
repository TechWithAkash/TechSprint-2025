'use client'

import { useState } from 'react'
import { Plus, X, Mic } from 'lucide-react'

export default function ManualExpenseEntry({ onExpenseAdded, onVoiceEntry, onClose }) {
  const [formData, setFormData] = useState({
    amount: '',
    category: '',
    description: '',
    merchant: '',
    date: new Date().toISOString().split('T')[0]
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  const categories = [
    { id: 'Food & Dining', name: 'खाना-पीना (Food)', emoji: '🍽️', hinglish: 'खाना-पीना' },
    { id: 'Transportation', name: 'यातायात (Transport)', emoji: '🚗', hinglish: 'यातायात' },
    { id: 'Entertainment', name: 'मनोरंजन (Fun)', emoji: '🎬', hinglish: 'मनोरंजन' },
    { id: 'Shopping', name: 'ਕपड़े-ਲੱਤੇ (Shopping)', emoji: '👕', hinglish: 'कपड़े-लत्ते' },
    { id: 'Healthcare', name: 'दवाई-इलाज (Health)', emoji: '💊', hinglish: 'दवाई-इलाज' },
    { id: 'Home & Utilities', name: 'घर का खर्च (Home)', emoji: '🏠', hinglish: 'घर का खर्च' },
    { id: 'Savings', name: 'बचत (Savings)', emoji: '💰', hinglish: 'बचत' },
    { id: 'Other', name: 'अन्य (Other)', emoji: '💳', hinglish: 'अन्य' }
  ]

  const quickAmounts = [20, 50, 100, 200, 500, 1000]

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
    setError('')
  }

  const handleQuickAmount = (amount) => {
    setFormData(prev => ({
      ...prev,
      amount: amount.toString()
    }))
  }

  const validateForm = () => {
    if (!formData.amount || parseFloat(formData.amount) <= 0) {
      setError('Please enter a valid amount')
      return false
    }
    
    if (!formData.category) {
      setError('Please select a category')
      return false
    }

    if (parseFloat(formData.amount) > 100000) {
      setError('Amount seems too high. Please check.')
      return false
    }

    return true
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setIsSubmitting(true)
    setError('')

    try {
      const expenseData = {
        amount: parseFloat(formData.amount),
        category: formData.category,
        description: formData.description.trim() || null,
        merchant: formData.merchant.trim() || null,
        date: formData.date,
        entryMethod: 'manual'
      }

      const response = await fetch('/api/expenses', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(expenseData),
      })

      const data = await response.json()

      if (data.success) {
        // Notify parent component
        if (onExpenseAdded) {
          onExpenseAdded(data.expense)
        }
        
        // Reset form
        setFormData({
          amount: '',
          category: '',
          description: '',
          merchant: '',
          date: new Date().toISOString().split('T')[0]
        })

        // Close modal after success
        if (onClose) {
          setTimeout(() => onClose(), 1000)
        }
      } else {
        setError(data.error || 'Failed to add expense')
      }
    } catch (err) {
      console.error('Error adding expense:', err)
      setError('Failed to add expense. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-bold text-gray-900">Add Expense</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          
          {/* Amount Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Amount *
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">
                ₹
              </span>
              <input
                type="number"
                value={formData.amount}
                onChange={(e) => handleInputChange('amount', e.target.value)}
                placeholder="0"
                className="w-full pl-8 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                step="0.01"
                min="0"
                required
              />
            </div>
            
            {/* Quick Amount Buttons */}
            <div className="flex flex-wrap gap-2 mt-3">
              {quickAmounts.map(amount => (
                <button
                  key={amount}
                  type="button"
                  onClick={() => handleQuickAmount(amount)}
                  className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded-full transition-colors"
                >
                  ₹{amount}
                </button>
              ))}
            </div>
          </div>

          {/* Category Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Category *
            </label>
            <div className="grid grid-cols-2 gap-2">
              {categories.map(category => (
                <button
                  key={category.id}
                  type="button"
                  onClick={() => handleInputChange('category', category.id)}
                  className={`p-3 rounded-lg border text-left transition-colors ${
                    formData.category === category.id
                      ? 'border-blue-500 bg-blue-50 text-blue-700'
                      : 'border-gray-300 hover:border-gray-400'
                  }`}
                >
                  <div className="flex items-center">
                    <span className="text-lg mr-2">{category.emoji}</span>
                    <span className="text-sm font-medium">{category.name}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Description Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description
              <span className="text-gray-400 text-xs ml-1">(Optional)</span>
            </label>
            <div className="relative">
              <input
                type="text"
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                placeholder="e.g., Lunch at cafe"
                className="w-full pr-12 pl-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                maxLength={100}
              />
              
              {/* Voice Button in Description Field */}
              {onVoiceEntry && (
                <button
                  type="button"
                  onClick={onVoiceEntry}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-blue-500 hover:text-blue-600"
                  title="Use voice input"
                >
                  <Mic className="w-5 h-5" />
                </button>
              )}
            </div>
          </div>

          {/* Merchant Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Merchant/Store
              <span className="text-gray-400 text-xs ml-1">(Optional)</span>
            </label>
            <input
              type="text"
              value={formData.merchant}
              onChange={(e) => handleInputChange('merchant', e.target.value)}
              placeholder="e.g., Swiggy, Amazon"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              maxLength={50}
            />
          </div>

          {/* Date Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Date
            </label>
            <input
              type="date"
              value={formData.date}
              onChange={(e) => handleInputChange('date', e.target.value)}
              max={new Date().toISOString().split('T')[0]}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
            />
          </div>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3">
              <p className="text-red-700 text-sm">{error}</p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex space-x-3 pt-4">
            
            {/* Voice Entry Button */}
            {onVoiceEntry && (
              <button
                type="button"
                onClick={onVoiceEntry}
                className="bg-blue-500 hover:bg-blue-600 text-white py-3 px-4 rounded-lg font-medium flex items-center justify-center"
                title="Switch to voice entry"
              >
                <Mic className="w-4 h-4 mr-2" />
                Voice
              </button>
            )}
            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className={`flex-1 py-3 px-4 rounded-lg font-medium flex items-center justify-center ${
                isSubmitting
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
            >
              {isSubmitting ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
              ) : (
                <Plus className="w-4 h-4 mr-2" />
              )}
              {isSubmitting ? 'Adding...' : 'Add Expense'}
            </button>
          </div>
        </form>

        {/* Voice Entry Tip */}
        {onVoiceEntry && (
          <div className="mt-4 bg-blue-50 rounded-lg p-3">
            <p className="text-xs text-blue-600 font-medium mb-1">💡 Pro Tip:</p>
            <p className="text-xs text-blue-700">
              Try voice entry for faster expense logging in Hindi, English, or Hinglish!
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
