'use client'

import { useState } from 'react'
import { X, TrendingUp, AlertTriangle, Target, Clock, BookOpen } from 'lucide-react'

export default function InvestmentAlertModal({ alert, isOpen, onClose, onSimulateInvestment }) {
  const [isSimulating, setIsSimulating] = useState(false)

  if (!isOpen || !alert) return null

  const handleSimulateInvestment = async () => {
    setIsSimulating(true)
    
    try {
      // Simulate investment processing
      await new Promise(resolve => setTimeout(resolve, 2000))
      
      if (onSimulateInvestment) {
        onSimulateInvestment(alert)
      }
      
      onClose()
    } catch (error) {
      console.error('Simulation error:', error)
    } finally {
      setIsSimulating(false)
    }
  }

  const handleRemindLater = () => {
    // Set reminder for 1 hour later
    console.log('Reminder set for 1 hour later')
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl max-w-md w-full shadow-2xl animate-in slide-in-from-bottom duration-300">
        
        {/* Header */}
        <div className="bg-gradient-to-r from-orange-500 to-red-500 text-white p-6 rounded-t-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full -mr-16 -mt-16"></div>
          <div className="relative">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-6 w-6" />
                <h2 className="text-xl font-bold">{alert.title}</h2>
              </div>
              <button
                onClick={onClose}
                className="text-white/80 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <p className="text-orange-100 text-sm">{alert.message}</p>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          
          {/* Market Condition */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex items-center mb-2">
              <TrendingUp className="h-5 w-5 text-red-600 mr-2" />
              <span className="font-medium text-red-800">Market Condition</span>
            </div>
            <p className="text-red-700 text-sm">{alert.marketCondition}</p>
            <div className="mt-2 flex items-center">
              <span className="text-xs text-red-600 mr-2">Opportunity Score:</span>
              <div className="flex space-x-1">
                {[...Array(10)].map((_, i) => (
                  <div
                    key={i}
                    className={`w-2 h-2 rounded-full ${
                      i < alert.opportunityScore ? 'bg-red-500' : 'bg-red-200'
                    }`}
                  />
                ))}
              </div>
              <span className="text-xs text-red-600 ml-2">{alert.opportunityScore}/10</span>
            </div>
          </div>

          {/* Investment Details */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center mb-3">
              <Target className="h-5 w-5 text-blue-600 mr-2" />
              <span className="font-medium text-blue-800">Simulated Returns</span>
            </div>
            <div className="text-center mb-3">
              <p className="text-sm text-blue-600 mb-1">Your Available Savings</p>
              <p className="text-2xl font-bold text-blue-800">₹{alert.metadata.userSavings}</p>
            </div>
            
            <div className="space-y-2">
              {alert.projectedReturns && Object.entries(alert.projectedReturns).map(([year, value]) => (
                <div key={year} className="flex justify-between items-center p-2 bg-blue-100 rounded">
                  <span className="font-medium text-blue-800">{year}:</span>
                  <span className="font-bold text-blue-900">{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Learning Tip */}
          <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4">
            <div className="flex items-center mb-2">
              <BookOpen className="h-5 w-5 text-emerald-600 mr-2" />
              <span className="font-medium text-emerald-800">Investment Tip</span>
            </div>
            <p className="text-emerald-700 text-sm">{alert.learningTip}</p>
          </div>

          {/* Risk Disclaimer */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
            <p className="text-yellow-800 text-xs font-medium">{alert.riskDisclaimer}</p>
          </div>

          {/* Action Buttons */}
          <div className="space-y-3">
            <button
              onClick={handleSimulateInvestment}
              disabled={isSimulating}
              className={`w-full py-3 px-4 rounded-lg font-medium transition-all ${
                isSimulating
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white shadow-lg hover:shadow-xl transform hover:scale-105'
              }`}
            >
              {isSimulating ? (
                <div className="flex items-center justify-center">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Simulating...
                </div>
              ) : (
                alert.actionText
              )}
            </button>
            
            <div className="flex space-x-3">
              <button
                onClick={handleRemindLater}
                className="flex-1 py-2 px-4 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                <Clock className="h-4 w-4 inline mr-1" />
                Remind Later
              </button>
              
              <button
                onClick={onClose}
                className="flex-1 py-2 px-4 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
