'use client'

import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Wallet,
  TrendingDown,
  Shield,
  Target,
  Sparkles,
  ChevronRight,
  Check
} from 'lucide-react'

// Strategic questions that directly impact AI recommendations
const PULSE_QUESTIONS = [
  {
    id: 'debt_status',
    question: 'Do you have any active loans or EMIs?',
    icon: '💳',
    description: 'Helps prioritize debt repayment vs savings',
    aiImpact: 'Adjusts budget to account for fixed obligations',
    options: [
      { value: 'none', label: 'No loans or EMIs', emoji: '✨', impact: 'Full income available for budgeting' },
      { value: 'low', label: 'Yes, under ₹10,000/month', emoji: '📊', impact: 'Moderate debt load' },
      { value: 'medium', label: 'Yes, ₹10,000-30,000/month', emoji: '⚖️', impact: 'Significant portion committed' },
      { value: 'high', label: 'Yes, over ₹30,000/month', emoji: '🎯', impact: 'Debt reduction priority' }
    ]
  },
  {
    id: 'savings_status',
    question: 'How much do you have saved for emergencies?',
    icon: '🛡️',
    description: 'Determines emergency fund priority',
    aiImpact: 'Recommends building safety net first',
    options: [
      { value: 'none', label: 'Less than 1 month expenses', emoji: '🚨', impact: 'Emergency fund is top priority' },
      { value: 'partial', label: '1-3 months expenses', emoji: '🔨', impact: 'Continue building safety net' },
      { value: 'adequate', label: '3-6 months expenses', emoji: '✅', impact: 'Can focus on investments' },
      { value: 'strong', label: 'More than 6 months', emoji: '💪', impact: 'Ready for wealth building' }
    ]
  },
  {
    id: 'money_stress',
    question: 'How do you feel about your finances right now?',
    icon: '🧠',
    description: 'Personalizes tone and urgency of advice',
    aiImpact: 'Adjusts communication style and priorities',
    options: [
      { value: 'stressed', label: 'Stressed - money is a constant worry', emoji: '😰', impact: 'Focus on stability first' },
      { value: 'concerned', label: 'Concerned - trying to improve', emoji: '🤔', impact: 'Balanced approach' },
      { value: 'stable', label: 'Stable - managing okay', emoji: '😊', impact: 'Growth-oriented advice' },
      { value: 'confident', label: 'Confident - finances are under control', emoji: '💪', impact: 'Optimization focus' }
    ]
  },
  {
    id: 'spending_style',
    question: 'How would you describe your spending habits?',
    icon: '🛒',
    description: 'Tailors saving strategies to your style',
    aiImpact: 'Recommends suitable budgeting methods',
    options: [
      { value: 'impulsive', label: 'Impulsive - often regret purchases', emoji: '⚡', impact: 'Needs spending guardrails' },
      { value: 'emotional', label: 'Emotional - spend when stressed/happy', emoji: '🎭', impact: 'Mindful spending tips' },
      { value: 'planned', label: 'Planned - mostly stick to budgets', emoji: '📋', impact: 'Fine-tune existing habits' },
      { value: 'frugal', label: 'Frugal - rarely spend on wants', emoji: '🎯', impact: 'Balance savings with living' }
    ]
  },
  {
    id: 'primary_goal',
    question: 'What\'s your #1 financial priority right now?',
    icon: '🎯',
    description: 'Focuses your entire budget around this goal',
    aiImpact: 'Prioritizes recommendations accordingly',
    options: [
      { value: 'debt_free', label: 'Become debt-free', emoji: '🔓', impact: 'Aggressive debt payoff plan' },
      { value: 'emergency_fund', label: 'Build emergency savings', emoji: '🛡️', impact: 'Safety-first budgeting' },
      { value: 'big_purchase', label: 'Save for big purchase (home/car/wedding)', emoji: '🏠', impact: 'Goal-based saving plan' },
      { value: 'invest', label: 'Start/grow investments', emoji: '📈', impact: 'Wealth-building focus' },
      { value: 'balance', label: 'Balance spending and saving', emoji: '⚖️', impact: 'Sustainable lifestyle budget' }
    ]
  }
]

export default function FinancialPulseStep({ profile, setProfile, onComplete }) {
  const [currentQuestion, setCurrentQuestion] = useState(0)
  const [answers, setAnswers] = useState(profile?.financialPulse || {})

  const question = PULSE_QUESTIONS[currentQuestion]
  const progress = ((currentQuestion + 1) / PULSE_QUESTIONS.length) * 100
  const isLastQuestion = currentQuestion === PULSE_QUESTIONS.length - 1

  const handleAnswer = (value) => {
    const newAnswers = { ...answers, [question.id]: value }
    setAnswers(newAnswers)

    // Update profile with financial pulse data
    setProfile(prev => ({
      ...prev,
      financialPulse: newAnswers
    }))

    // Auto-advance after brief delay
    setTimeout(() => {
      if (!isLastQuestion) {
        setCurrentQuestion(prev => prev + 1)
      } else {
        // All questions answered - complete step
        onComplete && onComplete(newAnswers)
      }
    }, 400)
  }

  const handleBack = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(prev => prev - 1)
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* Header with value proposition */}
      <div className="text-center mb-6">
        <div className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-100 to-pink-100 rounded-full mb-4">
          <Sparkles className="w-4 h-4 text-purple-600" />
          <span className="text-sm font-medium text-purple-700">5 Quick Questions = Smarter AI</span>
        </div>
        <p className="text-slate-600 text-sm max-w-md mx-auto">
          These questions help our AI understand your unique financial situation and give you
          <span className="font-semibold text-emerald-600"> personalized recommendations</span>
        </p>
      </div>

      {/* Progress indicator */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          {PULSE_QUESTIONS.map((q, idx) => (
            <div
              key={q.id}
              className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-all duration-300 ${
                idx < currentQuestion
                  ? 'bg-emerald-500 text-white'
                  : idx === currentQuestion
                  ? 'bg-emerald-100 text-emerald-700 ring-2 ring-emerald-500'
                  : 'bg-slate-100 text-slate-400'
              }`}
            >
              {idx < currentQuestion ? <Check className="w-4 h-4" /> : idx + 1}
            </div>
          ))}
        </div>
        <span className="text-sm text-slate-500">{currentQuestion + 1} of {PULSE_QUESTIONS.length}</span>
      </div>

      {/* Question Card */}
      <AnimatePresence mode="wait">
        <motion.div
          key={question.id}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          <Card className="border-2 border-slate-200 shadow-lg overflow-hidden">
            {/* Question Header */}
            <div className="bg-gradient-to-r from-slate-50 to-slate-100 p-6 border-b">
              <div className="flex items-start gap-4">
                <div className="text-4xl">{question.icon}</div>
                <div className="flex-1">
                  <h3 className="text-xl font-bold text-slate-900 mb-1">
                    {question.question}
                  </h3>
                  <p className="text-sm text-slate-600">{question.description}</p>
                </div>
              </div>
            </div>

            {/* Options */}
            <CardContent className="p-4 space-y-3">
              {question.options.map((option, idx) => {
                const isSelected = answers[question.id] === option.value
                return (
                  <motion.button
                    key={option.value}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    onClick={() => handleAnswer(option.value)}
                    className={`w-full p-4 rounded-xl border-2 text-left transition-all duration-200 ${
                      isSelected
                        ? 'border-emerald-500 bg-emerald-50 ring-2 ring-emerald-200'
                        : 'border-slate-200 hover:border-emerald-300 hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{option.emoji}</span>
                        <div>
                          <p className={`font-medium ${isSelected ? 'text-emerald-900' : 'text-slate-800'}`}>
                            {option.label}
                          </p>
                          <p className={`text-xs mt-0.5 ${isSelected ? 'text-emerald-600' : 'text-slate-500'}`}>
                            → {option.impact}
                          </p>
                        </div>
                      </div>
                      {isSelected && (
                        <div className="w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center">
                          <Check className="w-4 h-4 text-white" />
                        </div>
                      )}
                    </div>
                  </motion.button>
                )
              })}
            </CardContent>

            {/* AI Impact Note */}
            <div className="px-4 pb-4">
              <div className="flex items-center gap-2 p-3 bg-blue-50 rounded-lg border border-blue-100">
                <Sparkles className="w-4 h-4 text-blue-600 flex-shrink-0" />
                <p className="text-xs text-blue-700">
                  <span className="font-semibold">AI Impact:</span> {question.aiImpact}
                </p>
              </div>
            </div>
          </Card>
        </motion.div>
      </AnimatePresence>

      {/* Navigation */}
      <div className="flex justify-between mt-6">
        <Button
          variant="ghost"
          onClick={handleBack}
          disabled={currentQuestion === 0}
          className="text-slate-600"
        >
          ← Back
        </Button>

        {isLastQuestion && answers[question.id] && (
          <Button
            onClick={() => onComplete && onComplete(answers)}
            className="bg-emerald-600 hover:bg-emerald-700 text-white"
          >
            Generate My Budget <ChevronRight className="w-4 h-4 ml-1" />
          </Button>
        )}
      </div>
    </div>
  )
}
