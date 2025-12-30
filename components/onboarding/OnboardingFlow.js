'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import { useLanguage } from '@/components/providers/LanguageProvider'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import LanguageSelector from '@/components/ui/LanguageSelector'
import DetailedBudgetReport from '@/components/budget/DetailedBudgetReport'
import LifestyleQuiz from '@/components/onboarding/LifestyleQuiz'
import MultiIncomeStep from '@/components/onboarding/MultiIncomeStep'
import FinancialPulseStep from '@/components/onboarding/FinancialPulseStep'
import EnhancedDemographicsStep from '@/components/onboarding/EnhancedDemographicsStep'
import {
  ArrowRight,
  ArrowLeft,
  Coins,
  MapPin,
  Users,
  User,
  Briefcase,
  Loader2,
  CheckCircle,
  TrendingUp,
  PieChart,
  Target
} from 'lucide-react'
import toast from 'react-hot-toast'

// Indian cities for autocomplete
const INDIAN_CITIES = [
  'Mumbai', 'Delhi', 'Bangalore', 'Hyderabad', 'Chennai', 'Pune', 'Ahmedabad',
  'Kolkata', 'Jaipur', 'Lucknow', 'Kanpur', 'Nagpur', 'Indore', 'Thane',
  'Bhopal', 'Visakhapatnam', 'Pimpri-Chinchwad', 'Patna', 'Vadodara', 'Ghaziabad'
]

const INCOME_SOURCES = [
  { value: 'salary', label: 'Salary (Job)' },
  { value: 'business', label: 'Business' },
  { value: 'freelance', label: 'Freelancing' },
  { value: 'other', label: 'Other' }
]

const ONBOARDING_STEPS = [
  { key: 'language', title: 'Language', shortTitle: 'Language', icon: '🌐' },
  { key: 'income', title: 'Income Details', shortTitle: 'Income', icon: '💰' },
  { key: 'demographics', title: 'About You', shortTitle: 'Profile', icon: '👤' },
  { key: 'financial_pulse', title: 'Financial Pulse', shortTitle: 'Pulse', icon: '💡' },
  { key: 'budget_generation', title: 'AI Budget', shortTitle: 'Budget', icon: '🤖' },
  { key: 'review', title: 'Review', shortTitle: 'Review', icon: '✓' }
]

export default function OnboardingFlow() {
  const { data: session, status } = useSession()
  const { t } = useTranslation()
  const { currentLanguage, changeLanguage } = useLanguage()
  const router = useRouter()

  const [currentStep, setCurrentStep] = useState(0)
  const [loading, setLoading] = useState(false)
  const [profile, setProfile] = useState({
    monthlyIncome: '',
    incomeSource: 'salary',
    incomeSources: [], // Multiple income sources support
    city: '',
    familySize: '',
    age: '',
    occupation: '',
    // Enhanced demographics
    livingSituation: '',
    commuteMode: '',
    hasKids: false,
    monthlyRent: '',
    // Financial Pulse (strategic questions)
    financialPulse: {},
    budgetPreferences: {
      language: 'hinglish',
      notifications: true
    },
    lifestyleAnswers: {} // Legacy: Store quiz answers
  })
  const [generatedBudget, setGeneratedBudget] = useState(null)
  const [isGeneratingBudget, setIsGeneratingBudget] = useState(false)

  // Load existing profile on mount
  useEffect(() => {
    const loadProfile = async () => {
      try {
        const response = await fetch('/api/onboarding')
        if (response.ok) {
          const profile = await response.json()
          if (profile) {
            setProfile(profile)
            // Skip to the last incomplete step
            const lastStep = ONBOARDING_STEPS.findIndex(step => !profile[step.key + '_completed'])
            if (lastStep !== -1) {
              setCurrentStep(lastStep)
            } else {
              // All steps completed, go to review
              setCurrentStep(ONBOARDING_STEPS.length - 1)
            }
          }
        }
      } catch (error) {
        console.error('Failed to load profile:', error)
        // Continue with onboarding if loading fails
      } finally {
        setLoading(false)
      }
    }

    if (status === 'authenticated') {
      loadProfile()
    }
  }, [status])

  const updateProfile = async (stepKey, stepData) => {
    setLoading(true)
    try {
      const response = await fetch('/api/onboarding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ step: stepKey, data: stepData })
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to update profile')
      }

      setProfile(prev => ({ ...prev, ...result.profile }))
      return true
    } catch (error) {
      toast.error(error.message)
      return false
    } finally {
      setLoading(false)
    }
  }

  const generateBudget = async () => {
    setIsGeneratingBudget(true)
    try {
      console.log('Generating budget for onboarding...')
      const response = await fetch('/api/budget/generate', {
        method: 'POST'
      })

      const result = await response.json()
      console.log('Budget generation response:', { success: response.ok, hasBudget: !!result.budget, hasCategories: !!result.budget?.categories })

      if (!response.ok) {
        throw new Error(result.error || 'Failed to generate budget')
      }

      if (!result.budget || !result.budget.categories) {
        throw new Error('Invalid budget structure received')
      }

      setGeneratedBudget(result.budget)
      toast.success('Budget generated successfully! 🎉')
      return true
    } catch (error) {
      console.error('Budget generation error:', error)
      toast.error(`Budget generation failed: ${error.message}`)
      return false
    } finally {
      setIsGeneratingBudget(false)
    }
  }

  const handleNext = async () => {
    const step = ONBOARDING_STEPS[currentStep]

    switch (step.key) {
      case 'language':
        // Language selection is handled by the LanguageSelector component
        // Just move to the next step
        setCurrentStep(1)
        break

      case 'income':
        // Support both multi-income and legacy single income
        const hasIncomeSources = profile.incomeSources && profile.incomeSources.length > 0
        const hasLegacyIncome = profile.monthlyIncome && parseInt(profile.monthlyIncome) >= 1000

        if (!hasIncomeSources && !hasLegacyIncome) {
          toast.error('Please add at least one income source')
          return
        }

        // Prepare income data for API
        const incomeData = {
          incomeSources: profile.incomeSources || [],
          monthlyIncome: parseInt(profile.monthlyIncome) || 0,
          incomeSource: profile.incomeSource || 'salary'
        }

        const incomeSuccess = await updateProfile('income', incomeData)

        if (incomeSuccess) {
          setCurrentStep(2)
        }
        break

      case 'demographics':
        if (!profile.city || !profile.familySize || !profile.age || !profile.livingSituation) {
          toast.error('Please fill in all required fields (City, Age, Family Size, Living Situation)')
          return
        }

        const demoSuccess = await updateProfile('demographics', {
          city: profile.city,
          familySize: parseInt(profile.familySize),
          age: parseInt(profile.age),
          occupation: profile.occupation,
          // Enhanced fields
          livingSituation: profile.livingSituation,
          commuteMode: profile.commuteMode,
          hasKids: profile.hasKids,
          monthlyRent: profile.monthlyRent ? parseInt(profile.monthlyRent) : 0
        })

        if (demoSuccess) {
          setCurrentStep(3)
        }
        break

      case 'financial_pulse':
        // Financial pulse provides critical context for AI
        const pulseData = profile.financialPulse || {}
        const hasPulseData = Object.keys(pulseData).length > 0

        const pulseSuccess = await updateProfile('financial_pulse', {
          financialPulse: pulseData,
          // Map pulse answers to budget preferences for AI
          budgetPreferences: {
            ...profile.budgetPreferences,
            spendingStyle: pulseData.spending_style || 'balanced',
            primaryGoal: pulseData.primary_goal || 'balance',
            debtStatus: pulseData.debt_status || 'none',
            savingsStatus: pulseData.savings_status || 'partial',
            moneyStress: pulseData.money_stress || 'stable'
          }
        })

        if (pulseSuccess) {
          setCurrentStep(4)
        }
        break

      case 'budget_generation':
        const budgetSuccess = await generateBudget()
        if (budgetSuccess) {
          setCurrentStep(5)
        }
        break

      case 'review':
        const completeSuccess = await updateProfile('complete', {})
        if (completeSuccess) {
          toast.success('Onboarding completed! Welcome to WealthWise! 🎉')
          router.push('/dashboard')
        }
        break
    }
  }

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-emerald-600" />
      </div>
    )
  }

  if (status === 'unauthenticated') {
    router.push('/auth/signin')
    return null
  }

  const progressPercentage = ((currentStep + 1) / ONBOARDING_STEPS.length) * 100

  return (
    <div className="h-[calc(100vh-80px)] bg-white overflow-hidden">
      <div className="max-w-3xl mx-auto px-4 h-full flex flex-col py-4">
        {/* Compact Progress Section */}
        <div className="flex-shrink-0 mb-4">
          {/* Step Counter Badge & Progress Bar Combined */}
          <div className="flex items-center gap-4 mb-3">
            <div className="inline-flex items-center space-x-2 bg-slate-100 rounded-full px-4 py-1.5 flex-shrink-0">
              <span className="text-xs font-medium text-slate-600">Step</span>
              <span className="text-xs font-bold text-slate-900">{currentStep + 1}</span>
              <span className="text-xs text-slate-400">/</span>
              <span className="text-xs text-slate-500">{ONBOARDING_STEPS.length}</span>
            </div>

            {/* Progress Bar */}
            <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full transition-all duration-500 ease-out"
                style={{ width: `${progressPercentage}%` }}
              ></div>
            </div>
          </div>

          {/* Step Title - Compact */}
          <div className="text-center">
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-1">
              {ONBOARDING_STEPS[currentStep].title}
            </h1>
            <p className="text-slate-600 text-sm">
              {currentStep === 0 && "Choose your preferred language"}
              {currentStep === 1 && "Tell us about your earnings"}
              {currentStep === 2 && "Help us personalize your budget for your lifestyle"}
              {currentStep === 3 && "5 quick questions for smarter AI recommendations"}
              {currentStep === 4 && "Let AI create your personalized budget"}
              {currentStep === 5 && "Review and finalize your setup"}
            </p>
          </div>
        </div>

        {/* Content Card - Flexible Height */}
        <div className="flex-1 bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden flex flex-col mb-4">
          <div className="flex-1 overflow-y-auto p-6 sm:p-8">
            {currentStep === 0 && <LanguageStep />}
            {currentStep === 1 && <MultiIncomeStep profile={profile} setProfile={setProfile} />}
            {currentStep === 2 && <EnhancedDemographicsStep profile={profile} setProfile={setProfile} />}
            {currentStep === 3 && (
              <FinancialPulseStep
                profile={profile}
                setProfile={setProfile}
                onComplete={(answers) => {
                  setProfile(prev => ({ ...prev, financialPulse: answers }))
                }}
              />
            )}
            {currentStep === 4 && <BudgetGenerationStep isGenerating={isGeneratingBudget} profile={profile} />}
            {currentStep === 5 && <ReviewStep profile={profile} budget={generatedBudget} />}
          </div>
        </div>

        {/* Navigation Buttons - Fixed at Bottom */}
        <div className="flex-shrink-0 space-y-3">
          <div className="flex items-center justify-between gap-4">
            <Button
              onClick={handleBack}
              disabled={currentStep === 0 || loading}
              variant="outline"
              className="group border-2 border-slate-200 hover:border-slate-300 text-slate-700 hover:bg-slate-50 font-medium px-6 py-2.5 h-11 rounded-xl transition-all duration-200 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-0.5 transition-transform duration-200" />
              Back
            </Button>

            <Button
              onClick={handleNext}
              disabled={loading || isGeneratingBudget}
              className="group bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-8 py-2.5 h-11 rounded-xl shadow-sm hover:shadow-md transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading || isGeneratingBudget ? (
                <div className="flex items-center">
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  <span>{isGeneratingBudget ? 'Generating...' : 'Processing...'}</span>
                </div>
              ) : (
                <>
                  <span>{currentStep === ONBOARDING_STEPS.length - 1 ? 'Complete Setup' : 'Continue'}</span>
                  <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-0.5 transition-transform duration-200" />
                </>
              )}
            </Button>
          </div>

          {/* Step Indicators */}
          <div className="flex items-center justify-center gap-2">
            {ONBOARDING_STEPS.map((step, index) => (
              <div
                key={step.key}
                className={`h-1.5 rounded-full transition-all duration-300 ${index < currentStep
                  ? 'w-8 bg-emerald-500'
                  : index === currentStep
                    ? 'w-12 bg-emerald-600'
                    : 'w-8 bg-slate-200'
                  }`}
              ></div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// Language Step Component
function LanguageStep() {
  return <LanguageSelector variant="onboarding" />
}

// Income Step Component
function IncomeStep({ profile, setProfile }) {
  const { t } = useTranslation()

  return (
    <div className="space-y-5">
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            Monthly Income <span className="text-red-500">*</span>
          </label>
          <div className="relative">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 font-medium">₹</span>
            <Input
              type="number"
              placeholder="50,000"
              value={profile.monthlyIncome}
              onChange={(e) => setProfile(prev => ({ ...prev, monthlyIncome: e.target.value }))}
              className="h-11 pl-10 text-base border-slate-200 focus:border-emerald-500 focus:ring-emerald-500 rounded-lg"
              min="1000"
              step="1000"
            />
          </div>
          <p className="text-xs text-slate-500 mt-1">Minimum ₹1,000 required</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            Income Source
          </label>
          <Select value={profile.incomeSource} onValueChange={(value) => setProfile(prev => ({ ...prev, incomeSource: value }))}>
            <SelectTrigger className="h-11 border-slate-200 focus:border-emerald-500 rounded-lg">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="rounded-lg">
              {INCOME_SOURCES.map(source => (
                <SelectItem
                  key={source.value}
                  value={source.value}
                  className="cursor-pointer focus:bg-emerald-50 rounded-md"
                >
                  {source.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="bg-emerald-50 border border-emerald-100 rounded-xl p-3">
        <div className="flex gap-2.5">
          <div className="flex-shrink-0 w-4 h-4 bg-emerald-500 rounded-full flex items-center justify-center text-white text-[10px] font-bold mt-0.5">i</div>
          <div>
            <p className="text-xs font-medium text-emerald-900 mb-0.5">Why we need this</p>
            <p className="text-[11px] text-emerald-700 leading-snug">Your income helps us create a personalized budget that matches your financial situation.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// Demographics Step Component
function DemographicsStep({ profile, setProfile }) {
  const { t } = useTranslation()

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* City */}
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            City <span className="text-red-500">*</span>
          </label>
          <Select value={profile.city} onValueChange={(value) => setProfile(prev => ({ ...prev, city: value }))}>
            <SelectTrigger className="h-11 border-slate-200 focus:border-emerald-500 rounded-lg">
              <SelectValue placeholder="Select your city" />
            </SelectTrigger>
            <SelectContent className="rounded-lg max-h-[300px]">
              {INDIAN_CITIES.map(city => (
                <SelectItem
                  key={city}
                  value={city}
                  className="cursor-pointer focus:bg-emerald-50 rounded-md"
                >
                  {city}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Family Size */}
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            Family Size <span className="text-red-500">*</span>
          </label>
          <Input
            type="number"
            placeholder="e.g., 4"
            value={profile.familySize}
            onChange={(e) => setProfile(prev => ({ ...prev, familySize: e.target.value }))}
            className="h-11 border-slate-200 focus:border-emerald-500 focus:ring-emerald-500 rounded-lg"
            min="1"
            max="20"
          />
        </div>

        {/* Age */}
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            Age <span className="text-red-500">*</span>
          </label>
          <Input
            type="number"
            placeholder="e.g., 30"
            value={profile.age}
            onChange={(e) => setProfile(prev => ({ ...prev, age: e.target.value }))}
            className="h-11 border-slate-200 focus:border-emerald-500 focus:ring-emerald-500 rounded-lg"
            min="18"
            max="100"
          />
        </div>

        {/* Occupation */}
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">
            Occupation
          </label>
          <Input
            type="text"
            placeholder="e.g., Software Engineer"
            value={profile.occupation}
            onChange={(e) => setProfile(prev => ({ ...prev, occupation: e.target.value }))}
            className="h-11 border-slate-200 focus:border-emerald-500 focus:ring-emerald-500 rounded-lg"
          />
        </div>
      </div>

      <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
        <div className="flex gap-2.5">
          <div className="flex-shrink-0 w-4 h-4 bg-slate-400 rounded-full flex items-center justify-center text-white text-[10px] font-bold mt-0.5">🔒</div>
          <div>
            <p className="text-xs font-medium text-slate-900 mb-0.5">Your data is secure</p>
            <p className="text-[11px] text-slate-600 leading-snug">We use this information only to create accurate financial recommendations tailored to your location.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// Budget Generation Step Component - Enhanced with profile preview
function BudgetGenerationStep({ isGenerating, profile }) {
  const { t } = useTranslation()

  // Calculate total income from sources
  const totalIncome = profile?.incomeSources?.length > 0
    ? profile.incomeSources.reduce((sum, s) => sum + (s.amount || 0), 0)
    : parseInt(profile?.monthlyIncome) || 0

  // Get pulse insights for display
  const pulse = profile?.financialPulse || {}
  const pulseInsights = []

  if (pulse.debt_status === 'high' || pulse.debt_status === 'medium') {
    pulseInsights.push({ emoji: '🎯', text: 'Prioritizing debt repayment' })
  }
  if (pulse.savings_status === 'none' || pulse.savings_status === 'partial') {
    pulseInsights.push({ emoji: '🛡️', text: 'Building emergency fund' })
  }
  if (pulse.primary_goal) {
    const goalLabels = {
      debt_free: 'Debt freedom focus',
      emergency_fund: 'Safety-first budgeting',
      big_purchase: 'Goal-based savings',
      invest: 'Wealth-building mode',
      balance: 'Balanced lifestyle'
    }
    pulseInsights.push({ emoji: '✨', text: goalLabels[pulse.primary_goal] || 'Personalized approach' })
  }

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      {/* Header */}
      <div className="text-center">
        <div className="w-16 h-16 bg-gradient-to-br from-emerald-100 to-teal-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
          {isGenerating ? (
            <Loader2 className="w-8 h-8 text-emerald-600 animate-spin" />
          ) : (
            <PieChart className="w-8 h-8 text-emerald-600" />
          )}
        </div>
        <h3 className="text-lg font-bold text-slate-900 mb-1">
          {isGenerating ? 'Creating Your Budget...' : 'Ready to Generate'}
        </h3>
        <p className="text-sm text-slate-600">
          {isGenerating
            ? 'AI is analyzing your financial profile'
            : 'Click Continue to generate your personalized budget'
          }
        </p>
      </div>

      {/* Profile Summary Card */}
      <div className="bg-gradient-to-br from-slate-50 to-slate-100 rounded-xl p-4 border border-slate-200">
        <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
          <Target className="w-4 h-4" />
          AI will consider:
        </h4>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="bg-white rounded-lg p-3 border border-slate-200">
            <p className="text-xs text-slate-500">Monthly Income</p>
            <p className="font-bold text-emerald-600">₹{totalIncome.toLocaleString('en-IN')}</p>
          </div>
          <div className="bg-white rounded-lg p-3 border border-slate-200">
            <p className="text-xs text-slate-500">Location</p>
            <p className="font-bold text-slate-800">{profile?.city || 'India'}</p>
          </div>
          <div className="bg-white rounded-lg p-3 border border-slate-200">
            <p className="text-xs text-slate-500">Family Size</p>
            <p className="font-bold text-slate-800">{profile?.familySize || 1} members</p>
          </div>
          <div className="bg-white rounded-lg p-3 border border-slate-200">
            <p className="text-xs text-slate-500">Living</p>
            <p className="font-bold text-slate-800 text-xs">
              {profile?.livingSituation?.replace(/_/g, ' ') || 'Not specified'}
            </p>
          </div>
        </div>

        {/* Pulse Insights */}
        {pulseInsights.length > 0 && (
          <div className="mt-4 pt-3 border-t border-slate-200">
            <p className="text-xs text-slate-500 mb-2">Based on your financial pulse:</p>
            <div className="flex flex-wrap gap-2">
              {pulseInsights.map((insight, idx) => (
                <span
                  key={idx}
                  className="inline-flex items-center gap-1 px-2 py-1 bg-purple-50 text-purple-700 rounded-full text-xs font-medium"
                >
                  {insight.emoji} {insight.text}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Generation Progress */}
      {isGenerating && (
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2 text-slate-600">
            <div className="w-4 h-4 rounded-full bg-emerald-500 animate-pulse" />
            <span>Analyzing income sources...</span>
          </div>
          <div className="flex items-center gap-2 text-slate-600">
            <div className="w-4 h-4 rounded-full bg-emerald-300 animate-pulse" style={{ animationDelay: '0.2s' }} />
            <span>Calculating {profile?.city} cost of living...</span>
          </div>
          <div className="flex items-center gap-2 text-slate-600">
            <div className="w-4 h-4 rounded-full bg-emerald-200 animate-pulse" style={{ animationDelay: '0.4s' }} />
            <span>Creating personalized allocations...</span>
          </div>
        </div>
      )}

      {/* What you'll get */}
      <div className="bg-emerald-50 rounded-xl p-4 border border-emerald-100">
        <h4 className="font-semibold text-emerald-900 mb-3 text-sm">What you&apos;ll get:</h4>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            <span className="text-emerald-800">Smart category budgets</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            <span className="text-emerald-800">Savings recommendations</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            <span className="text-emerald-800">Investment advice</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            <span className="text-emerald-800">Tax-saving tips</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// Lifestyle Quiz Step Component (Optional)
function LifestyleQuizStep({ profile, setProfile, onSkip, onComplete }) {
  const handleQuizComplete = (answers) => {
    // Save answers to profile state
    setProfile(prev => ({
      ...prev,
      lifestyleAnswers: answers
    }))

    // Notify parent component that quiz is complete
    // This will trigger the handleNext function in the main flow
    if (onComplete) {
      setTimeout(() => {
        onComplete(answers)
      }, 500)
    }
  }

  const handleSkipQuiz = () => {
    // Skip quiz - proceed to budget generation
    onSkip()
  }

  return (
    <LifestyleQuiz
      onComplete={handleQuizComplete}
      onSkip={handleSkipQuiz}
      initialAnswers={profile.lifestyleAnswers || {}}
    />
  )
}

// Review Step Component  
function ReviewStep({ profile, budget }) {
  const { t } = useTranslation()

  if (!budget) {
    return (
      <div className="text-center py-8">
        <p className="text-slate-600 text-sm">Budget not generated yet. Please go back and generate your budget.</p>
      </div>
    )
  }

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(amount)
  }

  return (
    <div>
      {/* Use new detailed budget report component */}
      <DetailedBudgetReport budget={budget} profile={profile} />

      <p className="text-center text-sm text-slate-500 pt-4 pb-2">
        Click &apos;Complete Setup&apos; below to start managing your finances
      </p>
    </div>
  )
}
