'use client'

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from '@/lib/i18n'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip
} from 'recharts'
import {
  Lightbulb,
  Star,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  BarChart3,
  Settings,
  Wallet,
  TrendingUp,
  Eye,
  Activity,
  PieChart as PieChartIcon
} from 'lucide-react'
import BudgetCustomizer from '@/components/budget/BudgetCustomizer'
import BudgetCustomizationGuide from '@/components/budget/BudgetCustomizationGuide'
import ExpenseTrackingDashboard from '@/components/dashboard/ExpenseTrackingDashboard'
import toast from 'react-hot-toast'

// Category colors for charts
const CATEGORY_COLORS = {
  'Food & Dining': '#f97316',
  'Transportation': '#3b82f6',
  'Housing': '#8b5cf6',
  'Entertainment': '#ec4899',
  'Healthcare': '#ef4444',
  'Shopping': '#10b981',
  'Utilities': '#eab308',
  'Savings': '#06b6d4',
  'Other': '#64748b'
}

// Skeleton components
function SkeletonBox({ className }) {
  return <div className={`animate-pulse bg-slate-200 rounded ${className}`} />
}

function BudgetSkeleton() {
  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header Skeleton */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 sm:p-6">
        <div className="flex flex-col sm:flex-row justify-between gap-4">
          <div className="space-y-3 flex-1">
            <SkeletonBox className="h-5 w-24" />
            <SkeletonBox className="h-8 w-48" />
            <SkeletonBox className="h-4 w-32" />
          </div>
          <div className="flex items-center gap-3">
            <SkeletonBox className="h-20 w-24 rounded-xl" />
            <div className="space-y-2">
              <SkeletonBox className="h-9 w-24" />
              <SkeletonBox className="h-8 w-20" />
            </div>
          </div>
        </div>
      </div>

      {/* Stats Skeleton */}
      <div className="grid grid-cols-3 gap-3">
        {[1, 2, 3].map(i => (
          <div key={i} className="bg-white rounded-xl border border-slate-200 p-4">
            <SkeletonBox className="h-4 w-20 mb-2" />
            <SkeletonBox className="h-7 w-28" />
          </div>
        ))}
      </div>

      {/* Categories Skeleton */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 sm:p-6">
        <div className="flex justify-between items-center mb-6">
          <SkeletonBox className="h-6 w-40" />
          <SkeletonBox className="h-9 w-32" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map(i => (
            <div key={i} className="border border-slate-200 rounded-xl p-4">
              <div className="flex justify-between mb-3">
                <SkeletonBox className="h-5 w-24" />
                <SkeletonBox className="h-5 w-12" />
              </div>
              <SkeletonBox className="h-8 w-20 mb-3" />
              <SkeletonBox className="h-2 w-full" />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function BudgetDisplay({ refreshTrigger }) {
  const { t } = useTranslation()
  const [budget, setBudget] = useState(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [showCustomizer, setShowCustomizer] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    fetchBudget()
  }, [refreshTrigger])

  const fetchBudget = async () => {
    try {
      const response = await fetch('/api/budget/generate')
      const data = await response.json()
      if (data.success) {
        setBudget(data.budget)
      } else {
        setBudget(null)
      }
    } catch (error) {
      console.error('Failed to fetch budget:', error)
    } finally {
      setLoading(false)
    }
  }

  const generateBudget = async () => {
    setGenerating(true)
    try {
      const response = await fetch('/api/budget/generate', { method: 'POST' })
      const data = await response.json()
      if (data.success) {
        setBudget(data.budget)
        toast.success('Budget generated successfully!')
      } else {
        toast.error(data.error || 'Failed to generate budget')
      }
    } catch (error) {
      toast.error('Failed to generate budget')
    } finally {
      setGenerating(false)
    }
  }

  const handleSaveCustomBudget = async (customizedBudget) => {
    try {
      const response = await fetch('/api/budget/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ budget: customizedBudget })
      })
      const data = await response.json()
      if (data.success) {
        setBudget(customizedBudget)
        setShowCustomizer(false)
        toast.success('Budget saved successfully!')
      } else {
        throw new Error(data.error)
      }
    } catch (error) {
      toast.error('Failed to save budget')
    }
  }

  const getHealthBadge = (score) => {
    if (score >= 80) return { text: t('budget.excellent'), color: 'bg-emerald-100 text-emerald-700' }
    if (score >= 60) return { text: t('budget.good'), color: 'bg-yellow-100 text-yellow-700' }
    return { text: t('budget.needsImprovement'), color: 'bg-red-100 text-red-700' }
  }

  // Chart data
  const chartData = useMemo(() => {
    if (!budget?.categories) return { pieData: [], barData: [] }

    const entries = Object.entries(budget.categories)
    const pieData = entries.map(([key, cat]) => ({
      name: cat.englishName || key,
      value: cat.amount || 0,
      color: CATEGORY_COLORS[cat.englishName] || CATEGORY_COLORS['Other']
    }))
    const barData = entries.map(([key, cat]) => ({
      name: cat.englishName || key,
      amount: cat.amount || 0
    }))

    return { pieData, barData }
  }, [budget])

  // Loading state
  if (loading) {
    return <BudgetSkeleton />
  }

  // Show customizer
  if (showCustomizer && budget) {
    return (
      <BudgetCustomizer
        budget={budget}
        onSave={handleSaveCustomBudget}
        onCancel={() => setShowCustomizer(false)}
      />
    )
  }

  // Show guide
  if (showGuide) {
    return (
      <BudgetCustomizationGuide
        onStartCustomization={() => {
          setShowGuide(false)
          setShowCustomizer(true)
        }}
      />
    )
  }

  // No budget state
  if (!budget) {
    return (
      <div className="max-w-2xl mx-auto">
        <Card className="border-slate-200">
          <CardContent className="p-8 sm:p-12 text-center">
            <div className="w-16 h-16 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl flex items-center justify-center mx-auto mb-6">
              <BarChart3 className="w-8 h-8 text-white" />
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-800 mb-2">
              {t('budget.noBudget')}
            </h2>
            <p className="text-slate-500 mb-6 max-w-md mx-auto">
              {t('budget.noBudgetDesc')}
            </p>
            <Button
              onClick={generateBudget}
              disabled={generating}
              className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3"
            >
              {generating ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  {t('budget.generatingBudget')}
                </>
              ) : (
                <>
                  <Star className="w-4 h-4 mr-2" />
                  {t('budget.generateBudget')}
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Invalid budget state
  if (!budget.categories) {
    return (
      <Card className="max-w-md mx-auto">
        <CardContent className="p-8 text-center">
          <AlertCircle className="w-12 h-12 text-slate-300 mx-auto mb-4" />
          <p className="text-slate-500">Budget data not available</p>
        </CardContent>
      </Card>
    )
  }

  const healthBadge = getHealthBadge(budget.healthScore || 0)
  const totalAllocated = Object.values(budget.categories).reduce((sum, cat) => sum + (cat.amount || 0), 0)

  return (
    <div className="space-y-4 lg:space-y-6 max-w-6xl mx-auto">

      {/* Compact Budget Header */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 sm:p-6">
        <div className="flex flex-col sm:flex-row justify-between gap-4">
          {/* Left: Budget Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 bg-emerald-500 rounded-full" />
              <span className="text-xs font-medium text-emerald-700">
                {budget.isCustomized ? t('budget.customBudget') : t('budget.smartBudget')}
              </span>
              {budget.isCustomized && (
                <Badge className="bg-emerald-100 text-emerald-700 text-xs px-2 py-0.5">
                  {t('budget.personalized')}
                </Badge>
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-800 mb-1">
              {t('budget.budgetOverview')}
            </h1>
            <p className="text-lg sm:text-xl font-semibold text-slate-700">
              ₹{(budget.totalBudget || 0).toLocaleString('en-IN')}
            </p>
            <p className="text-xs text-slate-400 mt-1">
              {t('budget.lastUpdated')}: {budget.generatedAt ? new Date(budget.generatedAt).toLocaleDateString('en-IN') : 'N/A'}
            </p>
          </div>

          {/* Right: Health Score & Actions */}
          <div className="flex items-center gap-3">
            <div className="bg-slate-50 rounded-xl p-3 sm:p-4 text-center min-w-[90px]">
              <Star className="w-5 h-5 text-slate-500 mx-auto mb-1" />
              <div className="text-xl sm:text-2xl font-bold text-slate-800">
                {budget.healthScore || 0}%
              </div>
              <Badge className={`text-xs ${healthBadge.color}`}>
                {healthBadge.text}
              </Badge>
            </div>
            <div className="flex flex-col gap-2">
              <Button
                onClick={() => setShowCustomizer(true)}
                size="sm"
                className="bg-emerald-600 hover:bg-emerald-700 text-white h-9"
              >
                <Settings className="w-4 h-4 mr-1.5" />
                <span className="hidden sm:inline">{t('budget.customize')}</span>
                <span className="sm:hidden">{t('budget.edit')}</span>
              </Button>
              <Button
                onClick={() => setShowGuide(true)}
                variant="outline"
                size="sm"
                className="h-8 text-xs"
              >
                <Lightbulb className="w-3 h-3 mr-1" />
                <span className="hidden sm:inline">{t('budget.learn')}</span>
                <span className="sm:hidden">{t('budget.info')}</span>
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center">
              <Wallet className="w-4 h-4 text-emerald-600" />
            </div>
            <span className="text-xs text-slate-500 hidden sm:inline">{t('budget.monthlyBudget')}</span>
          </div>
          <p className="text-lg sm:text-xl font-bold text-emerald-600">
            ₹{(budget.totalBudget || 0).toLocaleString('en-IN')}
          </p>
          <p className="text-xs text-slate-400 sm:hidden">Budget</p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
              <TrendingUp className="w-4 h-4 text-blue-600" />
            </div>
            <span className="text-xs text-slate-500 hidden sm:inline">{t('budget.allocated')}</span>
          </div>
          <p className="text-lg sm:text-xl font-bold text-blue-600">
            ₹{totalAllocated.toLocaleString('en-IN')}
          </p>
          <p className="text-xs text-slate-400 sm:hidden">Allocated</p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-purple-100 flex items-center justify-center">
              <BarChart3 className="w-4 h-4 text-purple-600" />
            </div>
            <span className="text-xs text-slate-500 hidden sm:inline">{t('budget.categories')}</span>
          </div>
          <p className="text-lg sm:text-xl font-bold text-purple-600">
            {Object.keys(budget.categories).length}
          </p>
          <p className="text-xs text-slate-400 sm:hidden">Categories</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 p-1 bg-slate-100 rounded-xl">
        {[
          { id: 'overview', label: 'Overview', icon: Eye },
          { id: 'tracking', label: t('budget.tracking'), icon: Activity },
          { id: 'analytics', label: t('budget.analytics'), icon: PieChartIcon }
        ].map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg font-medium text-sm transition-all ${
                activeTab === tab.id
                  ? 'bg-white text-emerald-600 shadow-sm'
                  : 'text-slate-600 hover:text-slate-800'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <Card className="border-slate-200">
          <CardHeader className="pb-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <CardTitle className="text-lg font-semibold text-slate-800 flex items-center gap-2">
                  <Wallet className="w-5 h-5 text-emerald-600" />
                  {t('budget.budgetCategories')}
                </CardTitle>
                <p className="text-sm text-slate-500 mt-1">
                  {budget.isCustomized ? t('budget.personalizedAllocation') : t('budget.aiRecommendedBreakdown')}
                </p>
              </div>
              <Button
                onClick={() => setShowCustomizer(true)}
                variant="outline"
                size="sm"
                className="border-emerald-200 text-emerald-700 hover:bg-emerald-50"
              >
                <Settings className="w-4 h-4 mr-1.5" />
                {budget.isCustomized ? t('budget.modifyBudget') : t('budget.customizeBudget')}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {Object.entries(budget.categories).map(([key, category]) => (
                <div
                  key={key}
                  className="border border-slate-200 rounded-xl p-4 hover:shadow-md transition-shadow bg-white"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{category.emoji || '📦'}</span>
                      <span className="font-medium text-slate-800 text-sm">
                        {category.englishName || key}
                      </span>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {category.percentage || 0}%
                    </Badge>
                  </div>
                  <p className="text-xl font-bold text-slate-800 mb-2">
                    ₹{(category.amount || 0).toLocaleString('en-IN')}
                  </p>
                  <Progress value={category.percentage || 0} className="h-1.5 mb-2" />
                  {budget.explanations?.categories?.[key] && (
                    <p className="text-xs text-slate-500 line-clamp-2">
                      {budget.explanations.categories[key]}
                    </p>
                  )}
                </div>
              ))}
            </div>

            {/* Success message for customized budget */}
            {budget.isCustomized && (
              <div className="mt-4 p-4 bg-emerald-50 rounded-xl border border-emerald-200">
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-emerald-600 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-emerald-800 text-sm">Budget Customized</p>
                    {budget.customizedAt && (
                      <p className="text-xs text-emerald-600 mt-0.5">
                        Last modified: {new Date(budget.customizedAt).toLocaleDateString('en-IN')}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'tracking' && (
        <ExpenseTrackingDashboard budget={budget} refreshTrigger={refreshTrigger} />
      )}

      {activeTab === 'analytics' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Pie Chart */}
          <Card className="border-slate-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                <PieChartIcon className="w-4 h-4 text-emerald-600" />
                Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={chartData.pieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${(percent * 100).toFixed(0)}%`}
                    outerRadius={90}
                    dataKey="value"
                  >
                    {chartData.pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value) => `₹${value.toLocaleString('en-IN')}`}
                    contentStyle={{
                      backgroundColor: 'white',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Bar Chart */}
          <Card className="border-slate-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-blue-600" />
                Category Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={chartData.barData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis
                    dataKey="name"
                    angle={-45}
                    textAnchor="end"
                    height={80}
                    fontSize={11}
                    stroke="#64748b"
                  />
                  <YAxis
                    tickFormatter={(value) => `₹${(value / 1000).toFixed(0)}k`}
                    stroke="#64748b"
                    fontSize={11}
                  />
                  <Tooltip
                    formatter={(value) => `₹${value.toLocaleString('en-IN')}`}
                    contentStyle={{
                      backgroundColor: 'white',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                    }}
                  />
                  <Bar dataKey="amount" fill="#10b981" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      )}

      {/* AI Tips - Simplified */}
      {budget.tips && budget.tips.length > 0 && activeTab === 'overview' && (
        <Card className="border-slate-200 bg-amber-50/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-amber-800 flex items-center gap-2">
              <Lightbulb className="w-4 h-4" />
              {t('budget.aiPoweredTips')}
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="space-y-2">
              {budget.tips.slice(0, 3).map((tip, index) => (
                <div
                  key={index}
                  className="flex items-start gap-2 p-3 bg-white rounded-lg border border-amber-200"
                >
                  <CheckCircle className="w-4 h-4 text-amber-600 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-slate-700">{tip}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Regenerate Button */}
      <div className="flex justify-center pt-2">
        <Button
          onClick={generateBudget}
          disabled={generating}
          variant="outline"
          size="sm"
          className="text-slate-600"
        >
          {generating ? (
            <>
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              {t('budget.regenerating')}
            </>
          ) : (
            <>
              <RefreshCw className="w-4 h-4 mr-2" />
              {t('budget.regenerate')}
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
