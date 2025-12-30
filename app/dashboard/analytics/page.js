'use client'

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  BarChart3,
  TrendingUp,
  Target,
  Wallet,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
  PieChart,
  Calendar,
  Sparkles,
  Brain
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart as RechartsPie,
  Pie,
  Cell,
  AreaChart,
  Area,
  Legend
} from 'recharts'

// Skeleton Component
function AnalyticsSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {/* Stats Row Skeleton */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="h-3 w-20 bg-slate-200 rounded mb-2" />
            <div className="h-6 w-24 bg-slate-200 rounded" />
          </div>
        ))}
      </div>

      {/* Tabs Skeleton */}
      <div className="h-10 w-64 bg-slate-200 rounded-lg" />

      {/* Charts Skeleton */}
      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 p-4 h-80">
          <div className="h-4 w-32 bg-slate-200 rounded mb-4" />
          <div className="h-60 bg-slate-100 rounded" />
        </div>
        <div className="bg-white rounded-xl border border-slate-200 p-4 h-80">
          <div className="h-4 w-32 bg-slate-200 rounded mb-4" />
          <div className="h-60 bg-slate-100 rounded" />
        </div>
      </div>
    </div>
  )
}

// Category colors
const CATEGORY_COLORS = {
  food: '#10B981',
  transportation: '#3B82F6',
  housing: '#8B5CF6',
  entertainment: '#F59E0B',
  healthcare: '#EF4444',
  shopping: '#EC4899',
  utilities: '#06B6D4',
  other: '#6B7280'
}

function AnalyticsContent() {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [budget, setBudget] = useState(null)
  const [expenses, setExpenses] = useState([])
  const [goals, setGoals] = useState([])
  const [insights, setInsights] = useState([])
  const [activeTab, setActiveTab] = useState('overview')

  // Fetch data
  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [budgetRes, expensesRes, goalsRes, insightsRes] = await Promise.all([
        fetch('/api/budget/generate'),
        fetch('/api/expenses?limit=1000'),
        fetch('/api/goals'),
        fetch('/api/insights')
      ])

      const [budgetData, expensesData, goalsData, insightsData] = await Promise.all([
        budgetRes.json(),
        expensesRes.json(),
        goalsRes.json(),
        insightsRes.json()
      ])

      if (budgetData.success) setBudget(budgetData.budget)
      if (expensesData.success) setExpenses(expensesData.expenses || [])
      if (goalsData.success) setGoals(goalsData.goals || [])
      if (insightsData.success) setInsights(insightsData.insights || [])
    } catch (error) {
      console.error('Failed to fetch analytics data:', error)
    } finally {
      setLoading(false)
    }
  }

  // Calculate metrics
  const metrics = useMemo(() => {
    const currentMonth = new Date().toISOString().substring(0, 7)
    const lastMonth = new Date(new Date().setMonth(new Date().getMonth() - 1)).toISOString().substring(0, 7)

    const currentExpenses = expenses
      .filter(e => e.date?.startsWith(currentMonth))
      .reduce((sum, e) => sum + (e.amount || 0), 0)

    const lastExpenses = expenses
      .filter(e => e.date?.startsWith(lastMonth))
      .reduce((sum, e) => sum + (e.amount || 0), 0)

    const totalIncome = budget?.totalBudget || 0
    const savings = Math.max(0, totalIncome - currentExpenses)
    const savingsRate = totalIncome > 0 ? Math.round((savings / totalIncome) * 100) : 0

    const expenseChange = lastExpenses > 0
      ? Math.round(((currentExpenses - lastExpenses) / lastExpenses) * 100)
      : 0

    return {
      totalIncome,
      totalExpenses: currentExpenses,
      savings,
      savingsRate,
      expenseChange,
      activeGoals: goals.length,
      goalsOnTrack: goals.filter(g => (g.currentAmount / g.targetAmount) >= 0.5).length
    }
  }, [budget, expenses, goals])

  // Category data for pie chart
  const categoryData = useMemo(() => {
    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = expenses.filter(e => e.date?.startsWith(currentMonth))

    const grouped = monthExpenses.reduce((acc, e) => {
      const cat = e.category || 'other'
      acc[cat] = (acc[cat] || 0) + (e.amount || 0)
      return acc
    }, {})

    return Object.entries(grouped)
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: CATEGORY_COLORS[name] || CATEGORY_COLORS.other
      }))
      .sort((a, b) => b.value - a.value)
  }, [expenses])

  // Budget vs Actual data
  const budgetVsActualData = useMemo(() => {
    if (!budget?.categories) return []

    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = expenses.filter(e => e.date?.startsWith(currentMonth))

    return Object.entries(budget.categories)
      .filter(([_, data]) => data.amount > 0)
      .map(([category, data]) => {
        const spent = monthExpenses
          .filter(e => e.category === category)
          .reduce((sum, e) => sum + (e.amount || 0), 0)

        return {
          name: category.charAt(0).toUpperCase() + category.slice(1),
          budget: data.amount,
          spent
        }
      })
      .slice(0, 6)
  }, [budget, expenses])

  // Monthly trend data
  const trendData = useMemo(() => {
    const months = []
    for (let i = 5; i >= 0; i--) {
      const date = new Date()
      date.setMonth(date.getMonth() - i)
      const monthKey = date.toISOString().substring(0, 7)
      const monthName = date.toLocaleDateString('en-IN', { month: 'short' })

      const monthExpenses = expenses
        .filter(e => e.date?.startsWith(monthKey))
        .reduce((sum, e) => sum + (e.amount || 0), 0)

      const income = budget?.totalBudget || 0

      months.push({
        name: monthName,
        expenses: monthExpenses,
        savings: Math.max(0, income - monthExpenses)
      })
    }
    return months
  }, [expenses, budget])

  if (loading) {
    return (
      <DashboardLayout title={t('analytics.title')}>
        <AnalyticsSkeleton />
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title={t('analytics.title')}>
      <div className="space-y-4 max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-emerald-600" />
              {t('analytics.financialAnalytics')}
            </h2>
            <p className="text-sm text-slate-500">
              {t('analytics.insightsFor')} {new Date().toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchData} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            {t('analytics.refresh')}
          </Button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-50 rounded-lg">
                  <Wallet className="w-4 h-4 text-emerald-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t('analytics.monthlyIncome')}</p>
                  <p className="text-lg font-semibold text-slate-800">
                    ₹{metrics.totalIncome.toLocaleString('en-IN')}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-50 rounded-lg">
                  <ArrowDownRight className="w-4 h-4 text-blue-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t('analytics.totalExpenses')}</p>
                  <p className="text-lg font-semibold text-slate-800">
                    ₹{metrics.totalExpenses.toLocaleString('en-IN')}
                  </p>
                  {metrics.expenseChange !== 0 && (
                    <p className={`text-xs ${metrics.expenseChange > 0 ? 'text-red-500' : 'text-emerald-500'}`}>
                      {metrics.expenseChange > 0 ? '↑' : '↓'} {Math.abs(metrics.expenseChange)}%
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-50 rounded-lg">
                  <ArrowUpRight className="w-4 h-4 text-purple-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t('analytics.savings')}</p>
                  <p className="text-lg font-semibold text-slate-800">
                    ₹{metrics.savings.toLocaleString('en-IN')}
                  </p>
                  <p className="text-xs text-slate-400">{metrics.savingsRate}% {t('analytics.saved')}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-amber-50 rounded-lg">
                  <Target className="w-4 h-4 text-amber-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t('analytics.activeGoals')}</p>
                  <p className="text-lg font-semibold text-slate-800">{metrics.activeGoals}</p>
                  <p className="text-xs text-slate-400">{metrics.goalsOnTrack} {t('analytics.onTrack')}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="bg-slate-100 p-1">
            <TabsTrigger value="overview" className="gap-2 text-sm">
              <BarChart3 className="w-4 h-4" />
              {t('analytics.overview')}
            </TabsTrigger>
            <TabsTrigger value="spending" className="gap-2 text-sm">
              <PieChart className="w-4 h-4" />
              {t('analytics.spending')}
            </TabsTrigger>
            <TabsTrigger value="trends" className="gap-2 text-sm">
              <TrendingUp className="w-4 h-4" />
              {t('analytics.trends')}
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4 mt-4">
            <div className="grid md:grid-cols-2 gap-4">
              {/* Budget vs Actual */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-emerald-600" />
                    {t('analytics.budgetVsActual')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {budgetVsActualData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={budgetVsActualData} layout="vertical">
                        <XAxis type="number" tickFormatter={(v) => `₹${(v/1000).toFixed(0)}k`} fontSize={10} />
                        <YAxis type="category" dataKey="name" width={80} fontSize={10} />
                        <Tooltip
                          formatter={(value) => [`₹${value.toLocaleString('en-IN')}`, '']}
                          contentStyle={{ fontSize: 12 }}
                        />
                        <Bar dataKey="budget" fill="#10B981" name="Budget" radius={[0, 4, 4, 0]} />
                        <Bar dataKey="spent" fill="#3B82F6" name="Spent" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-60 flex items-center justify-center text-slate-400 text-sm">
                      {t('analytics.noData')}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Savings Progress */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <Target className="w-4 h-4 text-emerald-600" />
                    {t('analytics.savingsProgress')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-col items-center justify-center h-60">
                    {/* Circular Progress */}
                    <div className="relative w-36 h-36">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle
                          cx="72"
                          cy="72"
                          r="60"
                          stroke="#E2E8F0"
                          strokeWidth="12"
                          fill="none"
                        />
                        <circle
                          cx="72"
                          cy="72"
                          r="60"
                          stroke={metrics.savingsRate >= 100 ? '#10B981' : '#10B981'}
                          strokeWidth="12"
                          fill="none"
                          strokeDasharray={`${Math.min(metrics.savingsRate, 100) * 3.77} 377`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-2xl font-bold text-emerald-600">
                          {Math.min(metrics.savingsRate, 100)}%
                        </span>
                        <span className="text-xs text-slate-500">{t('analytics.ofTarget')}</span>
                      </div>
                    </div>

                    {metrics.savingsRate >= 100 && (
                      <div className="mt-3 flex items-center gap-1 text-emerald-600">
                        <Sparkles className="w-4 h-4" />
                        <span className="text-sm font-medium">{t('analytics.targetExceeded')}</span>
                      </div>
                    )}

                    <div className="mt-4 grid grid-cols-2 gap-6 text-center">
                      <div>
                        <p className="text-xs text-slate-500">{t('analytics.currentSavings')}</p>
                        <p className="text-lg font-semibold text-emerald-600">
                          ₹{metrics.savings.toLocaleString('en-IN')}
                        </p>
                        <p className="text-xs text-slate-400">{metrics.savingsRate}% {t('analytics.ofIncome')}</p>
                      </div>
                      <div>
                        <p className="text-xs text-slate-500">{t('analytics.targetSavings')}</p>
                        <p className="text-lg font-semibold text-slate-700">
                          ₹{Math.round(metrics.totalIncome * 0.15).toLocaleString('en-IN')}
                        </p>
                        <p className="text-xs text-slate-400">15% {t('analytics.ofIncome')}</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Monthly Trend */}
            <Card className="border-slate-200">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-emerald-600" />
                  {t('analytics.trends')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="colorExpenses" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorSavings" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10B981" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="name" fontSize={10} />
                    <YAxis tickFormatter={(v) => `₹${(v/1000).toFixed(0)}k`} fontSize={10} />
                    <Tooltip
                      formatter={(value) => [`₹${value.toLocaleString('en-IN')}`, '']}
                      contentStyle={{ fontSize: 12 }}
                    />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="expenses"
                      stroke="#3B82F6"
                      fillOpacity={1}
                      fill="url(#colorExpenses)"
                      name="Expenses"
                    />
                    <Area
                      type="monotone"
                      dataKey="savings"
                      stroke="#10B981"
                      fillOpacity={1}
                      fill="url(#colorSavings)"
                      name="Savings"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Spending Tab */}
          <TabsContent value="spending" className="space-y-4 mt-4">
            <div className="grid md:grid-cols-2 gap-4">
              {/* Category Pie */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <PieChart className="w-4 h-4 text-emerald-600" />
                    {t('analytics.spending')} by Category
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {categoryData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={280}>
                      <RechartsPie>
                        <Pie
                          data={categoryData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={100}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {categoryData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          formatter={(value) => [`₹${value.toLocaleString('en-IN')}`, '']}
                          contentStyle={{ fontSize: 12 }}
                        />
                      </RechartsPie>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-72 flex items-center justify-center text-slate-400 text-sm">
                      {t('analytics.noData')}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Category List */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-700">
                    Category Breakdown
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {categoryData.slice(0, 6).map((cat, i) => {
                      const total = categoryData.reduce((sum, c) => sum + c.value, 0)
                      const percent = total > 0 ? Math.round((cat.value / total) * 100) : 0

                      return (
                        <div key={i} className="flex items-center gap-3">
                          <div
                            className="w-3 h-3 rounded-full flex-shrink-0"
                            style={{ backgroundColor: cat.color }}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-slate-700 truncate">{cat.name}</span>
                              <span className="text-slate-500 ml-2">₹{cat.value.toLocaleString('en-IN')}</span>
                            </div>
                            <div className="mt-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{ width: `${percent}%`, backgroundColor: cat.color }}
                              />
                            </div>
                          </div>
                          <span className="text-xs text-slate-400 w-10 text-right">{percent}%</span>
                        </div>
                      )
                    })}
                    {categoryData.length === 0 && (
                      <p className="text-center text-slate-400 text-sm py-8">{t('analytics.noData')}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Trends Tab */}
          <TabsContent value="trends" className="space-y-4 mt-4">
            <Card className="border-slate-200">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                  <Calendar className="w-4 h-4 text-blue-600" />
                  {t('analytics.monthlySummary')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[0, 1, 2, 3, 4, 5].map((i) => {
                    const date = new Date()
                    date.setMonth(date.getMonth() - i)
                    const monthKey = date.toISOString().substring(0, 7)
                    const monthExpenses = expenses.filter(e => e.date?.startsWith(monthKey))
                    const total = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
                    const income = budget?.totalBudget || 0
                    const saved = income - total
                    const hasData = monthExpenses.length > 0

                    return (
                      <div key={monthKey} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                        <div>
                          <p className="font-medium text-slate-700 text-sm">
                            {date.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}
                          </p>
                          <p className="text-xs text-slate-400">
                            {hasData ? `${monthExpenses.length} ${t('analytics.transactions').toLowerCase()}` : t('analytics.noTransactions')}
                          </p>
                        </div>
                        <div className="text-right">
                          {hasData ? (
                            <>
                              <p className="font-semibold text-slate-700 text-sm">
                                ₹{total.toLocaleString('en-IN')}
                              </p>
                              <p className={`text-xs ${saved >= 0 ? 'text-emerald-600' : 'text-red-500'}`}>
                                {saved >= 0 ? '+' : ''}₹{saved.toLocaleString('en-IN')} saved
                              </p>
                            </>
                          ) : (
                            <p className="text-sm text-slate-400">{t('analytics.noData')}</p>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>

            {/* AI Insights */}
            <Card className="border-slate-200">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
                  <Brain className="w-4 h-4 text-purple-600" />
                  {t('analytics.aiPoweredInsights')}
                  {insights.length > 0 && (
                    <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">
                      {insights.length} {t('analytics.new')}
                    </span>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {insights.length > 0 ? (
                  <div className="space-y-3 max-h-80 overflow-y-auto">
                    {insights.slice(0, 6).map((insight, index) => (
                      <div
                        key={index}
                        className={`p-3 rounded-lg border ${
                          insight.type === 'warning'
                            ? 'bg-amber-50 border-amber-200'
                            : insight.type === 'success'
                            ? 'bg-emerald-50 border-emerald-200'
                            : 'bg-blue-50 border-blue-200'
                        }`}
                      >
                        <p className="text-sm text-slate-700">{insight.message}</p>
                        {insight.suggestion && (
                          <p className="text-xs text-slate-500 mt-1">{insight.suggestion}</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Sparkles className="w-10 h-10 text-slate-200 mx-auto mb-2" />
                    <p className="text-sm text-slate-400">{t('analytics.addMoreData')}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  )
}

export default function AnalyticsPage() {
  return (
    <OnboardingGuard>
      <AnalyticsContent />
    </OnboardingGuard>
  )
}
