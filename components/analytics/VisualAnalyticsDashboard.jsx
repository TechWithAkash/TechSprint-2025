'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  BarChart3,
  PieChart,
  TrendingUp,
  Target,
  Wallet,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
  Sparkles,
  Calendar
} from 'lucide-react'

import MetricCard from './widgets/MetricCard'
import BudgetVsActualChart from './charts/BudgetVsActualChart'
import MonthlyTrendChart from './charts/MonthlyTrendChart'
import CategoryPieChart from './charts/CategoryPieChart'
import SavingsProgressGauge from './charts/SavingsProgressGauge'

export default function VisualAnalyticsDashboard({ compact = false }) {
  const [loading, setLoading] = useState(true)
  const [budget, setBudget] = useState(null)
  const [expenses, setExpenses] = useState([])
  const [goals, setGoals] = useState([])
  const [activeTab, setActiveTab] = useState('overview')

  // Fetch data
  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      // Fetch all data without limits for comprehensive analytics
      const [budgetRes, expensesRes, goalsRes] = await Promise.all([
        fetch('/api/budget/generate'),
        fetch('/api/expenses?limit=1000'), // Get all expenses for historical trend analysis
        fetch('/api/goals')
      ])

      const [budgetData, expensesData, goalsData] = await Promise.all([
        budgetRes.json(),
        expensesRes.json(),
        goalsRes.json()
      ])

      if (budgetData.success) setBudget(budgetData.budget)
      if (expensesData.success) setExpenses(expensesData.expenses || [])
      if (goalsData.success) setGoals(goalsData.goals || [])
    } catch (error) {
      console.error('Failed to fetch analytics data:', error)
    } finally {
      setLoading(false)
    }
  }

  // Calculate key metrics
  const metrics = {
    totalIncome: budget?.totalBudget || 0,
    totalExpenses: (() => {
      const currentMonth = new Date().toISOString().substring(0, 7)
      return expenses
        .filter(e => e.date?.startsWith(currentMonth))
        .reduce((sum, e) => sum + (e.amount || 0), 0)
    })(),
    get savings() { return Math.max(0, this.totalIncome - this.totalExpenses) },
    get savingsRate() { return this.totalIncome > 0 ? Math.round((this.savings / this.totalIncome) * 100) : 0 },
    expenseCount: expenses.filter(e => e.date?.startsWith(new Date().toISOString().substring(0, 7))).length,
    activeGoals: goals.length,
    goalsOnTrack: goals.filter(g => (g.currentAmount / g.targetAmount) >= 0.5).length
  }

  // Calculate month-over-month changes
  const getMonthChange = () => {
    const now = new Date()
    const currentMonth = now.toISOString().substring(0, 7)
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().substring(0, 7)

    const currentExpenses = expenses.filter(e => e.date?.startsWith(currentMonth)).reduce((sum, e) => sum + e.amount, 0)
    const lastExpenses = expenses.filter(e => e.date?.startsWith(lastMonth)).reduce((sum, e) => sum + e.amount, 0)

    if (lastExpenses === 0) return { trend: 'stable', value: '0%' }
    const change = Math.round(((currentExpenses - lastExpenses) / lastExpenses) * 100)
    return {
      trend: change > 0 ? 'up' : change < 0 ? 'down' : 'stable',
      value: `${Math.abs(change)}%`
    }
  }

  const expenseChange = getMonthChange()

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <RefreshCw className="w-8 h-8 animate-spin text-emerald-600" />
        </CardContent>
      </Card>
    )
  }

  // Compact view for dashboard
  if (compact) {
    return (
      <Card className="overflow-hidden">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-emerald-600" />
              Quick Analytics
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={fetchData}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center p-3 bg-emerald-50 rounded-xl">
              <p className="text-xs text-gray-500">Savings Rate</p>
              <p className="text-2xl font-bold text-emerald-600">{metrics.savingsRate}%</p>
            </div>
            <div className="text-center p-3 bg-blue-50 rounded-xl">
              <p className="text-xs text-gray-500">This Month</p>
              <p className="text-2xl font-bold text-blue-600">₹{(metrics.totalExpenses / 1000).toFixed(0)}k</p>
            </div>
            <div className="text-center p-3 bg-purple-50 rounded-xl">
              <p className="text-xs text-gray-500">Transactions</p>
              <p className="text-2xl font-bold text-purple-600">{metrics.expenseCount}</p>
            </div>
            <div className="text-center p-3 bg-amber-50 rounded-xl">
              <p className="text-xs text-gray-500">Goals Active</p>
              <p className="text-2xl font-bold text-amber-600">{metrics.activeGoals}</p>
            </div>
          </div>

          {/* Mini Chart Preview */}
          <div className="h-40">
            <MonthlyTrendChart expenses={expenses} budget={budget} months={3} height={140} />
          </div>
        </CardContent>
      </Card>
    )
  }

  // Full analytics view
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <BarChart3 className="w-7 h-7 text-emerald-600" />
            Financial Analytics
          </h2>
          <p className="text-gray-600 mt-1">
            Insights for {new Date().toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}
          </p>
        </div>
        <Button variant="outline" onClick={fetchData} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Key Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Monthly Income"
          value={`₹${metrics.totalIncome.toLocaleString('en-IN')}`}
          icon={Wallet}
          color="emerald"
        />
        <MetricCard
          title="Total Expenses"
          value={`₹${metrics.totalExpenses.toLocaleString('en-IN')}`}
          icon={ArrowDownRight}
          color="blue"
          trend={expenseChange.trend}
          trendValue={expenseChange.value}
        />
        <MetricCard
          title="Savings"
          value={`₹${metrics.savings.toLocaleString('en-IN')}`}
          subtitle={`${metrics.savingsRate}% saved`}
          icon={ArrowUpRight}
          color="purple"
        />
        <MetricCard
          title="Active Goals"
          value={metrics.activeGoals}
          subtitle={`${metrics.goalsOnTrack} on track`}
          icon={Target}
          color="amber"
        />
      </div>

      {/* Tabs for different views */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3 lg:w-auto lg:inline-grid">
          <TabsTrigger value="overview" className="gap-2">
            <BarChart3 className="w-4 h-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="spending" className="gap-2">
            <PieChart className="w-4 h-4" />
            Spending
          </TabsTrigger>
          <TabsTrigger value="trends" className="gap-2">
            <TrendingUp className="w-4 h-4" />
            Trends
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <BudgetVsActualChart budget={budget} expenses={expenses} height={300} />
            <SavingsProgressGauge budget={budget} expenses={expenses} goals={goals} height={280} />
          </div>
          <MonthlyTrendChart expenses={expenses} budget={budget} months={6} height={280} />
        </TabsContent>

        {/* Spending Tab */}
        <TabsContent value="spending" className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <CategoryPieChart expenses={expenses} height={350} />
            <BudgetVsActualChart budget={budget} expenses={expenses} height={350} />
          </div>
        </TabsContent>

        {/* Trends Tab */}
        <TabsContent value="trends" className="space-y-4">
          <MonthlyTrendChart expenses={expenses} budget={budget} months={6} height={350} />
          <div className="grid md:grid-cols-2 gap-4">
            <SavingsProgressGauge budget={budget} expenses={expenses} goals={goals} height={300} />
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Calendar className="w-5 h-5 text-blue-600" />
                  Monthly Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[0, 1, 2].map((i) => {
                    const date = new Date()
                    date.setMonth(date.getMonth() - i)
                    const monthKey = date.toISOString().substring(0, 7)
                    const monthExpenses = expenses.filter(e => e.date?.startsWith(monthKey))
                    const total = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)
                    const income = budget?.totalBudget || 0
                    const saved = income - total
                    const hasData = monthExpenses.length > 0

                    return (
                      <div key={monthKey} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div>
                          <p className="font-medium text-gray-900">
                            {date.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}
                          </p>
                          <p className="text-xs text-gray-500">
                            {hasData ? `${monthExpenses.length} transactions` : 'No transactions'}
                          </p>
                        </div>
                        <div className="text-right">
                          {hasData ? (
                            <>
                              <p className="font-bold text-gray-900">
                                ₹{total.toLocaleString('en-IN')}
                              </p>
                              <p className={`text-xs ${saved >= 0 ? 'text-emerald-600' : 'text-red-600'}`}>
                                {saved >= 0 ? '+' : ''}₹{saved.toLocaleString('en-IN')} saved
                              </p>
                            </>
                          ) : (
                            <p className="text-sm text-gray-400">No data</p>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
