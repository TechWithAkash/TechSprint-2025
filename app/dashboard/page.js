// app/dashboard/page.js
'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import LanguageSelector from '@/components/ui/LanguageSelector'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  TrendingUp,
  Wallet,
  Target,
  PiggyBank,
  Plus,
  Mic,
  BarChart3,
  DollarSign,
  AlertCircle,
  RefreshCw,
  Sparkles,
  CreditCard,
  Calculator,
  User,
  Settings,
  HelpCircle
} from 'lucide-react'
import toast from 'react-hot-toast'
import BudgetDisplay from '@/components/dashboard/BudgetDisplay'
import ExpenseEntryModal from '@/components/expenses/ExpenseEntryModal'
import { AgentDashboard } from '@/components/agents/AgentDashboard'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SeasonalPlanningWidget } from '@/components/seasonal'
import IncomeRecommendations from '@/components/budget/IncomeRecommendations'
import { FinancialInsightsWidget } from '@/components/insights'
import DailyPulseWidget from '@/components/retention/DailyPulseWidget'
import DailyTipCard from '@/components/retention/DailyTipCard'
import SmartNudgeToast from '@/components/retention/SmartNudgeToast'
import { Trophy } from 'lucide-react'

function DashboardContent() {
  const { data: session } = useSession()
  const router = useRouter()
  const { t } = useTranslation()
  const [showExpenseEntry, setShowExpenseEntry] = useState(false)
  const [loading, setLoading] = useState(true)
  const [budget, setBudget] = useState(null)
  const [expenses, setExpenses] = useState([])
  const [goals, setGoals] = useState([])
  const [monthlyData, setMonthlyData] = useState({
    totalIncome: 0,
    totalExpenses: 0,
    totalSaved: 0,
    savingsRate: 0
  })

  // Get dynamic greeting based on time
  const getGreeting = () => {
    const now = new Date()
    const hour = now.getHours()
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    let timeGreeting = ''
    if (hour < 12) timeGreeting = 'Good morning'
    else if (hour < 17) timeGreeting = 'Good afternoon'
    else timeGreeting = 'Good evening'

    const dateStr = `${dayNames[now.getDay()]}, ${monthNames[now.getMonth()]} ${now.getDate()}`

    return {
      greeting: timeGreeting,
      date: dateStr
    }
  }

  const greetingData = getGreeting()

  // Fetch all user data
  useEffect(() => {
    fetchAllData()
  }, [])

  const fetchAllData = async () => {
    setLoading(true)
    try {
      // Fetch budget, expenses, and goals in parallel
      const [budgetResponse, expensesResponse, goalsResponse] = await Promise.all([
        fetch('/api/budget/generate'),
        fetch('/api/expenses?limit=10'),
        fetch('/api/goals')
      ])

      const budgetData = await budgetResponse.json()
      const expensesData = await expensesResponse.json()
      const goalsData = await goalsResponse.json()

      // Set budget data
      if (budgetData.success && budgetData.budget) {
        setBudget(budgetData.budget)
      }

      // Set expenses data
      if (expensesData.success) {
        setExpenses(expensesData.expenses || [])

        // Calculate monthly financial data
        const currentMonth = new Date().toISOString().substring(0, 7)
        const currentMonthExpenses = expensesData.expenses?.filter(expense =>
          expense.date?.substring(0, 7) === currentMonth
        ) || []

        const totalExpenses = currentMonthExpenses.reduce((sum, expense) => sum + expense.amount, 0)
        const totalIncome = budgetData.budget?.totalBudget || 0
        const totalSaved = totalIncome - totalExpenses
        const savingsRate = totalIncome > 0 ? Math.round((totalSaved / totalIncome) * 100) : 0

        setMonthlyData({
          totalIncome,
          totalExpenses,
          totalSaved,
          savingsRate: Math.max(0, savingsRate)
        })
      }

      // Set goals data
      if (goalsData.success) {
        setGoals(goalsData.goals || [])
      }

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
      toast.error('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  // Handle expense added
  const handleExpenseAdded = (expense) => {
    console.log('Expense added:', expense)
    toast.success('Expense added successfully!')
    setExpenses(prev => [expense, ...prev].slice(0, 10)) // Keep only latest 10
    setShowExpenseEntry(false)
    // Refresh monthly data
    fetchAllData()
  }

  // Quick action handlers
  const handleVoiceEntry = () => {
    setShowExpenseEntry(true)
  }

  const handleAddExpense = () => {
    router.push('/dashboard/expenses?mode=manual')
  }

  const handleViewBudget = () => {
    router.push('/dashboard/budget')
  }

  const handleViewGoals = () => {
    router.push('/dashboard/goals')
  }

  // Calculate financial health score based on real data
  const getFinancialHealthScore = () => {
    if (!budget || !monthlyData.totalIncome) return 50

    let score = 0

    // Savings rate (40% of score)
    const savingsRate = monthlyData.savingsRate
    if (savingsRate >= 30) score += 40
    else if (savingsRate >= 20) score += 30
    else if (savingsRate >= 10) score += 20
    else score += 10

    // Budget adherence (30% of score)
    if (budget.healthScore) {
      score += Math.round((budget.healthScore / 100) * 30)
    } else {
      score += 20 // Default if no health score
    }

    // Goal progress (30% of score)
    if (goals.length > 0) {
      const avgProgress = goals.reduce((sum, goal) => {
        const progress = Math.min((goal.currentAmount / goal.targetAmount) * 100, 100)
        return sum + progress
      }, 0) / goals.length
      score += Math.round((avgProgress / 100) * 30)
    } else {
      score += 15 // Partial score if no goals set
    }

    return Math.min(Math.max(score, 0), 100)
  }

  const financialHealthScore = getFinancialHealthScore()

  if (loading) {
    return (
      <DashboardLayout title="Dashboard Overview">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <RefreshCw className="h-8 w-8 animate-spin text-emerald-600 mx-auto mb-2" />
            <p className="text-slate-600">{t('common.loadingFinancialData')}</p>
          </div>
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title={t('dashboard.overview')}>
      <div className="space-y-6">

        {/* Compact Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h1 className="text-lg font-semibold text-slate-800">
              {greetingData.greeting}, {session?.user?.name?.split(' ')[0] || 'Friend'}
            </h1>
            <p className="text-sm text-slate-500">{greetingData.date}</p>
          </div>

          {/* Quick Stats Pills */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className={`px-3 py-1.5 rounded-full text-sm font-medium ${
              financialHealthScore >= 75 ? 'bg-emerald-100 text-emerald-700' :
              financialHealthScore >= 50 ? 'bg-blue-100 text-blue-700' :
              'bg-amber-100 text-amber-700'
            }`}>
              <span className="hidden sm:inline">Health: </span>{financialHealthScore}/100
            </div>
            {monthlyData.totalIncome > 0 && (
              <>
                <div className="px-3 py-1.5 rounded-full bg-slate-100 text-slate-700 text-sm font-medium">
                  {monthlyData.savingsRate}% saved
                </div>
                <div className="px-3 py-1.5 rounded-full bg-purple-100 text-purple-700 text-sm font-medium">
                  {goals.filter(g => g.status === 'active').length} goals
                </div>
              </>
            )}
          </div>
        </div>

        {/* Primary Action Row - 4 Column Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Financial Summary Card */}
          <div className="col-span-2 lg:col-span-1 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl p-4 text-white">
            <div className="flex items-center justify-between mb-3">
              <span className="text-emerald-100 text-sm font-medium">This Month</span>
              <Wallet className="w-5 h-5 text-emerald-200" />
            </div>
            {monthlyData.totalIncome > 0 ? (
              <>
                <div className="text-2xl font-bold mb-1">
                  ₹{monthlyData.totalSaved > 0 ? monthlyData.totalSaved.toLocaleString('en-IN') : '0'}
                </div>
                <div className="text-emerald-100 text-sm">saved of ₹{monthlyData.totalIncome.toLocaleString('en-IN')}</div>
                <div className="mt-3 bg-white/20 rounded-full h-2">
                  <div
                    className="bg-white rounded-full h-2 transition-all"
                    style={{ width: `${Math.min(monthlyData.savingsRate, 100)}%` }}
                  />
                </div>
              </>
            ) : (
              <div className="text-emerald-100">
                <p className="text-sm mb-2">No budget set up yet</p>
                <Button
                  onClick={() => router.push('/dashboard/budget')}
                  size="sm"
                  variant="secondary"
                  className="bg-white/20 hover:bg-white/30 text-white border-0"
                >
                  Set Up Budget
                </Button>
              </div>
            )}
          </div>

          {/* Quick Add Expense */}
          <button
            onClick={() => setShowExpenseEntry(true)}
            className="bg-white border-2 border-dashed border-slate-200 hover:border-emerald-400 hover:bg-emerald-50 rounded-xl p-4 transition-all group text-left"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-emerald-100 group-hover:bg-emerald-200 flex items-center justify-center transition-colors">
                <Mic className="w-5 h-5 text-emerald-600" />
              </div>
              <div>
                <div className="font-semibold text-slate-800">Quick Add</div>
                <div className="text-xs text-slate-500">Voice or manual</div>
              </div>
            </div>
            <div className="text-xs text-slate-400 group-hover:text-emerald-600 transition-colors">
              + Add expense
            </div>
          </button>

          {/* Budget Status */}
          <button
            onClick={handleViewBudget}
            className="bg-white border border-slate-200 hover:border-violet-400 hover:shadow-sm rounded-xl p-4 transition-all text-left"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-violet-100 flex items-center justify-center">
                <BarChart3 className="w-5 h-5 text-violet-600" />
              </div>
              <div>
                <div className="font-semibold text-slate-800">Budget</div>
                <div className="text-xs text-slate-500">
                  {budget ? `${Math.round((monthlyData.totalExpenses / budget.totalBudget) * 100)}% used` : 'Not set'}
                </div>
              </div>
            </div>
            <div className="text-xs text-violet-600 font-medium">View details →</div>
          </button>

          {/* Goals Status */}
          <button
            onClick={handleViewGoals}
            className="bg-white border border-slate-200 hover:border-purple-400 hover:shadow-sm rounded-xl p-4 transition-all text-left"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center">
                <Target className="w-5 h-5 text-purple-600" />
              </div>
              <div>
                <div className="font-semibold text-slate-800">Goals</div>
                <div className="text-xs text-slate-500">
                  {goals.length > 0 ? `${goals.filter(g => g.status === 'completed').length}/${goals.length} complete` : 'None set'}
                </div>
              </div>
            </div>
            <div className="text-xs text-purple-600 font-medium">Track progress →</div>
          </button>
        </div>

        {/* Daily Engagement Row - Balanced 2 Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Today's Pulse Widget */}
          <DailyPulseWidget
            onQuickAdd={() => setShowExpenseEntry(true)}
          />

          {/* Recent Activity Card - Expanded */}
          <Card className="border-slate-200">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <CreditCard className="w-4 h-4 text-slate-500" />
                  Recent Activity
                </CardTitle>
                <button
                  onClick={() => router.push('/dashboard/expenses')}
                  className="text-xs text-emerald-600 font-medium hover:underline"
                >
                  View all →
                </button>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              {expenses.length > 0 ? (
                <div className="space-y-2">
                  {expenses.slice(0, 5).map((expense) => (
                    <div key={expense.id} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-base">
                          {expense.category === 'Food & Dining' ? '🍕' :
                            expense.category === 'Transportation' ? '🚗' :
                            expense.category === 'Shopping' ? '🛒' :
                            expense.category === 'Healthcare' ? '🏥' :
                            expense.category === 'Entertainment' ? '🎬' :
                            expense.category === 'Home & Utilities' ? '🏠' : '💰'}
                        </div>
                        <div>
                          <p className="text-sm font-medium text-slate-800 truncate max-w-[180px]">
                            {expense.description || expense.merchant || expense.category}
                          </p>
                          <p className="text-xs text-slate-500">
                            {new Date(expense.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })}
                          </p>
                        </div>
                      </div>
                      <span className="text-sm font-semibold text-red-600">
                        -₹{expense.amount.toLocaleString('en-IN')}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6">
                  <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-3">
                    <CreditCard className="w-6 h-6 text-slate-400" />
                  </div>
                  <p className="text-sm text-slate-600 mb-1">No transactions yet</p>
                  <p className="text-xs text-slate-500 mb-3">Start tracking your expenses</p>
                  <Button onClick={() => setShowExpenseEntry(true)} size="sm" className="bg-emerald-600 hover:bg-emerald-700">
                    Add First Expense
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Daily Tip - Full Width Banner */}
        <DailyTipCard className="w-full" />

        {/* Main Dashboard Tabs */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="bg-slate-100 p-1 rounded-lg">
            <TabsTrigger value="overview" className="flex items-center gap-2 rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm">
              <BarChart3 className="h-4 w-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="ai-agents" className="flex items-center gap-2 rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm">
              <Sparkles className="h-4 w-4" />
              <span>AI Agents</span>
              <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded">
                BETA
              </span>
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4 mt-0">
            {/* Two Column Layout - AI Insights & Spending */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* AI-Powered Financial Insights */}
              <FinancialInsightsWidget compact={true} />

              {/* Budget Spending Overview */}
              <Card className="border-slate-200">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-blue-600" />
                      Budget Overview
                    </span>
                    <button
                      onClick={handleViewBudget}
                      className="text-xs text-emerald-600 hover:underline font-medium"
                    >
                      View all →
                    </button>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  {budget && budget.categories ? (
                    <div className="space-y-3">
                      {Object.entries(budget.categories)
                        .sort(([, a], [, b]) => b.amount - a.amount)
                        .slice(0, 4)
                        .map(([key, category]) => {
                          const categoryExpenses = expenses.filter(e => e.category === category.englishName)
                          const actualSpent = categoryExpenses.reduce((sum, e) => sum + e.amount, 0)
                          const budgetAmount = category.amount
                          const spentPercentage = budgetAmount > 0 ? Math.min((actualSpent / budgetAmount) * 100, 100) : 0

                          return (
                            <div key={key}>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium text-slate-700">{category.englishName}</span>
                                <span className="text-xs text-slate-500">
                                  ₹{actualSpent.toLocaleString('en-IN')} / ₹{budgetAmount.toLocaleString('en-IN')}
                                </span>
                              </div>
                              <div className="w-full bg-slate-100 rounded-full h-1.5">
                                <div
                                  className={`h-1.5 rounded-full transition-all ${
                                    spentPercentage > 90 ? 'bg-red-500' :
                                    spentPercentage > 70 ? 'bg-amber-500' :
                                    'bg-emerald-500'
                                  }`}
                                  style={{ width: `${Math.min(spentPercentage, 100)}%` }}
                                />
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  ) : (
                    <div className="text-center py-6">
                      <BarChart3 className="h-8 w-8 text-slate-300 mx-auto mb-2" />
                      <p className="text-sm text-slate-500 mb-2">No budget data</p>
                      <Button onClick={handleViewBudget} size="sm" variant="outline">
                        Create Budget
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Seasonal & Income Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SeasonalPlanningWidget
                compact={true}
                onViewAll={() => router.push('/dashboard/budget#seasonal')}
              />
              <IncomeRecommendations compact={true} />
            </div>

            {/* Goals Section */}
            <Card className="border-slate-200">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Target className="w-4 h-4 text-purple-600" />
                    Savings Goals
                  </span>
                  <button
                    onClick={handleViewGoals}
                    className="text-xs text-emerald-600 hover:underline font-medium"
                  >
                    Manage goals →
                  </button>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                {goals.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {goals.slice(0, 4).map((goal) => {
                      const progress = Math.min((goal.currentAmount / goal.targetAmount) * 100, 100)
                      const isCompleted = goal.status === 'completed' || progress >= 100

                      return (
                        <div
                          key={goal.id}
                          className={`p-3 rounded-lg border ${
                            isCompleted ? 'bg-emerald-50 border-emerald-200' :
                            progress > 50 ? 'bg-blue-50 border-blue-200' :
                            'bg-slate-50 border-slate-200'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-slate-800 truncate">{goal.name}</span>
                            {isCompleted && <span className="text-emerald-500">✓</span>}
                          </div>
                          <div className="w-full bg-white rounded-full h-1.5 mb-1">
                            <div
                              className={`h-1.5 rounded-full ${
                                isCompleted ? 'bg-emerald-500' :
                                progress > 50 ? 'bg-blue-500' :
                                'bg-slate-400'
                              }`}
                              style={{ width: `${Math.min(progress, 100)}%` }}
                            />
                          </div>
                          <div className="flex justify-between text-xs text-slate-500">
                            <span>₹{(goal.currentAmount / 1000).toFixed(0)}k</span>
                            <span>{progress.toFixed(0)}%</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <Target className="h-8 w-8 text-slate-300 mx-auto mb-2" />
                    <p className="text-sm text-slate-500 mb-2">No goals set yet</p>
                    <Button onClick={handleViewGoals} size="sm" className="bg-purple-600 hover:bg-purple-700">
                      Create First Goal
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Quick Actions - Compact Grid */}
            <Card className="border-slate-200">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  <button
                    onClick={handleAddExpense}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-emerald-100 group-hover:bg-emerald-200 flex items-center justify-center mb-1 transition-colors">
                      <Plus className="w-5 h-5 text-emerald-600" />
                    </div>
                    <span className="text-xs text-slate-600">Add</span>
                  </button>

                  <button
                    onClick={() => router.push('/dashboard/debt')}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-red-100 group-hover:bg-red-200 flex items-center justify-center mb-1 transition-colors">
                      <CreditCard className="w-5 h-5 text-red-600" />
                    </div>
                    <span className="text-xs text-slate-600">Debt</span>
                  </button>

                  <button
                    onClick={() => router.push('/dashboard/debt-calculator')}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-amber-100 group-hover:bg-amber-200 flex items-center justify-center mb-1 transition-colors">
                      <Calculator className="w-5 h-5 text-amber-600" />
                    </div>
                    <span className="text-xs text-slate-600">Calculator</span>
                  </button>

                  <button
                    onClick={() => router.push('/dashboard/profile')}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-indigo-100 group-hover:bg-indigo-200 flex items-center justify-center mb-1 transition-colors">
                      <User className="w-5 h-5 text-indigo-600" />
                    </div>
                    <span className="text-xs text-slate-600">Profile</span>
                  </button>

                  <button
                    onClick={() => router.push('/dashboard/settings')}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-slate-100 group-hover:bg-slate-200 flex items-center justify-center mb-1 transition-colors">
                      <Settings className="w-5 h-5 text-slate-600" />
                    </div>
                    <span className="text-xs text-slate-600">Settings</span>
                  </button>

                  <button
                    onClick={() => router.push('/dashboard/help')}
                    className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                  >
                    <div className="w-10 h-10 rounded-lg bg-green-100 group-hover:bg-green-200 flex items-center justify-center mb-1 transition-colors">
                      <HelpCircle className="w-5 h-5 text-green-600" />
                    </div>
                    <span className="text-xs text-slate-600">Help</span>
                  </button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* AI Agents Tab */}
          <TabsContent value="ai-agents" className="space-y-6">
            <AgentDashboard />
          </TabsContent>
        </Tabs>
      </div>

      {/* Expense Entry Modal */}
      <ExpenseEntryModal
        isOpen={showExpenseEntry}
        onClose={() => setShowExpenseEntry(false)}
        onExpenseAdded={handleExpenseAdded}
      />

      {/* Smart Nudge Toasts */}
      <SmartNudgeToast />
    </DashboardLayout>
  )
}

export default function DashboardPage() {
  return (
    <OnboardingGuard>
      <DashboardContent />
    </OnboardingGuard>
  )
}
