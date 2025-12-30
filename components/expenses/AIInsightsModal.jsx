'use client'

import { useState, useEffect, useRef } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Sparkles,
  Download,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  PiggyBank,
  AlertTriangle,
  Lightbulb,
  BarChart3,
  Calendar,
  Wallet,
  Target,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Clock,
  Zap
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function AIInsightsModal({ isOpen, onClose }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [report, setReport] = useState(null)
  const [activeTab, setActiveTab] = useState('patterns')
  const [exportingPDF, setExportingPDF] = useState(false)
  const contentRef = useRef(null)

  useEffect(() => {
    if (isOpen && !report) {
      fetchInsights()
    }
  }, [isOpen])

  const fetchInsights = async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/expenses/insights')
      const data = await response.json()

      if (data.success) {
        setReport(data.report)
        if (!data.report) {
          setError(data.message || 'No data available')
        }
      } else {
        setError(data.error || 'Failed to generate insights')
      }
    } catch (err) {
      console.error('Insights fetch error:', err)
      setError('Failed to connect to insights service')
    } finally {
      setLoading(false)
    }
  }

  const handleExportPDF = async () => {
    if (!report) return

    setExportingPDF(true)
    try {
      const { generateInsightsPDF } = await import('./insights/InsightsPDFGenerator')
      await generateInsightsPDF(report)
      toast.success('PDF downloaded successfully!')
    } catch (err) {
      console.error('PDF export error:', err)
      toast.error('Failed to export PDF')
    } finally {
      setExportingPDF(false)
    }
  }

  const handleClose = () => {
    setActiveTab('patterns')
    onClose()
  }

  const tabs = [
    { id: 'patterns', label: 'Spending', icon: BarChart3, color: 'blue' },
    { id: 'savings', label: 'Savings', icon: PiggyBank, color: 'emerald' },
    { id: 'predictions', label: 'Forecast', icon: TrendingUp, color: 'amber' },
    { id: 'recommendations', label: 'Tips', icon: Lightbulb, color: 'purple' }
  ]

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader className="flex-shrink-0">
          <div className="flex items-center gap-2">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Sparkles className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <DialogTitle className="text-xl">AI Financial Insights</DialogTitle>
              <DialogDescription>
                {report?.generatedAt
                  ? `Generated on ${new Date(report.generatedAt).toLocaleDateString('en-IN', {
                      weekday: 'long',
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric'
                    })}`
                  : 'Analyzing your expenses...'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        {/* Content Area */}
        <div className="flex-1 overflow-hidden flex flex-col" ref={contentRef}>
          {loading && <LoadingState />}
          {error && !loading && <ErrorState error={error} onRetry={fetchInsights} />}
          {!loading && !error && report && (
            <>
              {/* Summary Cards */}
              <SummaryCards summary={report.summary} predictions={report.predictions} />

              {/* Tabs */}
              <div className="flex gap-1 p-1 bg-slate-100 rounded-lg mb-4 flex-shrink-0">
                {tabs.map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                      activeTab === tab.id
                        ? `bg-white shadow-sm text-${tab.color}-700`
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <tab.icon className="w-4 h-4" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div className="flex-1 overflow-y-auto pr-2">
                {activeTab === 'patterns' && (
                  <SpendingPatternsSection data={report.spendingPatterns} />
                )}
                {activeTab === 'savings' && (
                  <SavingsOpportunitiesSection data={report.savingsOpportunities} />
                )}
                {activeTab === 'predictions' && (
                  <PredictionsSection data={report.predictions} summary={report.summary} />
                )}
                {activeTab === 'recommendations' && (
                  <RecommendationsSection data={report.recommendations} />
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {!loading && !error && report && (
          <div className="flex items-center justify-between pt-4 border-t flex-shrink-0">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              {report.aiGenerated ? (
                <>
                  <Sparkles className="w-3 h-3 text-purple-500" />
                  <span>AI-powered analysis</span>
                </>
              ) : (
                <>
                  <Zap className="w-3 h-3 text-amber-500" />
                  <span>Rule-based analysis</span>
                </>
              )}
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={fetchInsights}
                disabled={loading}
              >
                <RefreshCw className={`w-4 h-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={handleExportPDF}
                disabled={exportingPDF}
                className="bg-purple-600 hover:bg-purple-700"
              >
                <Download className={`w-4 h-4 mr-1 ${exportingPDF ? 'animate-pulse' : ''}`} />
                {exportingPDF ? 'Exporting...' : 'Download PDF'}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

// Loading State
function LoadingState() {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="flex flex-col items-center gap-4">
        <div className="relative">
          <Sparkles className="w-12 h-12 text-purple-600 animate-pulse" />
          <div className="absolute inset-0 w-12 h-12 border-4 border-purple-200 border-t-purple-600 rounded-full animate-spin" />
        </div>
        <div className="text-center">
          <p className="text-lg font-medium text-slate-900">Analyzing Your Finances</p>
          <p className="text-sm text-slate-500 mt-1">Our AI is generating personalized insights...</p>
        </div>
      </div>
    </div>
  )
}

// Error State
function ErrorState({ error, onRetry }) {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="text-center">
        <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-3" />
        <p className="text-slate-700 font-medium mb-2">Unable to Generate Insights</p>
        <p className="text-sm text-slate-500 mb-4">{error}</p>
        <Button variant="outline" onClick={onRetry}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Try Again
        </Button>
      </div>
    </div>
  )
}

// Summary Cards
function SummaryCards({ summary, predictions }) {
  const cards = [
    {
      label: 'Total Spent',
      value: `₹${summary.totalSpent?.toLocaleString('en-IN') || 0}`,
      icon: Wallet,
      color: 'emerald',
      subtext: `${summary.transactionCount || 0} transactions`
    },
    {
      label: 'Savings Rate',
      value: `${summary.savingsRate || 0}%`,
      icon: PiggyBank,
      color: summary.savingsRate >= 20 ? 'blue' : 'amber',
      subtext: summary.savingsRate >= 20 ? 'On track!' : 'Below 20% target'
    },
    {
      label: 'Daily Average',
      value: `₹${summary.dailyAverage?.toLocaleString('en-IN') || 0}`,
      icon: Calendar,
      color: 'purple',
      subtext: 'per day this month'
    },
    {
      label: 'Month Forecast',
      value: `₹${predictions?.monthEndForecast?.toLocaleString('en-IN') || 0}`,
      icon: predictions?.willExceedBudget ? AlertTriangle : Target,
      color: predictions?.willExceedBudget ? 'red' : 'emerald',
      subtext: predictions?.willExceedBudget ? 'May exceed budget' : 'Within budget'
    }
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4 flex-shrink-0">
      {cards.map((card, idx) => (
        <Card key={idx} className={`bg-gradient-to-br from-${card.color}-50 to-${card.color}-100 border-${card.color}-200`}>
          <CardContent className="p-3">
            <div className="flex items-center gap-2 mb-1">
              <card.icon className={`w-4 h-4 text-${card.color}-600`} />
              <span className={`text-xs font-medium text-${card.color}-600`}>{card.label}</span>
            </div>
            <p className={`text-xl font-bold text-${card.color}-700`}>{card.value}</p>
            <p className="text-xs text-slate-500 mt-0.5">{card.subtext}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// Spending Patterns Section
function SpendingPatternsSection({ data }) {
  if (!data) return null

  return (
    <div className="space-y-4">
      {/* Category Breakdown */}
      <Card>
        <CardContent className="p-4">
          <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-blue-600" />
            Category Breakdown
          </h3>
          <div className="space-y-3">
            {data.categoryBreakdown?.slice(0, 6).map((cat, idx) => (
              <div key={idx}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-700">{cat.category}</span>
                  <span className="font-medium">₹{cat.amount?.toLocaleString('en-IN')} ({cat.percentage}%)</span>
                </div>
                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${cat.percentage}%`,
                      backgroundColor: cat.color || '#6B7280'
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Peak Spending Days */}
      <Card>
        <CardContent className="p-4">
          <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
            <Calendar className="w-4 h-4 text-blue-600" />
            Peak Spending Days
          </h3>
          <div className="grid grid-cols-3 gap-2">
            {data.peakDays?.map((day, idx) => (
              <div key={idx} className={`p-3 rounded-lg ${idx === 0 ? 'bg-blue-50 border border-blue-200' : 'bg-slate-50'}`}>
                <p className={`text-sm font-medium ${idx === 0 ? 'text-blue-700' : 'text-slate-700'}`}>
                  {day.day}
                </p>
                <p className={`text-lg font-bold ${idx === 0 ? 'text-blue-600' : 'text-slate-600'}`}>
                  ₹{day.total?.toLocaleString('en-IN')}
                </p>
                <p className="text-xs text-slate-500">{day.count} transactions</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Top Merchants */}
      {data.topMerchants?.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <Target className="w-4 h-4 text-blue-600" />
              Top Spending Areas
            </h3>
            <div className="space-y-2">
              {data.topMerchants.map((merchant, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 bg-slate-50 rounded-lg">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 flex items-center justify-center bg-blue-100 text-blue-700 text-xs font-bold rounded-full">
                      {idx + 1}
                    </span>
                    <span className="text-sm text-slate-700 truncate max-w-[150px]">{merchant.name}</span>
                  </div>
                  <div className="text-right">
                    <span className="font-medium text-slate-800">₹{merchant.total?.toLocaleString('en-IN')}</span>
                    <span className="text-xs text-slate-500 ml-1">({merchant.count}x)</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// Savings Opportunities Section
function SavingsOpportunitiesSection({ data }) {
  if (!data) return null

  return (
    <div className="space-y-4">
      {/* Potential Savings Banner */}
      <Card className="bg-gradient-to-r from-emerald-500 to-teal-500 text-white">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-emerald-100 text-sm">Potential Monthly Savings</p>
              <p className="text-3xl font-bold">₹{data.potentialSavings?.toLocaleString('en-IN') || 0}</p>
            </div>
            <PiggyBank className="w-12 h-12 text-emerald-200" />
          </div>
        </CardContent>
      </Card>

      {/* Budget Comparisons */}
      <Card>
        <CardContent className="p-4">
          <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-emerald-600" />
            Budget vs Actual
          </h3>
          <div className="space-y-3">
            {data.budgetComparisons?.slice(0, 6).map((item, idx) => (
              <div key={idx} className="p-3 bg-slate-50 rounded-lg">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-sm font-medium text-slate-700">
                    {item.emoji} {item.category}
                  </span>
                  <Badge variant={item.status === 'over' ? 'destructive' : item.status === 'warning' ? 'warning' : 'success'}>
                    {item.usagePercent}%
                  </Badge>
                </div>
                <div className="flex justify-between text-xs text-slate-500 mb-1">
                  <span>Spent: ₹{item.spent?.toLocaleString('en-IN')}</span>
                  <span>Budget: ₹{item.budgeted?.toLocaleString('en-IN')}</span>
                </div>
                <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      item.status === 'over' ? 'bg-red-500' :
                      item.status === 'warning' ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(item.usagePercent, 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Areas to Reduce */}
      {data.areasToReduce?.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-emerald-600" />
              Areas to Reduce
            </h3>
            <div className="space-y-2">
              {data.areasToReduce.map((area, idx) => (
                <div key={idx} className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-medium text-amber-800">
                      {area.emoji} {area.category}
                    </span>
                    <span className="text-sm text-red-600 font-medium">
                      +₹{area.overBy?.toLocaleString('en-IN')} over
                    </span>
                  </div>
                  <p className="text-sm text-amber-700">{area.tip}</p>
                  <p className="text-xs text-emerald-600 mt-1 font-medium">
                    Potential saving: ₹{area.suggestedReduction?.toLocaleString('en-IN')}/month
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Suggestions */}
      {data.suggestions?.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-emerald-600" />
              Quick Tips
            </h3>
            <ul className="space-y-2">
              {data.suggestions.map((tip, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm text-slate-600">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                  <span>{tip}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// Predictions Section
function PredictionsSection({ data, summary }) {
  if (!data) return null

  return (
    <div className="space-y-4">
      {/* Month End Forecast */}
      <Card className={`${data.willExceedBudget ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'}`}>
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-slate-800 flex items-center gap-2">
              <Target className={`w-4 h-4 ${data.willExceedBudget ? 'text-red-600' : 'text-emerald-600'}`} />
              Month-End Forecast
            </h3>
            <Badge variant={data.willExceedBudget ? 'destructive' : 'success'}>
              {data.confidence} confidence
            </Badge>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-slate-500">Projected Spend</p>
              <p className={`text-2xl font-bold ${data.willExceedBudget ? 'text-red-600' : 'text-emerald-600'}`}>
                ₹{data.monthEndForecast?.toLocaleString('en-IN')}
              </p>
            </div>
            <div>
              <p className="text-sm text-slate-500">Budget</p>
              <p className="text-2xl font-bold text-slate-700">
                ₹{summary.totalBudget?.toLocaleString('en-IN')}
              </p>
            </div>
          </div>

          {data.willExceedBudget && (
            <div className="mt-3 p-2 bg-red-100 rounded-lg flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600" />
              <span className="text-sm text-red-700">
                May exceed budget by ₹{data.exceedBy?.toLocaleString('en-IN')}
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Budget Breach Warnings */}
      {data.warnings?.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-600" />
              Category Warnings
            </h3>
            <div className="space-y-2">
              {data.warnings.map((warning, idx) => (
                <div key={idx} className={`p-3 rounded-lg ${
                  warning.severity === 'high' ? 'bg-red-50 border border-red-200' : 'bg-amber-50 border border-amber-200'
                }`}>
                  <div className="flex justify-between items-center">
                    <span className="font-medium text-slate-700">
                      {warning.emoji} {warning.category}
                    </span>
                    <Badge variant={warning.severity === 'high' ? 'destructive' : 'warning'}>
                      {warning.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-slate-600 mt-1">
                    Projected: ₹{warning.projectedSpend?.toLocaleString('en-IN')}
                    <span className="text-red-600 ml-1">
                      (+₹{warning.projectedOverage?.toLocaleString('en-IN')} over)
                    </span>
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Anomalies */}
      {data.anomalies?.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-600" />
              Unusual Expenses Detected
            </h3>
            <div className="space-y-2">
              {data.anomalies.map((anomaly, idx) => (
                <div key={idx} className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
                  <div className="flex justify-between items-center">
                    <span className="font-medium text-slate-700">{anomaly.description}</span>
                    <span className="font-bold text-amber-700">₹{anomaly.amount?.toLocaleString('en-IN')}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">{anomaly.reason}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// Recommendations Section
function RecommendationsSection({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="text-center py-8">
        <Lightbulb className="w-12 h-12 text-slate-300 mx-auto mb-3" />
        <p className="text-slate-500">No recommendations available yet</p>
      </div>
    )
  }

  const priorityColors = {
    high: 'red',
    medium: 'amber',
    low: 'blue'
  }

  const categoryIcons = {
    spending: Wallet,
    saving: PiggyBank,
    budgeting: Target,
    lifestyle: Lightbulb
  }

  return (
    <div className="space-y-3">
      {data.map((rec, idx) => {
        const Icon = categoryIcons[rec.category] || Lightbulb
        const color = priorityColors[rec.priority] || 'blue'

        return (
          <Card key={idx} className="overflow-hidden">
            <CardContent className="p-0">
              <div className={`h-1 bg-${color}-500`} />
              <div className="p-4">
                <div className="flex items-start gap-3">
                  <div className={`p-2 bg-${color}-100 rounded-lg flex-shrink-0`}>
                    <Icon className={`w-5 h-5 text-${color}-600`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold text-slate-800">{rec.title}</h4>
                      <Badge variant={rec.priority === 'high' ? 'destructive' : rec.priority === 'medium' ? 'warning' : 'secondary'} className="text-xs">
                        {rec.priority}
                      </Badge>
                    </div>
                    <p className="text-sm text-slate-600 mb-2">{rec.description}</p>
                    {rec.impact && (
                      <div className="flex items-center gap-1 text-xs text-emerald-600 font-medium">
                        <TrendingUp className="w-3 h-3" />
                        {rec.impact}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
