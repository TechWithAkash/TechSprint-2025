'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import {
  Users,
  TrendingUp,
  Calculator,
  Target,
  CheckCircle2,
  AlertCircle,
  ChevronRight,
  Briefcase,
  PiggyBank,
  Shield,
  Wallet,
  ArrowUpRight,
  ArrowDownRight,
  Sparkles,
  BookOpen,
  Trophy,
  Clock,
  RefreshCw
} from 'lucide-react'
import toast from 'react-hot-toast'

const TABS = [
  { id: 'peer', label: 'Peer Insights', icon: Users },
  { id: 'tax', label: 'Tax Optimization', icon: Calculator },
  { id: 'recommendations', label: 'Recommendations', icon: Target },
  { id: 'action', label: 'Action Plan', icon: CheckCircle2 }
]

export default function IncomeRecommendations({ compact = false }) {
  const [activeTab, setActiveTab] = useState('peer')
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchRecommendations()
  }, [])

  const fetchRecommendations = async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch('/api/recommendations/income')
      const result = await response.json()

      if (result.success) {
        setData(result)
      } else {
        setError(result.error || 'Failed to load recommendations')
      }
    } catch (err) {
      console.error('Fetch recommendations error:', err)
      setError('Failed to load recommendations')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="py-12">
          <div className="flex flex-col items-center justify-center space-y-4">
            <RefreshCw className="h-8 w-8 animate-spin text-emerald-600" />
            <p className="text-slate-600">Loading personalized recommendations...</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="py-12">
          <div className="flex flex-col items-center justify-center space-y-4">
            <AlertCircle className="h-8 w-8 text-red-500" />
            <p className="text-slate-600">{error}</p>
            <Button onClick={fetchRecommendations} variant="outline">
              Try Again
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (!data?.incomeReport) {
    return (
      <Card>
        <CardContent className="py-12">
          <div className="flex flex-col items-center justify-center space-y-4">
            <Wallet className="h-8 w-8 text-slate-400" />
            <p className="text-slate-600">Complete your profile to get personalized recommendations</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (compact) {
    return <CompactView data={data} />
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-emerald-600" />
          Income-Based Insights
        </CardTitle>
        <CardDescription>
          Personalized recommendations based on your {data.incomeReport?.summary?.incomeBracket || 'income bracket'}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 border-b pb-4">
          {TABS.map((tab) => {
            const Icon = tab.icon
            return (
              <Button
                key={tab.id}
                variant={activeTab === tab.id ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setActiveTab(tab.id)}
                className="flex items-center gap-2"
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{tab.label}</span>
              </Button>
            )
          })}
        </div>

        {/* Tab Content */}
        <div className="min-h-[400px]">
          {activeTab === 'peer' && <PeerInsightsTab data={data} />}
          {activeTab === 'tax' && <TaxOptimizationTab data={data} />}
          {activeTab === 'recommendations' && <RecommendationsTab data={data} />}
          {activeTab === 'action' && <ActionPlanTab data={data} />}
        </div>
      </CardContent>
    </Card>
  )
}

// Compact view for dashboard widget
function CompactView({ data }) {
  const peer = data.peerInsights
  if (!peer) return null

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Users className="h-4 w-4 text-emerald-600" />
          How You Compare
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Savings Comparison */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-slate-600">Your savings rate</span>
            <span className="font-medium">{peer.userSavingsRate}%</span>
          </div>
          <Progress value={peer.userSavingsRate} max={peer.topPerformerRate} className="h-2" />
          <div className="flex justify-between text-xs text-slate-500">
            <span>Peer avg: {peer.peerAverageSavingsRate}%</span>
            <span>Top: {peer.topPerformerRate}%</span>
          </div>
        </div>

        {/* Percentile Badge */}
        <div className="flex items-center justify-between p-3 bg-emerald-50 rounded-lg">
          <div className="flex items-center gap-2">
            <Trophy className="h-5 w-5 text-emerald-600" />
            <span className="text-sm font-medium text-emerald-800">
              Top {100 - peer.percentile}%
            </span>
          </div>
          <span className="text-xs text-emerald-600">of your bracket</span>
        </div>

        {/* Quick Tip */}
        {peer.successStrategies?.[0] && (
          <div className="p-3 bg-slate-50 rounded-lg">
            <p className="text-xs text-slate-500 mb-1">Success Strategy</p>
            <p className="text-sm text-slate-700">{peer.successStrategies[0]}</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// Peer Insights Tab
function PeerInsightsTab({ data }) {
  const peer = data.peerInsights
  if (!peer) return <p className="text-slate-500">No peer data available</p>

  const getComparisonColor = (comparison) => {
    switch (comparison) {
      case 'top_performer': return 'text-emerald-600 bg-emerald-50'
      case 'above_average': return 'text-blue-600 bg-blue-50'
      case 'on_track': return 'text-amber-600 bg-amber-50'
      default: return 'text-red-600 bg-red-50'
    }
  }

  const getComparisonIcon = (comparison) => {
    switch (comparison) {
      case 'top_performer': return <Trophy className="h-5 w-5" />
      case 'above_average': return <ArrowUpRight className="h-5 w-5" />
      case 'on_track': return <TrendingUp className="h-5 w-5" />
      default: return <ArrowDownRight className="h-5 w-5" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Comparison Badge */}
      <div className={`p-4 rounded-lg flex items-center gap-4 ${getComparisonColor(peer.savingsComparison)}`}>
        {getComparisonIcon(peer.savingsComparison)}
        <div>
          <p className="font-medium">{peer.comparisonMessage}</p>
          <p className="text-sm opacity-80">
            You're in the top {100 - peer.percentile}% of savers in your income bracket
          </p>
        </div>
      </div>

      {/* Savings Comparison Chart */}
      <div className="space-y-4">
        <h4 className="font-medium text-slate-800">Savings Rate Comparison</h4>

        {/* Your Rate */}
        <div className="space-y-1">
          <div className="flex justify-between text-sm">
            <span>Your Rate</span>
            <span className="font-medium">{peer.userSavingsRate}%</span>
          </div>
          <Progress value={peer.userSavingsRate} max={50} className="h-3 bg-slate-200" />
        </div>

        {/* Peer Average */}
        <div className="space-y-1">
          <div className="flex justify-between text-sm">
            <span>Peer Average</span>
            <span className="font-medium text-slate-600">{peer.peerAverageSavingsRate}%</span>
          </div>
          <Progress value={peer.peerAverageSavingsRate} max={50} className="h-3 bg-slate-200" />
        </div>

        {/* Top Performer */}
        <div className="space-y-1">
          <div className="flex justify-between text-sm">
            <span>Top Performers</span>
            <span className="font-medium text-emerald-600">{peer.topPerformerRate}%</span>
          </div>
          <Progress value={peer.topPerformerRate} max={50} className="h-3 bg-slate-200" />
        </div>
      </div>

      {/* Common Goals */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <Target className="h-4 w-4 text-emerald-600" />
            Common Goals
          </h4>
          <ul className="space-y-2">
            {peer.commonGoals?.map((goal, i) => (
              <li key={i} className="flex items-center gap-2 text-sm text-slate-600">
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                {goal}
              </li>
            ))}
          </ul>
        </div>

        <div className="space-y-3">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-amber-600" />
            Common Challenges
          </h4>
          <ul className="space-y-2">
            {peer.commonChallenges?.map((challenge, i) => (
              <li key={i} className="flex items-center gap-2 text-sm text-slate-600">
                <AlertCircle className="h-4 w-4 text-amber-500" />
                {challenge}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Success Strategies */}
      <div className="space-y-3">
        <h4 className="font-medium text-slate-800 flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-purple-600" />
          Success Strategies from Top Performers
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {peer.successStrategies?.map((strategy, i) => (
            <div key={i} className="p-3 bg-purple-50 rounded-lg text-sm text-purple-800">
              {strategy}
            </div>
          ))}
        </div>
      </div>

      {/* Investment Allocation */}
      <div className="space-y-3">
        <h4 className="font-medium text-slate-800 flex items-center gap-2">
          <PiggyBank className="h-4 w-4 text-blue-600" />
          Recommended Investment Allocation
        </h4>
        <div className="flex flex-wrap gap-3">
          {Object.entries(peer.investmentAllocation || {}).map(([asset, percentage]) => (
            <div key={asset} className="px-4 py-2 bg-slate-100 rounded-lg">
              <p className="text-xs text-slate-500 capitalize">{asset}</p>
              <p className="font-medium text-slate-800">{percentage}%</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// Tax Optimization Tab
function TaxOptimizationTab({ data }) {
  const tax = data.taxRecommendations
  if (!tax) return <p className="text-slate-500">No tax data available</p>

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="p-4 bg-emerald-50 rounded-lg">
        <div className="flex items-center gap-3 mb-2">
          <Calculator className="h-6 w-6 text-emerald-600" />
          <div>
            <p className="font-medium text-emerald-800">Potential Tax Savings</p>
            <p className="text-2xl font-bold text-emerald-700">
              Rs. {tax.potentialSavings?.toLocaleString('en-IN')}
            </p>
          </div>
        </div>
        <p className="text-sm text-emerald-700">{tax.summary}</p>
      </div>

      {/* Tax Bracket Info */}
      <div className="p-4 bg-slate-50 rounded-lg">
        <p className="text-sm text-slate-500 mb-1">Your Tax Bracket</p>
        <p className="font-medium text-slate-800">{tax.taxBracket}</p>
      </div>

      {/* Regime Comparison */}
      {tax.regimeComparison && (
        <div className="space-y-3">
          <h4 className="font-medium text-slate-800">Old vs New Tax Regime</h4>
          <div className="grid grid-cols-2 gap-4">
            <div className={`p-4 rounded-lg border-2 ${tax.regimeComparison.betterRegime === 'old' ? 'border-emerald-500 bg-emerald-50' : 'border-slate-200'}`}>
              <p className="text-sm text-slate-500">Old Regime Tax</p>
              <p className="text-xl font-bold text-slate-800">
                Rs. {Math.round(tax.regimeComparison.oldRegimeTax).toLocaleString('en-IN')}
              </p>
              {tax.regimeComparison.betterRegime === 'old' && (
                <span className="text-xs text-emerald-600 font-medium">Recommended</span>
              )}
            </div>
            <div className={`p-4 rounded-lg border-2 ${tax.regimeComparison.betterRegime === 'new' ? 'border-emerald-500 bg-emerald-50' : 'border-slate-200'}`}>
              <p className="text-sm text-slate-500">New Regime Tax</p>
              <p className="text-xl font-bold text-slate-800">
                Rs. {Math.round(tax.regimeComparison.newRegimeTax).toLocaleString('en-IN')}
              </p>
              {tax.regimeComparison.betterRegime === 'new' && (
                <span className="text-xs text-emerald-600 font-medium">Recommended</span>
              )}
            </div>
          </div>
          <p className="text-sm text-slate-600">{tax.regimeComparison.recommendation}</p>
        </div>
      )}

      {/* Tax Saving Options */}
      <div className="space-y-4">
        <h4 className="font-medium text-slate-800">Tax Saving Investments</h4>

        {tax.recommendations?.map((rec, i) => (
          <div key={i} className="border rounded-lg overflow-hidden">
            <div className="p-4 bg-slate-50 flex justify-between items-center">
              <div>
                <p className="font-medium text-slate-800">{rec.title}</p>
                <p className="text-sm text-slate-500">Section {rec.section}</p>
              </div>
              <div className="text-right">
                <p className="text-sm text-slate-500">Limit</p>
                <p className="font-medium text-slate-800">Rs. {rec.limit.toLocaleString('en-IN')}</p>
              </div>
            </div>
            <div className="p-4 space-y-3">
              {rec.options?.map((opt, j) => (
                <div key={j} className="flex justify-between items-start p-3 bg-slate-50 rounded-lg">
                  <div>
                    <p className="font-medium text-slate-700">{opt.name}</p>
                    <p className="text-sm text-slate-500">{opt.benefit}</p>
                    {opt.lockIn && (
                      <p className="text-xs text-slate-400 mt-1">Lock-in: {opt.lockIn}</p>
                    )}
                  </div>
                  {opt.expectedReturn && (
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Returns</p>
                      <p className="text-sm font-medium text-emerald-600">{opt.expectedReturn}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Quick Tips */}
      {tax.tips && (
        <div className="space-y-3">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-blue-600" />
            Quick Tax Tips
          </h4>
          <ul className="space-y-2">
            {tax.tips.map((tip, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                <ChevronRight className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
                {tip}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// Recommendations Tab
function RecommendationsTab({ data }) {
  const recs = data.incomeRecommendations
  if (!recs) return <p className="text-slate-500">No recommendations available</p>

  return (
    <div className="space-y-6">
      {/* Income Profile Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-50 rounded-lg">
          <p className="text-xs text-slate-500">Income Bracket</p>
          <p className="font-medium text-slate-800 capitalize">{recs.profile}</p>
        </div>
        <div className="p-4 bg-slate-50 rounded-lg">
          <p className="text-xs text-slate-500">Income Stability</p>
          <p className="font-medium text-slate-800">{recs.stabilityRatio}%</p>
        </div>
        <div className="p-4 bg-slate-50 rounded-lg">
          <p className="text-xs text-slate-500">Savings Target</p>
          <p className="font-medium text-slate-800">{recs.savingsTarget}%</p>
        </div>
        <div className="p-4 bg-slate-50 rounded-lg">
          <p className="text-xs text-slate-500">Emergency Fund</p>
          <p className="font-medium text-slate-800">{recs.emergencyFundMonths} months</p>
        </div>
      </div>

      {/* Risk Advice */}
      {recs.riskAdvice && (
        <div className="p-4 bg-blue-50 rounded-lg flex items-start gap-3">
          <Shield className="h-5 w-5 text-blue-600 mt-0.5" />
          <div>
            <p className="font-medium text-blue-800">Investment Risk Guidance</p>
            <p className="text-sm text-blue-700">{recs.riskAdvice}</p>
          </div>
        </div>
      )}

      {/* Recommendations List */}
      <div className="space-y-3">
        <h4 className="font-medium text-slate-800">Personalized Recommendations</h4>
        <div className="space-y-2">
          {recs.recommendations?.map((rec, i) => (
            <div key={i} className="p-4 border rounded-lg hover:bg-slate-50 transition-colors">
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center text-sm font-medium flex-shrink-0">
                  {i + 1}
                </div>
                <p className="text-slate-700">{rec}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Investment Allocation */}
      {recs.investmentAllocation && (
        <div className="space-y-3">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <PiggyBank className="h-4 w-4 text-emerald-600" />
            Suggested Asset Allocation
          </h4>
          <div className="flex flex-wrap gap-3">
            {Object.entries(recs.investmentAllocation).map(([asset, percentage]) => (
              <div key={asset} className="flex-1 min-w-[100px] p-4 bg-gradient-to-br from-emerald-50 to-teal-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-emerald-700">{percentage}%</p>
                <p className="text-sm text-slate-600 capitalize">{asset}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Action Plan Tab
function ActionPlanTab({ data }) {
  const plan = data.incomeReport?.actionPlan
  if (!plan) return <p className="text-slate-500">No action plan available</p>

  return (
    <div className="space-y-6">
      <div className="p-4 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-lg">
        <h4 className="font-medium text-emerald-800 flex items-center gap-2">
          <Clock className="h-5 w-5" />
          4-Week Financial Action Plan
        </h4>
        <p className="text-sm text-emerald-700 mt-1">
          Follow this step-by-step plan to optimize your finances
        </p>
      </div>

      <div className="space-y-4">
        {plan.map((week, i) => (
          <div key={i} className="border rounded-lg overflow-hidden">
            <div className="p-4 bg-slate-50 flex justify-between items-center">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold">
                  W{week.week}
                </div>
                <div>
                  <p className="font-medium text-slate-800">{week.title}</p>
                  <p className="text-xs text-slate-500">Time needed: {week.timeRequired}</p>
                </div>
              </div>
              {week.potentialSavings && (
                <span className="text-sm text-emerald-600 font-medium">
                  Saves {week.potentialSavings}
                </span>
              )}
            </div>
            <div className="p-4">
              <ul className="space-y-2">
                {week.actions?.map((action, j) => (
                  <li key={j} className="flex items-start gap-2 text-sm text-slate-600">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                    {action}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Call to Action */}
      <div className="p-4 bg-slate-100 rounded-lg text-center">
        <p className="text-slate-600 mb-3">Ready to take control of your finances?</p>
        <Button className="bg-emerald-600 hover:bg-emerald-700">
          <Target className="h-4 w-4 mr-2" />
          Start Week 1 Now
        </Button>
      </div>
    </div>
  )
}
