'use client'

import { useMemo } from 'react'
import {
  RadialBarChart,
  RadialBar,
  ResponsiveContainer,
  PolarAngleAxis
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Target, TrendingUp, AlertTriangle, CheckCircle2, Sparkles } from 'lucide-react'

export default function SavingsProgressGauge({
  budget,
  expenses,
  goals,
  height = 280
}) {
  const savingsData = useMemo(() => {
    const totalBudget = budget?.totalBudget || 0
    const currentMonth = new Date().toISOString().substring(0, 7)

    // Calculate total spent this month
    const monthExpenses = (expenses || []).filter(e => e.date?.startsWith(currentMonth))
    const totalSpent = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)

    // Calculate savings
    const actualSavings = Math.max(0, totalBudget - totalSpent)
    const targetSavings = budget?.categories?.savings?.amount || totalBudget * 0.2

    // Calculate savings rate
    const savingsRate = totalBudget > 0 ? Math.round((actualSavings / totalBudget) * 100) : 0
    const targetRate = totalBudget > 0 ? Math.round((targetSavings / totalBudget) * 100) : 20
    const progressPercent = targetSavings > 0 ? Math.min(100, Math.round((actualSavings / targetSavings) * 100)) : 0

    // Calculate goals progress
    const goalsProgress = (goals || []).length > 0
      ? Math.round(goals.reduce((sum, g) => {
          return sum + Math.min(100, (g.currentAmount / g.targetAmount) * 100)
        }, 0) / goals.length)
      : 0

    return {
      actualSavings,
      targetSavings,
      savingsRate,
      targetRate,
      progressPercent,
      goalsProgress,
      totalBudget,
      totalSpent,
      isOnTrack: progressPercent >= 80,
      isExceeding: progressPercent >= 100
    }
  }, [budget, expenses, goals])

  // Gauge data for the radial chart
  const gaugeData = [
    {
      name: 'Savings',
      value: savingsData.progressPercent,
      fill: savingsData.isExceeding ? '#10B981' : savingsData.isOnTrack ? '#3B82F6' : '#F59E0B'
    }
  ]

  const getStatusIcon = () => {
    if (savingsData.isExceeding) return <Sparkles className="w-5 h-5 text-emerald-500" />
    if (savingsData.isOnTrack) return <CheckCircle2 className="w-5 h-5 text-blue-500" />
    return <AlertTriangle className="w-5 h-5 text-amber-500" />
  }

  const getStatusText = () => {
    if (savingsData.isExceeding) return 'Excellent! Target exceeded'
    if (savingsData.isOnTrack) return 'On track to meet target'
    return 'Needs attention'
  }

  const getStatusColor = () => {
    if (savingsData.isExceeding) return 'text-emerald-600 bg-emerald-50'
    if (savingsData.isOnTrack) return 'text-blue-600 bg-blue-50'
    return 'text-amber-600 bg-amber-50'
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Target className="w-5 h-5 text-emerald-600" />
          Savings Progress
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative">
          <ResponsiveContainer width="100%" height={height - 100}>
            <RadialBarChart
              cx="50%"
              cy="50%"
              innerRadius="60%"
              outerRadius="90%"
              barSize={20}
              data={gaugeData}
              startAngle={180}
              endAngle={0}
            >
              <PolarAngleAxis
                type="number"
                domain={[0, 100]}
                angleAxisId={0}
                tick={false}
              />
              <RadialBar
                background={{ fill: '#E5E7EB' }}
                clockWise
                dataKey="value"
                cornerRadius={10}
                fill={gaugeData[0].fill}
              />
            </RadialBarChart>
          </ResponsiveContainer>

          {/* Center content */}
          <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ top: '-20px' }}>
            <div className="text-4xl font-bold text-gray-900">
              {savingsData.progressPercent}%
            </div>
            <div className="text-sm text-gray-500">of target</div>
          </div>
        </div>

        {/* Status Badge */}
        <div className="flex justify-center -mt-4 mb-4">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium ${getStatusColor()}`}>
            {getStatusIcon()}
            {getStatusText()}
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 gap-4 pt-4 border-t">
          <div className="text-center">
            <p className="text-xs text-gray-500 mb-1">Current Savings</p>
            <p className="text-xl font-bold text-emerald-600">
              ₹{savingsData.actualSavings.toLocaleString('en-IN')}
            </p>
            <p className="text-xs text-gray-400">{savingsData.savingsRate}% of income</p>
          </div>
          <div className="text-center">
            <p className="text-xs text-gray-500 mb-1">Target Savings</p>
            <p className="text-xl font-bold text-gray-700">
              ₹{savingsData.targetSavings.toLocaleString('en-IN')}
            </p>
            <p className="text-xs text-gray-400">{savingsData.targetRate}% of income</p>
          </div>
        </div>

        {/* Goals Progress */}
        {(goals || []).length > 0 && (
          <div className="mt-4 pt-4 border-t">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">Goals Progress</span>
              <span className="text-sm font-bold text-purple-600">{savingsData.goalsProgress}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2.5">
              <div
                className="bg-gradient-to-r from-purple-500 to-pink-500 h-2.5 rounded-full transition-all duration-500"
                style={{ width: `${savingsData.goalsProgress}%` }}
              />
            </div>
            <p className="text-xs text-gray-500 mt-1">
              {goals.length} active goal{goals.length !== 1 ? 's' : ''}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
