'use client'

import { useMemo } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { TrendingUp } from 'lucide-react'

export default function MonthlyTrendChart({ expenses, budget, months = 6, height = 280 }) {
  const chartData = useMemo(() => {
    const now = new Date()
    const monthlyData = []
    const budgetAmount = budget?.totalBudget || 0

    // Generate last N months
    for (let i = months - 1; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1)
      const monthKey = date.toISOString().substring(0, 7) // YYYY-MM
      const monthName = date.toLocaleDateString('en-IN', { month: 'short' })

      // Filter expenses for this month - using REAL expense data only
      const monthExpenses = (expenses || []).filter(e =>
        e.date?.startsWith(monthKey)
      )

      const totalSpent = monthExpenses.reduce((sum, e) => sum + (e.amount || 0), 0)

      // Only calculate savings if there's actual data (budget exists and month has transactions OR is current month)
      const isCurrentMonth = monthKey === now.toISOString().substring(0, 7)
      const hasData = monthExpenses.length > 0 || isCurrentMonth
      const savings = hasData && budgetAmount > 0 ? Math.max(0, budgetAmount - totalSpent) : 0

      monthlyData.push({
        month: monthName,
        fullMonth: date.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }),
        expenses: totalSpent,
        savings: hasData ? savings : null, // null for months with no data
        budget: budgetAmount,
        savingsRate: budgetAmount > 0 && hasData ? Math.round((savings / budgetAmount) * 100) : 0,
        hasData: hasData,
        transactionCount: monthExpenses.length
      })
    }

    return monthlyData
  }, [expenses, budget, months])

  // Check if we have any real data to display
  const hasAnyData = useMemo(() => {
    return chartData.some(d => d.expenses > 0 || d.transactionCount > 0)
  }, [chartData])

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null

    const data = payload[0]?.payload
    return (
      <div className="bg-white p-3 rounded-lg shadow-lg border text-sm">
        <p className="font-semibold text-gray-900 mb-2">{data?.fullMonth}</p>
        {data?.transactionCount > 0 ? (
          <div className="space-y-1">
            <p className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500"></span>
              <span className="text-gray-600">Expenses:</span>
              <span className="font-medium">₹{data?.expenses?.toLocaleString('en-IN')}</span>
            </p>
            <p className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
              <span className="text-gray-600">Savings:</span>
              <span className="font-medium">₹{(data?.savings || 0).toLocaleString('en-IN')}</span>
            </p>
            <p className="text-gray-500 text-xs mt-1">
              {data?.transactionCount} transactions • {data?.savingsRate}% saved
            </p>
          </div>
        ) : (
          <p className="text-gray-500 text-sm">No transactions recorded</p>
        )}
      </div>
    )
  }

  // Calculate trend
  const trend = useMemo(() => {
    if (chartData.length < 2) return { direction: 'stable', change: 0 }

    const current = chartData[chartData.length - 1]?.savings || 0
    const previous = chartData[chartData.length - 2]?.savings || 0

    if (previous === 0) return { direction: 'stable', change: 0 }

    const change = Math.round(((current - previous) / previous) * 100)
    return {
      direction: change > 0 ? 'up' : change < 0 ? 'down' : 'stable',
      change: Math.abs(change)
    }
  }, [chartData])

  // Show empty state if no data
  if (!hasAnyData) {
    return (
      <Card className="overflow-hidden">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-lg">
            <TrendingUp className="w-5 h-5 text-blue-600" />
            {months}-Month Trend
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <TrendingUp className="w-12 h-12 text-gray-300 mb-3" />
            <p className="text-gray-500 font-medium">No expense data yet</p>
            <p className="text-gray-400 text-sm mt-1">Start tracking expenses to see trends</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-lg">
            <TrendingUp className="w-5 h-5 text-blue-600" />
            {months}-Month Trend
          </CardTitle>
          {trend.change > 0 && hasAnyData && (
            <span className={`text-sm px-2 py-1 rounded-full ${
              trend.direction === 'up'
                ? 'bg-emerald-100 text-emerald-700'
                : trend.direction === 'down'
                ? 'bg-red-100 text-red-700'
                : 'bg-gray-100 text-gray-700'
            }`}>
              {trend.direction === 'up' ? '↑' : trend.direction === 'down' ? '↓' : '→'} {trend.change}%
            </span>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart
            data={chartData}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorExpenses" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#F43F5E" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorSavings" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" vertical={false} />
            <XAxis
              dataKey="month"
              tick={{ fontSize: 12, fill: '#6B7280' }}
              tickLine={false}
              axisLine={{ stroke: '#E5E7EB' }}
            />
            <YAxis
              tick={{ fontSize: 11, fill: '#6B7280' }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => `₹${(value / 1000).toFixed(0)}k`}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend
              wrapperStyle={{ paddingTop: 10 }}
              formatter={(value) => <span className="text-sm text-gray-600">{value}</span>}
            />
            <Area
              type="monotone"
              dataKey="expenses"
              name="Expenses"
              stroke="#F43F5E"
              strokeWidth={2}
              fill="url(#colorExpenses)"
            />
            <Area
              type="monotone"
              dataKey="savings"
              name="Savings"
              stroke="#10B981"
              strokeWidth={2}
              fill="url(#colorSavings)"
            />
          </AreaChart>
        </ResponsiveContainer>

        {/* Summary Stats - Only calculate from months with actual data */}
        {(() => {
          const monthsWithData = chartData.filter(d => d.transactionCount > 0)
          const monthCount = monthsWithData.length || 1
          const avgExpenses = Math.round(monthsWithData.reduce((sum, d) => sum + d.expenses, 0) / monthCount)
          const avgSavings = Math.round(monthsWithData.reduce((sum, d) => sum + (d.savings || 0), 0) / monthCount)

          return (
            <div className="mt-4 grid grid-cols-2 gap-4 pt-4 border-t">
              <div className="text-center">
                <p className="text-xs text-gray-500 mb-1">
                  Avg. Monthly Expenses
                  <span className="text-gray-400 ml-1">({monthCount} mo)</span>
                </p>
                <p className="text-lg font-bold text-rose-600">
                  ₹{avgExpenses.toLocaleString('en-IN')}
                </p>
              </div>
              <div className="text-center">
                <p className="text-xs text-gray-500 mb-1">
                  Avg. Monthly Savings
                  <span className="text-gray-400 ml-1">({monthCount} mo)</span>
                </p>
                <p className="text-lg font-bold text-emerald-600">
                  ₹{avgSavings.toLocaleString('en-IN')}
                </p>
              </div>
            </div>
          )
        })()}
      </CardContent>
    </Card>
  )
}
