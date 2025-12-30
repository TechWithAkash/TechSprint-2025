'use client'

import { useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Legend
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { BarChart3 } from 'lucide-react'

const COLORS = {
  budget: '#10B981', // emerald-500
  spent: '#3B82F6', // blue-500
  over: '#EF4444' // red-500
}

export default function BudgetVsActualChart({ budget, expenses, height = 300 }) {
  const chartData = useMemo(() => {
    if (!budget?.categories) return []

    // Get current month expenses grouped by category
    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = (expenses || []).filter(e => e.date?.startsWith(currentMonth))

    // Calculate spent per category
    const spentByCategory = monthExpenses.reduce((acc, expense) => {
      const category = expense.category || 'Other'
      acc[category] = (acc[category] || 0) + expense.amount
      return acc
    }, {})

    // Build chart data
    const categories = Object.entries(budget.categories)
    return categories
      .filter(([key]) => key !== 'savings') // Exclude savings from comparison
      .map(([key, cat]) => {
        const budgetAmount = cat.amount || 0
        const spentAmount = spentByCategory[cat.englishName] || 0
        const isOver = spentAmount > budgetAmount

        return {
          name: cat.englishName?.replace(' & ', '\n& ') || key,
          shortName: cat.englishName?.split(' ')[0] || key,
          emoji: cat.emoji || '',
          budget: budgetAmount,
          spent: spentAmount,
          remaining: Math.max(0, budgetAmount - spentAmount),
          percentage: budgetAmount > 0 ? Math.round((spentAmount / budgetAmount) * 100) : 0,
          isOver
        }
      })
      .sort((a, b) => b.percentage - a.percentage) // Sort by usage
  }, [budget, expenses])

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null

    const data = payload[0]?.payload
    return (
      <div className="bg-white p-3 rounded-lg shadow-lg border text-sm">
        <p className="font-semibold text-gray-900 mb-2">{data?.emoji} {label?.replace('\n', ' ')}</p>
        <div className="space-y-1">
          <p className="text-emerald-600">
            Budget: <span className="font-medium">₹{data?.budget?.toLocaleString('en-IN')}</span>
          </p>
          <p className={data?.isOver ? 'text-red-600' : 'text-blue-600'}>
            Spent: <span className="font-medium">₹{data?.spent?.toLocaleString('en-IN')}</span>
          </p>
          <p className={`font-medium ${data?.isOver ? 'text-red-600' : 'text-emerald-600'}`}>
            {data?.isOver ? `Over by ₹${(data?.spent - data?.budget).toLocaleString('en-IN')}` :
              `${data?.percentage}% used`}
          </p>
        </div>
      </div>
    )
  }

  if (!chartData.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <BarChart3 className="w-5 h-5 text-emerald-600" />
            Budget vs Actual
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-48 text-gray-500">
            No budget data available
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-lg">
          <BarChart3 className="w-5 h-5 text-emerald-600" />
          Budget vs Actual Spending
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={height}>
          <BarChart
            data={chartData}
            margin={{ top: 10, right: 10, left: 0, bottom: 5 }}
            barGap={2}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" vertical={false} />
            <XAxis
              dataKey="shortName"
              tick={{ fontSize: 11, fill: '#6B7280' }}
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
            <Bar
              dataKey="budget"
              name="Budget"
              fill={COLORS.budget}
              radius={[4, 4, 0, 0]}
              maxBarSize={40}
            />
            <Bar
              dataKey="spent"
              name="Spent"
              radius={[4, 4, 0, 0]}
              maxBarSize={40}
            >
              {chartData.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.isOver ? COLORS.over : COLORS.spent}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>

        {/* Quick Stats */}
        <div className="mt-4 grid grid-cols-3 gap-3 pt-4 border-t">
          <div className="text-center">
            <p className="text-xs text-gray-500">On Track</p>
            <p className="text-lg font-bold text-emerald-600">
              {chartData.filter(d => d.percentage <= 100).length}
            </p>
          </div>
          <div className="text-center border-x">
            <p className="text-xs text-gray-500">Warning</p>
            <p className="text-lg font-bold text-amber-600">
              {chartData.filter(d => d.percentage > 80 && d.percentage <= 100).length}
            </p>
          </div>
          <div className="text-center">
            <p className="text-xs text-gray-500">Over Budget</p>
            <p className="text-lg font-bold text-red-600">
              {chartData.filter(d => d.isOver).length}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
