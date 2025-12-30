'use client'

import { useMemo, useState } from 'react'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  Sector
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PieChart as PieChartIcon } from 'lucide-react'

const COLORS = [
  '#10B981', // emerald
  '#3B82F6', // blue
  '#8B5CF6', // purple
  '#F59E0B', // amber
  '#EF4444', // red
  '#EC4899', // pink
  '#06B6D4', // cyan
  '#6366F1'  // indigo
]

const renderActiveShape = (props) => {
  const {
    cx, cy, innerRadius, outerRadius, startAngle, endAngle,
    fill, payload, percent
  } = props

  return (
    <g>
      <text x={cx} y={cy - 10} textAnchor="middle" fill="#1F2937" className="text-lg font-bold">
        {payload.emoji} {payload.name}
      </text>
      <text x={cx} y={cy + 15} textAnchor="middle" fill="#6B7280" className="text-sm">
        ₹{payload.value.toLocaleString('en-IN')}
      </text>
      <text x={cx} y={cy + 35} textAnchor="middle" fill="#9CA3AF" className="text-xs">
        {(percent * 100).toFixed(1)}%
      </text>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 8}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
      />
      <Sector
        cx={cx}
        cy={cy}
        startAngle={startAngle}
        endAngle={endAngle}
        innerRadius={outerRadius + 12}
        outerRadius={outerRadius + 16}
        fill={fill}
      />
    </g>
  )
}

export default function CategoryPieChart({ expenses, height = 320 }) {
  const [activeIndex, setActiveIndex] = useState(0)

  const chartData = useMemo(() => {
    if (!expenses?.length) return []

    // Get current month expenses
    const currentMonth = new Date().toISOString().substring(0, 7)
    const monthExpenses = expenses.filter(e => e.date?.startsWith(currentMonth))

    // Group by category
    const categoryTotals = monthExpenses.reduce((acc, expense) => {
      const category = expense.category || 'Other'
      if (!acc[category]) {
        acc[category] = { total: 0, count: 0 }
      }
      acc[category].total += expense.amount || 0
      acc[category].count += 1
      return acc
    }, {})

    // Convert to array and add metadata
    const categoryEmojis = {
      'Food & Dining': '🍽️',
      'Transportation': '🚗',
      'Entertainment': '🎬',
      'Shopping': '🛍️',
      'Healthcare': '💊',
      'Home & Utilities': '🏠',
      'Savings': '💰',
      'Other': '💳'
    }

    return Object.entries(categoryTotals)
      .map(([name, data], index) => ({
        name,
        value: data.total,
        count: data.count,
        emoji: categoryEmojis[name] || '💳',
        color: COLORS[index % COLORS.length]
      }))
      .filter(item => item.value > 0)
      .sort((a, b) => b.value - a.value)
  }, [expenses])

  const totalSpent = useMemo(() => {
    return chartData.reduce((sum, item) => sum + item.value, 0)
  }, [chartData])

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null

    const data = payload[0]?.payload
    const percentage = totalSpent > 0 ? ((data.value / totalSpent) * 100).toFixed(1) : 0

    return (
      <div className="bg-white p-3 rounded-lg shadow-lg border text-sm">
        <p className="font-semibold text-gray-900 mb-1">
          {data.emoji} {data.name}
        </p>
        <p className="text-gray-600">
          Amount: <span className="font-medium text-gray-900">₹{data.value.toLocaleString('en-IN')}</span>
        </p>
        <p className="text-gray-600">
          Share: <span className="font-medium text-gray-900">{percentage}%</span>
        </p>
        <p className="text-gray-500 text-xs mt-1">
          {data.count} transaction{data.count !== 1 ? 's' : ''}
        </p>
      </div>
    )
  }

  if (!chartData.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <PieChartIcon className="w-5 h-5 text-purple-600" />
            Spending by Category
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-48 text-gray-500">
            No expense data this month
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-lg">
          <PieChartIcon className="w-5 h-5 text-purple-600" />
          Spending by Category
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={height}>
          <PieChart>
            <Pie
              activeIndex={activeIndex}
              activeShape={renderActiveShape}
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
              onMouseEnter={(_, index) => setActiveIndex(index)}
            >
              {chartData.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color}
                  stroke="white"
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Category Legend */}
        <div className="mt-2 grid grid-cols-2 gap-2">
          {chartData.slice(0, 6).map((item, index) => (
            <div
              key={item.name}
              className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer transition-colors ${
                activeIndex === index ? 'bg-gray-100' : 'hover:bg-gray-50'
              }`}
              onMouseEnter={() => setActiveIndex(index)}
            >
              <div
                className="w-3 h-3 rounded-full flex-shrink-0"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-xs truncate">{item.emoji} {item.name}</span>
              <span className="text-xs text-gray-500 ml-auto">
                {totalSpent > 0 ? Math.round((item.value / totalSpent) * 100) : 0}%
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
