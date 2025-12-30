'use client'

import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

export default function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  trendValue,
  color = 'emerald',
  size = 'default'
}) {
  const colorClasses = {
    emerald: {
      bg: 'bg-emerald-50',
      icon: 'text-emerald-600',
      accent: 'bg-emerald-500'
    },
    blue: {
      bg: 'bg-blue-50',
      icon: 'text-blue-600',
      accent: 'bg-blue-500'
    },
    purple: {
      bg: 'bg-purple-50',
      icon: 'text-purple-600',
      accent: 'bg-purple-500'
    },
    orange: {
      bg: 'bg-orange-50',
      icon: 'text-orange-600',
      accent: 'bg-orange-500'
    },
    red: {
      bg: 'bg-red-50',
      icon: 'text-red-600',
      accent: 'bg-red-500'
    },
    amber: {
      bg: 'bg-amber-50',
      icon: 'text-amber-600',
      accent: 'bg-amber-500'
    }
  }

  const colors = colorClasses[color] || colorClasses.emerald

  const getTrendIcon = () => {
    if (trend === 'up') return <TrendingUp className="w-4 h-4" />
    if (trend === 'down') return <TrendingDown className="w-4 h-4" />
    return <Minus className="w-4 h-4" />
  }

  const getTrendColor = () => {
    if (trend === 'up') return 'text-emerald-600 bg-emerald-50'
    if (trend === 'down') return 'text-red-600 bg-red-50'
    return 'text-gray-600 bg-gray-50'
  }

  return (
    <Card className="overflow-hidden hover:shadow-lg transition-shadow duration-300">
      <CardContent className={`p-0 ${size === 'compact' ? '' : ''}`}>
        <div className="flex items-stretch">
          {/* Color accent bar */}
          <div className={`w-1.5 ${colors.accent}`} />

          <div className="flex-1 p-4">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-500 mb-1">{title}</p>
                <p className={`font-bold text-gray-900 ${size === 'compact' ? 'text-xl' : 'text-2xl'}`}>
                  {value}
                </p>
                {subtitle && (
                  <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
                )}
              </div>

              <div className="flex flex-col items-end gap-2">
                {Icon && (
                  <div className={`p-2.5 rounded-xl ${colors.bg}`}>
                    <Icon className={`w-5 h-5 ${colors.icon}`} />
                  </div>
                )}

                {trendValue && (
                  <div className={`flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${getTrendColor()}`}>
                    {getTrendIcon()}
                    <span>{trendValue}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
