'use client'

import Link from 'next/link'
import {
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle2,
  Lightbulb,
  PartyPopper,
  ArrowRight,
  Sparkles
} from 'lucide-react'

const typeConfig = {
  spending: {
    icon: TrendingUp,
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    iconBg: 'bg-blue-100',
    iconColor: 'text-blue-600',
    titleColor: 'text-blue-900'
  },
  achievement: {
    icon: CheckCircle2,
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    iconBg: 'bg-emerald-100',
    iconColor: 'text-emerald-600',
    titleColor: 'text-emerald-900'
  },
  warning: {
    icon: AlertTriangle,
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    iconBg: 'bg-amber-100',
    iconColor: 'text-amber-600',
    titleColor: 'text-amber-900'
  },
  recommendation: {
    icon: Lightbulb,
    bg: 'bg-purple-50',
    border: 'border-purple-200',
    iconBg: 'bg-purple-100',
    iconColor: 'text-purple-600',
    titleColor: 'text-purple-900'
  },
  celebration: {
    icon: PartyPopper,
    bg: 'bg-gradient-to-r from-pink-50 to-orange-50',
    border: 'border-pink-200',
    iconBg: 'bg-gradient-to-r from-pink-100 to-orange-100',
    iconColor: 'text-pink-600',
    titleColor: 'text-pink-900'
  }
}

const priorityBadge = {
  high: 'bg-red-100 text-red-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-gray-100 text-gray-600'
}

export default function InsightCard({ insight, compact = false }) {
  const config = typeConfig[insight.type] || typeConfig.recommendation
  const Icon = config.icon

  if (compact) {
    return (
      <div className={`flex items-start gap-3 p-3 rounded-xl ${config.bg} ${config.border} border`}>
        <div className={`p-1.5 rounded-lg ${config.iconBg}`}>
          <Icon className={`w-4 h-4 ${config.iconColor}`} />
        </div>
        <div className="flex-1 min-w-0">
          <p className={`font-medium text-sm ${config.titleColor} truncate`}>
            {insight.title}
          </p>
          <p className="text-xs text-gray-600 mt-0.5 line-clamp-2">
            {insight.message}
          </p>
        </div>
        {insight.actionUrl && (
          <Link
            href={insight.actionUrl}
            className={`p-1.5 rounded-lg hover:bg-white/50 transition-colors ${config.iconColor}`}
          >
            <ArrowRight className="w-4 h-4" />
          </Link>
        )}
      </div>
    )
  }

  return (
    <div className={`relative overflow-hidden rounded-2xl ${config.bg} ${config.border} border-2 p-4 transition-all hover:shadow-md`}>
      {/* Priority Badge */}
      {insight.priority === 'high' && (
        <div className="absolute top-3 right-3">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${priorityBadge[insight.priority]}`}>
            Important
          </span>
        </div>
      )}

      {/* AI Badge */}
      {insight.source === 'ai' && (
        <div className="absolute top-3 right-3">
          <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-gradient-to-r from-violet-100 to-purple-100 text-purple-700 flex items-center gap-1">
            <Sparkles className="w-3 h-3" />
            AI
          </span>
        </div>
      )}

      <div className="flex items-start gap-4">
        {/* Icon */}
        <div className={`p-3 rounded-xl ${config.iconBg} flex-shrink-0`}>
          <Icon className={`w-6 h-6 ${config.iconColor}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <h4 className={`font-semibold ${config.titleColor} pr-16`}>
            {insight.title}
          </h4>
          <p className="text-sm text-gray-600 mt-1 leading-relaxed">
            {insight.message}
          </p>

          {/* Action Button */}
          {insight.actionLabel && insight.actionUrl && (
            <Link
              href={insight.actionUrl}
              className={`inline-flex items-center gap-1 mt-3 text-sm font-medium ${config.iconColor} hover:underline`}
            >
              {insight.actionLabel}
              <ArrowRight className="w-4 h-4" />
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}
