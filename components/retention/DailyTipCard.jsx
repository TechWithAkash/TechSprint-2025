'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Lightbulb,
  ThumbsUp,
  ThumbsDown,
  X,
  RefreshCw,
  AlertTriangle,
  TrendingUp,
  Award
} from 'lucide-react'

const categoryStyles = {
  warning: {
    icon: AlertTriangle,
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    iconColor: 'text-amber-500',
    titleColor: 'text-amber-700'
  },
  insight: {
    icon: Lightbulb,
    bg: 'bg-purple-50',
    border: 'border-purple-200',
    iconColor: 'text-purple-500',
    titleColor: 'text-purple-700'
  },
  achievement: {
    icon: Award,
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    iconColor: 'text-emerald-500',
    titleColor: 'text-emerald-700'
  },
  wisdom: {
    icon: Lightbulb,
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    iconColor: 'text-blue-500',
    titleColor: 'text-blue-700'
  },
  general: {
    icon: Lightbulb,
    bg: 'bg-slate-50',
    border: 'border-slate-200',
    iconColor: 'text-slate-500',
    titleColor: 'text-slate-700'
  }
}

export default function DailyTipCard({ className = '' }) {
  const [tip, setTip] = useState(null)
  const [loading, setLoading] = useState(true)
  const [dismissed, setDismissed] = useState(false)
  const [feedbackGiven, setFeedbackGiven] = useState(false)

  useEffect(() => {
    fetchDailyTip()
  }, [])

  const fetchDailyTip = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/retention/daily-tip')
      const data = await response.json()

      if (data.success && data.tip) {
        setTip(data.tip)
        setDismissed(false)
        setFeedbackGiven(false)
      } else if (data.disabled) {
        setDismissed(true)
      }
    } catch (error) {
      console.error('Failed to fetch daily tip:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleFeedback = async (feedback) => {
    if (!tip?.id || feedbackGiven) return

    try {
      await fetch('/api/retention/daily-tip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'feedback',
          tipId: tip.id,
          feedback
        })
      })
      setFeedbackGiven(true)
    } catch (error) {
      console.error('Failed to submit feedback:', error)
    }
  }

  const handleDismiss = async () => {
    try {
      await fetch('/api/retention/daily-tip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'dismiss' })
      })
      setDismissed(true)
    } catch (error) {
      console.error('Failed to dismiss tip:', error)
    }
  }

  // Show minimal state if dismissed or no tip (don't leave gap)
  if (dismissed || (!loading && !tip)) {
    return (
      <Card className={`overflow-hidden border border-slate-200 bg-gradient-to-r from-slate-50 to-slate-100 ${className}`}>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-white">
                <Lightbulb className="w-4 h-4 text-slate-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Daily insights help you save smarter</p>
                <p className="text-xs text-slate-500">Check back tomorrow for personalized tips</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={fetchDailyTip}
              className="text-xs text-slate-500 hover:text-slate-700"
            >
              <RefreshCw className="w-3 h-3 mr-1" />
              Refresh
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  // Loading state
  if (loading) {
    return (
      <Card className={`overflow-hidden ${className}`}>
        <CardContent className="p-4">
          <div className="animate-pulse">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-5 h-5 bg-slate-200 rounded" />
              <div className="h-4 bg-slate-200 rounded w-24" />
            </div>
            <div className="space-y-2">
              <div className="h-4 bg-slate-200 rounded w-full" />
              <div className="h-4 bg-slate-200 rounded w-3/4" />
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  const style = categoryStyles[tip.category] || categoryStyles.general
  const IconComponent = style.icon

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        transition={{ duration: 0.3 }}
      >
        <Card className={`overflow-hidden border-l-4 ${style.border} ${style.bg} ${className}`}>
          <CardContent className="p-4">
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className={`p-1.5 rounded-lg ${style.bg}`}>
                  <IconComponent className={`w-4 h-4 ${style.iconColor}`} />
                </div>
                <span className={`text-sm font-medium ${style.titleColor}`}>
                  {tip.title || "Today's Insight"}
                </span>
              </div>
              <button
                onClick={handleDismiss}
                className="p-1 rounded-full hover:bg-white/50 transition-colors"
                aria-label="Dismiss tip"
              >
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>

            {/* Tip Message */}
            <p className="text-slate-700 text-sm leading-relaxed mb-4">
              {tip.message}
            </p>

            {/* Feedback */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-200/60">
              <div className="flex items-center gap-1">
                {feedbackGiven ? (
                  <span className="text-xs text-emerald-600 flex items-center gap-1">
                    <TrendingUp className="w-3 h-3" />
                    Thanks for your feedback!
                  </span>
                ) : (
                  <>
                    <span className="text-xs text-slate-500 mr-2">Was this helpful?</span>
                    <button
                      onClick={() => handleFeedback('helpful')}
                      className="p-1.5 rounded-lg hover:bg-emerald-100 transition-colors group"
                      aria-label="Mark as helpful"
                    >
                      <ThumbsUp className="w-4 h-4 text-slate-400 group-hover:text-emerald-600" />
                    </button>
                    <button
                      onClick={() => handleFeedback('not_relevant')}
                      className="p-1.5 rounded-lg hover:bg-red-100 transition-colors group"
                      aria-label="Mark as not relevant"
                    >
                      <ThumbsDown className="w-4 h-4 text-slate-400 group-hover:text-red-500" />
                    </button>
                  </>
                )}
              </div>

              <button
                onClick={handleDismiss}
                className="text-xs text-slate-400 hover:text-slate-600 transition-colors"
              >
                Hide tips
              </button>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </AnimatePresence>
  )
}
