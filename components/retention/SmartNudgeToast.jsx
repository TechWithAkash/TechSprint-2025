'use client'

import { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useRouter } from 'next/navigation'
import {
  AlertTriangle, AlertCircle, Zap, Target,
  Clock, Trophy, X, ChevronRight
} from 'lucide-react'

const ICON_MAP = {
  'AlertTriangle': AlertTriangle,
  'AlertCircle': AlertCircle,
  'Zap': Zap,
  'Target': Target,
  'Clock': Clock,
  'Trophy': Trophy
}

const PRIORITY_STYLES = {
  high: {
    border: 'border-l-red-500',
    bg: 'bg-red-50',
    icon: 'text-red-500',
    title: 'text-red-700'
  },
  medium: {
    border: 'border-l-amber-500',
    bg: 'bg-amber-50',
    icon: 'text-amber-500',
    title: 'text-amber-700'
  },
  low: {
    border: 'border-l-blue-500',
    bg: 'bg-blue-50',
    icon: 'text-blue-500',
    title: 'text-blue-700'
  }
}

function NudgeToast({ nudge, onDismiss, onAction }) {
  const [progress, setProgress] = useState(100)
  const [shouldDismiss, setShouldDismiss] = useState(false)
  const router = useRouter()

  const IconComponent = ICON_MAP[nudge.icon] || AlertCircle
  const styles = PRIORITY_STYLES[nudge.priority] || PRIORITY_STYLES.medium

  // Handle auto-dismiss when progress reaches 0
  useEffect(() => {
    if (shouldDismiss) {
      onDismiss(nudge)
    }
  }, [shouldDismiss, nudge, onDismiss])

  useEffect(() => {
    // Auto-dismiss after 8 seconds
    const duration = 8000
    const interval = 50
    const decrement = (100 / duration) * interval

    const timer = setInterval(() => {
      setProgress(prev => {
        if (prev <= decrement) {
          clearInterval(timer)
          setShouldDismiss(true)
          return 0
        }
        return prev - decrement
      })
    }, interval)

    return () => clearInterval(timer)
  }, [nudge.id])

  const handleAction = () => {
    onAction(nudge)
    if (nudge.actionUrl) {
      router.push(nudge.actionUrl)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: 100, scale: 0.9 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 100, scale: 0.9 }}
      transition={{ type: 'spring', stiffness: 400, damping: 25 }}
      className={`
        relative w-80 rounded-lg shadow-lg border-l-4 overflow-hidden
        ${styles.border} ${styles.bg}
      `}
    >
      {/* Content */}
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div className={`p-1.5 rounded-lg bg-white/60`}>
            <IconComponent className={`w-5 h-5 ${styles.icon}`} />
          </div>

          {/* Text */}
          <div className="flex-1 min-w-0">
            <h4 className={`font-medium text-sm ${styles.title}`}>
              {nudge.title}
            </h4>
            <p className="text-xs text-slate-600 mt-0.5 line-clamp-2">
              {nudge.message}
            </p>

            {/* Action button */}
            {nudge.actionLabel && (
              <button
                onClick={handleAction}
                className="mt-2 text-xs font-medium text-slate-700 hover:text-slate-900 flex items-center gap-1 transition-colors"
              >
                {nudge.actionLabel}
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Close button */}
          <button
            onClick={() => onDismiss(nudge)}
            className="p-1 rounded-full hover:bg-white/50 transition-colors"
            aria-label="Dismiss"
          >
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-white/30">
        <motion.div
          initial={{ width: '100%' }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.05, ease: 'linear' }}
          className={`h-full ${styles.icon.replace('text-', 'bg-')} opacity-60`}
        />
      </div>
    </motion.div>
  )
}

export default function SmartNudgeToast() {
  const [nudges, setNudges] = useState([])
  const [dismissed, setDismissed] = useState(new Set())

  useEffect(() => {
    fetchNudges()

    // Refresh every 5 minutes
    const interval = setInterval(fetchNudges, 5 * 60 * 1000)
    return () => clearInterval(interval)
  }, [])

  const fetchNudges = async () => {
    try {
      const response = await fetch('/api/retention/smart-nudges')
      const data = await response.json()

      if (data.success && data.nudges?.length > 0) {
        // Filter out dismissed nudges
        const newNudges = data.nudges.filter(n => !dismissed.has(n.id))
        setNudges(newNudges)
      }
    } catch (error) {
      console.error('Failed to fetch nudges:', error)
    }
  }

  const handleDismiss = useCallback(async (nudge) => {
    setDismissed(prev => new Set([...prev, nudge.id]))
    setNudges(prev => prev.filter(n => n.id !== nudge.id))

    try {
      await fetch('/api/retention/smart-nudges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'dismiss',
          nudgeType: nudge.type
        })
      })
    } catch (error) {
      console.error('Failed to record dismissal:', error)
    }
  }, [])

  const handleAction = useCallback(async (nudge) => {
    setNudges(prev => prev.filter(n => n.id !== nudge.id))

    try {
      await fetch('/api/retention/smart-nudges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'clicked',
          nudgeType: nudge.type
        })
      })
    } catch (error) {
      console.error('Failed to record click:', error)
    }
  }, [])

  if (nudges.length === 0) return null

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-3">
      <AnimatePresence mode="sync">
        {nudges.slice(0, 3).map((nudge) => (
          <NudgeToast
            key={nudge.id}
            nudge={nudge}
            onDismiss={handleDismiss}
            onAction={handleAction}
          />
        ))}
      </AnimatePresence>
    </div>
  )
}
