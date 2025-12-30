'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Plus, Check, Sun, Cloud, CloudRain, Zap } from 'lucide-react'

const MOOD_OPTIONS = [
  {
    id: 'great',
    emoji: '😌',
    label: '₹0',
    description: 'No spend',
    estimatedSpend: 0,
    color: 'emerald',
    bgColor: 'bg-emerald-50',
    borderColor: 'border-emerald-300',
    textColor: 'text-emerald-700'
  },
  {
    id: 'good',
    emoji: '😊',
    label: '<₹500',
    description: 'Light',
    estimatedSpend: 250,
    color: 'blue',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-300',
    textColor: 'text-blue-700'
  },
  {
    id: 'okay',
    emoji: '😐',
    label: '₹500-2k',
    description: 'Moderate',
    estimatedSpend: 1000,
    color: 'amber',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-300',
    textColor: 'text-amber-700'
  },
  {
    id: 'tough',
    emoji: '😰',
    label: '>₹2k',
    description: 'Heavy',
    estimatedSpend: 3000,
    color: 'red',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-300',
    textColor: 'text-red-700'
  }
]

export default function DailyPulseWidget({ onQuickAdd, className = '' }) {
  const [loading, setLoading] = useState(true)
  const [checkedIn, setCheckedIn] = useState(false)
  const [selectedMood, setSelectedMood] = useState(null)
  const [weekSummary, setWeekSummary] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    fetchPulseStatus()
  }, [])

  const fetchPulseStatus = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/retention/daily-pulse')
      const data = await response.json()

      if (data.success) {
        setCheckedIn(data.checkedInToday)
        if (data.todaysPulse) {
          setSelectedMood(data.todaysPulse.mood)
        }
        setWeekSummary(data.weekSummary)
      }
    } catch (error) {
      console.error('Failed to fetch pulse status:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleMoodSelect = async (mood) => {
    if (submitting) return

    const moodOption = MOOD_OPTIONS.find(m => m.id === mood)
    setSubmitting(true)
    setSelectedMood(mood)

    try {
      const response = await fetch('/api/retention/daily-pulse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mood,
          estimatedSpend: moodOption.estimatedSpend
        })
      })

      const data = await response.json()

      if (data.success) {
        setCheckedIn(true)
        setMessage(data.message)
        // Refresh week summary
        fetchPulseStatus()
      }
    } catch (error) {
      console.error('Failed to record pulse:', error)
    } finally {
      setSubmitting(false)
    }
  }

  // Get current date info
  const now = new Date()
  const dateStr = now.toLocaleDateString('en-IN', {
    weekday: 'short',
    month: 'short',
    day: 'numeric'
  })

  // Determine weather icon based on time
  const hour = now.getHours()
  const WeatherIcon = hour >= 6 && hour < 18 ? Sun : Cloud

  if (loading) {
    return (
      <Card className={`border-l-4 border-l-emerald-500 ${className}`}>
        <CardContent className="p-4">
          <div className="animate-pulse">
            <div className="flex justify-between mb-4">
              <div className="h-5 bg-slate-200 rounded w-24" />
              <div className="h-4 bg-slate-200 rounded w-16" />
            </div>
            <div className="flex gap-3 justify-center">
              {[1, 2, 3, 4].map(i => (
                <div key={i} className="w-16 h-20 bg-slate-200 rounded-xl" />
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={`border-l-4 border-l-emerald-500 overflow-hidden ${className}`}>
      <CardContent className="p-4">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            <Zap className="w-4 h-4 text-emerald-500" />
            Today&apos;s Pulse
          </h3>
          <span className="text-xs text-slate-500 flex items-center gap-1">
            {dateStr}
            <WeatherIcon className="w-4 h-4 text-amber-400" />
          </span>
        </div>

        <AnimatePresence mode="wait">
          {checkedIn ? (
            // Checked in state
            <motion.div
              key="checked-in"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="text-center py-2"
            >
              <div className="flex items-center justify-center gap-2 mb-2">
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 500, delay: 0.1 }}
                  className="w-8 h-8 rounded-full bg-emerald-100 flex items-center justify-center"
                >
                  <Check className="w-5 h-5 text-emerald-600" />
                </motion.div>
                <span className="text-2xl">
                  {MOOD_OPTIONS.find(m => m.id === selectedMood)?.emoji}
                </span>
              </div>
              <p className="text-sm text-slate-600 mb-3">{message || "You're all set for today!"}</p>

              {/* Quick add button */}
              <Button
                variant="outline"
                size="sm"
                onClick={onQuickAdd}
                className="text-emerald-600 border-emerald-200 hover:bg-emerald-50"
              >
                <Plus className="w-4 h-4 mr-1" />
                Add specific expense
              </Button>
            </motion.div>
          ) : (
            // Check-in state
            <motion.div
              key="check-in"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <p className="text-sm text-slate-600 text-center mb-4">
                How&apos;s your spending today?
              </p>

              {/* Mood selector */}
              <div className="grid grid-cols-4 gap-2 mb-4">
                {MOOD_OPTIONS.map((mood) => (
                  <motion.button
                    key={mood.id}
                    onClick={() => handleMoodSelect(mood.id)}
                    disabled={submitting}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className={`
                      relative flex flex-col items-center p-3 rounded-xl border-2 transition-all
                      ${selectedMood === mood.id
                        ? `${mood.bgColor} ${mood.borderColor}`
                        : 'bg-white border-slate-200 hover:border-slate-300'
                      }
                      ${submitting ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                  >
                    <span className="text-2xl mb-1">{mood.emoji}</span>
                    <span className={`text-xs font-medium ${selectedMood === mood.id ? mood.textColor : 'text-slate-600'}`}>
                      {mood.label}
                    </span>
                  </motion.button>
                ))}
              </div>

              {/* Divider with "or" */}
              <div className="relative flex items-center justify-center mb-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-200" />
                </div>
                <span className="relative bg-white px-3 text-xs text-slate-400">or</span>
              </div>

              {/* Quick add button */}
              <Button
                variant="outline"
                size="sm"
                onClick={onQuickAdd}
                className="w-full text-slate-600 border-slate-200 hover:bg-slate-50"
              >
                <Plus className="w-4 h-4 mr-2" />
                Quick Add Expense
              </Button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Week summary footer */}
        {weekSummary && (
          <div className="mt-4 pt-3 border-t border-slate-100">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>
                This week: <span className="font-medium text-slate-700">₹{weekSummary.totalSpent?.toLocaleString('en-IN') || 0}</span> spent
              </span>
              <span>
                {weekSummary.daysTracked || 0} days tracked
              </span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
