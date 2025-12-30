'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Calendar,
  IndianRupee,
  TrendingUp,
  ChevronRight,
  Sparkles,
  Gift,
  GraduationCap,
  Plane,
  Heart,
  Star,
  AlertCircle,
  CheckCircle2,
  Clock
} from 'lucide-react'
import { getUpcomingEvents, estimateEventExpense } from '@/lib/indianFinancialCalendar'
import { seasonalPlanner } from '@/lib/seasonalPlanner'

// Event type icons
const EVENT_ICONS = {
  festival: Gift,
  education: GraduationCap,
  travel: Plane,
  celebration: Heart,
  custom: Star,
  tax: IndianRupee
}

// Event type colors
const EVENT_COLORS = {
  festival: 'bg-orange-100 text-orange-700 border-orange-200',
  education: 'bg-blue-100 text-blue-700 border-blue-200',
  travel: 'bg-purple-100 text-purple-700 border-purple-200',
  celebration: 'bg-pink-100 text-pink-700 border-pink-200',
  custom: 'bg-slate-100 text-slate-700 border-slate-200',
  tax: 'bg-green-100 text-green-700 border-green-200'
}

export default function SeasonalPlanningWidget({
  onViewAll,
  onAddEvent,
  compact = false
}) {
  const [upcomingEvents, setUpcomingEvents] = useState([])
  const [savingsData, setSavingsData] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [userProfile, setUserProfile] = useState(null)

  const loadSeasonalData = useCallback(async () => {
    setIsLoading(true)
    try {
      // Fetch real data from API (connected to user's database)
      const response = await fetch('/api/seasonal-events?months=6')
      const data = await response.json()

      if (data.success) {
        // Use real user profile data
        setUserProfile(data.userProfile)

        // Use pre-calculated events from API (with real user income/family size)
        const allEvents = data.allEvents || []

        // Sort by date
        allEvents.sort((a, b) => new Date(a.date) - new Date(b.date))

        setUpcomingEvents(allEvents.slice(0, compact ? 3 : 5))
        setSavingsData(data.savingsData)
      } else {
        console.error('Failed to fetch seasonal data:', data.error)
        // Fallback to local calculation if API fails
        fallbackToLocalData()
      }
    } catch (error) {
      console.error('Error loading seasonal data:', error)
      // Fallback to local calculation if API fails
      fallbackToLocalData()
    } finally {
      setIsLoading(false)
    }
  }, [compact])

  // Fallback function for when API is unavailable
  const fallbackToLocalData = () => {
    const defaultIncome = 50000
    const defaultFamilySize = 1

    const calendarEvents = getUpcomingEvents(6, new Date())
    const allEvents = calendarEvents.map(e => ({
      ...e,
      estimatedCost: estimateEventExpense(e.id, { monthlyIncome: defaultIncome, familySize: defaultFamilySize }),
      source: 'calendar'
    }))

    allEvents.sort((a, b) => new Date(a.date) - new Date(b.date))

    const savings = seasonalPlanner.calculateMonthlySavingsRequired(
      allEvents,
      defaultIncome,
      new Date()
    )

    setUpcomingEvents(allEvents.slice(0, compact ? 3 : 5))
    setSavingsData(savings)
    setUserProfile({ monthlyIncome: defaultIncome, familySize: defaultFamilySize })
  }

  useEffect(() => {
    loadSeasonalData()
  }, [loadSeasonalData])

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(amount)
  }

  const formatDate = (dateStr) => {
    const date = new Date(dateStr)
    return date.toLocaleDateString('en-IN', {
      day: 'numeric',
      month: 'short'
    })
  }

  const getDaysUntil = (dateStr) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffTime = date - now
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
  }

  const getUrgencyBadge = (daysUntil) => {
    if (daysUntil <= 30) {
      return <Badge className="bg-red-100 text-red-700 border-0 text-xs">Urgent</Badge>
    } else if (daysUntil <= 60) {
      return <Badge className="bg-amber-100 text-amber-700 border-0 text-xs">Soon</Badge>
    }
    return null
  }

  if (isLoading) {
    return (
      <Card className="animate-pulse">
        <CardContent className="p-6">
          <div className="h-32 bg-slate-100 rounded-lg"></div>
        </CardContent>
      </Card>
    )
  }

  // Compact view for dashboard
  if (compact) {
    return (
      <Card className="overflow-hidden">
        <CardHeader className="pb-2 bg-gradient-to-r from-orange-50 to-amber-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-orange-100 rounded-lg">
                <Calendar className="h-4 w-4 text-orange-600" />
              </div>
              <CardTitle className="text-base">Seasonal Planning</CardTitle>
            </div>
            {onViewAll && (
              <Button variant="ghost" size="sm" onClick={onViewAll} className="text-xs">
                View All
                <ChevronRight className="h-3 w-3 ml-1" />
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-4 space-y-3">
          {/* Monthly Savings Needed */}
          {savingsData && savingsData.totalMonthlySavingsRequired > 0 && (
            <div className="p-3 bg-emerald-50 rounded-lg border border-emerald-200">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-600">Monthly Savings Needed</span>
                <Sparkles className="h-3 w-3 text-emerald-600" />
              </div>
              <p className="text-lg font-bold text-emerald-700">
                {formatCurrency(savingsData.totalMonthlySavingsRequired)}
              </p>
              <p className="text-xs text-slate-500">
                For {upcomingEvents.length} upcoming event{upcomingEvents.length > 1 ? 's' : ''}
              </p>
            </div>
          )}

          {/* Upcoming Events List */}
          {upcomingEvents.length > 0 ? (
            <div className="space-y-2">
              {upcomingEvents.slice(0, 3).map((event, index) => {
                const EventIcon = EVENT_ICONS[event.category] || Gift
                const daysUntil = getDaysUntil(event.date)

                return (
                  <div
                    key={event.id || index}
                    className="flex items-center justify-between p-2 bg-slate-50 rounded-lg"
                  >
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded-lg ${EVENT_COLORS[event.category] || EVENT_COLORS.custom}`}>
                        <EventIcon className="h-3 w-3" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-900">{event.name}</p>
                        <p className="text-xs text-slate-500">
                          {formatDate(event.date)} ({daysUntil} days)
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-semibold text-slate-700">
                        {formatCurrency(event.estimatedCost || event.amount)}
                      </p>
                      {getUrgencyBadge(daysUntil)}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="text-center py-4">
              <p className="text-sm text-slate-500">No upcoming events</p>
              {onAddEvent && (
                <Button variant="outline" size="sm" onClick={onAddEvent} className="mt-2">
                  Add Event
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  // Full view
  return (
    <Card className="overflow-hidden">
      <CardHeader className="bg-gradient-to-r from-orange-50 via-amber-50 to-yellow-50 border-b">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-orange-100 rounded-xl">
              <Calendar className="h-6 w-6 text-orange-600" />
            </div>
            <div>
              <CardTitle className="text-lg">Seasonal Financial Planning</CardTitle>
              <CardDescription>Plan ahead for festivals, celebrations & expenses</CardDescription>
            </div>
          </div>
          {onAddEvent && (
            <Button onClick={onAddEvent} size="sm" className="bg-orange-600 hover:bg-orange-700">
              Add Event
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="p-6 space-y-6">
        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Monthly Savings Needed */}
          <div className="p-4 bg-emerald-50 rounded-xl border border-emerald-200">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="h-4 w-4 text-emerald-600" />
              <span className="text-xs font-medium text-emerald-700">Monthly Savings</span>
            </div>
            <p className="text-2xl font-bold text-emerald-700">
              {formatCurrency(savingsData?.totalMonthlySavingsRequired || 0)}
            </p>
            <p className="text-xs text-emerald-600 mt-1">
              {savingsData?.recommendation?.message || 'Start saving for upcoming events'}
            </p>
          </div>

          {/* Total Events */}
          <div className="p-4 bg-blue-50 rounded-xl border border-blue-200">
            <div className="flex items-center gap-2 mb-2">
              <Calendar className="h-4 w-4 text-blue-600" />
              <span className="text-xs font-medium text-blue-700">Upcoming Events</span>
            </div>
            <p className="text-2xl font-bold text-blue-700">{upcomingEvents.length}</p>
            <p className="text-xs text-blue-600 mt-1">In the next 6 months</p>
          </div>

          {/* Total Budget */}
          <div className="p-4 bg-purple-50 rounded-xl border border-purple-200">
            <div className="flex items-center gap-2 mb-2">
              <IndianRupee className="h-4 w-4 text-purple-600" />
              <span className="text-xs font-medium text-purple-700">Total Budget</span>
            </div>
            <p className="text-2xl font-bold text-purple-700">
              {formatCurrency(upcomingEvents.reduce((sum, e) => sum + (e.estimatedCost || e.amount || 0), 0))}
            </p>
            <p className="text-xs text-purple-600 mt-1">Across all events</p>
          </div>
        </div>

        {/* Event Timeline */}
        <div>
          <h3 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Upcoming Events Timeline
          </h3>

          {upcomingEvents.length > 0 ? (
            <div className="space-y-3">
              {upcomingEvents.map((event, index) => {
                const EventIcon = EVENT_ICONS[event.category] || Gift
                const daysUntil = getDaysUntil(event.date)
                const progress = Math.max(0, Math.min(100, ((180 - daysUntil) / 180) * 100))
                const estimatedCost = event.estimatedCost || event.amount || 0
                const monthlySaving = daysUntil > 0 ? Math.round(estimatedCost / Math.ceil(daysUntil / 30)) : estimatedCost

                return (
                  <div
                    key={event.id || index}
                    className="p-4 bg-white border border-slate-200 rounded-xl hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1">
                        <div className={`p-2.5 rounded-xl ${EVENT_COLORS[event.category] || EVENT_COLORS.custom}`}>
                          <EventIcon className="h-5 w-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h4 className="font-semibold text-slate-900">{event.name}</h4>
                            {event.hindiName && (
                              <span className="text-sm text-slate-500">({event.hindiName})</span>
                            )}
                            {getUrgencyBadge(daysUntil)}
                          </div>
                          <p className="text-sm text-slate-500 mt-0.5">
                            {formatDate(event.date)} - {daysUntil} days away
                          </p>

                          {/* Progress bar */}
                          <div className="mt-2">
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="text-slate-500">Time remaining</span>
                              <span className="text-slate-600">{Math.round(100 - progress)}%</span>
                            </div>
                            <Progress value={100 - progress} className="h-1.5" />
                          </div>
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <p className="text-lg font-bold text-slate-900">
                          {formatCurrency(estimatedCost)}
                        </p>
                        <p className="text-xs text-emerald-600 font-medium">
                          Save {formatCurrency(monthlySaving)}/mo
                        </p>
                      </div>
                    </div>

                    {/* Sub-categories if available */}
                    {event.subCategories && event.subCategories.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-slate-100">
                        <p className="text-xs text-slate-500 mb-2">Typical expenses:</p>
                        <div className="flex flex-wrap gap-1.5">
                          {event.subCategories.slice(0, 4).map((sub, i) => (
                            <Badge key={i} variant="outline" className="text-xs">
                              {typeof sub === 'object' ? sub.name : sub}
                            </Badge>
                          ))}
                          {event.subCategories.length > 4 && (
                            <Badge variant="outline" className="text-xs text-slate-400">
                              +{event.subCategories.length - 4} more
                            </Badge>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="text-center py-8 bg-slate-50 rounded-xl">
              <Calendar className="h-12 w-12 text-slate-300 mx-auto mb-3" />
              <p className="text-slate-600 font-medium">No upcoming events</p>
              <p className="text-sm text-slate-500 mt-1">
                Add custom events to start planning
              </p>
              {onAddEvent && (
                <Button onClick={onAddEvent} variant="outline" className="mt-4">
                  Add Your First Event
                </Button>
              )}
            </div>
          )}
        </div>

        {/* Tips */}
        {savingsData?.tips && savingsData.tips.length > 0 && (
          <div className="p-4 bg-amber-50 rounded-xl border border-amber-200">
            <div className="flex items-start gap-3">
              <Sparkles className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-amber-900 mb-1">Smart Tip</h4>
                <p className="text-sm text-amber-700">{savingsData.tips[0]}</p>
              </div>
            </div>
          </div>
        )}

        {/* View All Button */}
        {onViewAll && upcomingEvents.length > 0 && (
          <div className="text-center">
            <Button variant="outline" onClick={onViewAll}>
              View All Events & Calendar
              <ChevronRight className="h-4 w-4 ml-2" />
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
