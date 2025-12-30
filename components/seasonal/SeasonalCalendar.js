'use client'

import { useState, useEffect, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  ChevronLeft,
  ChevronRight,
  Calendar,
  Gift,
  GraduationCap,
  Plane,
  Heart,
  Star,
  IndianRupee
} from 'lucide-react'
import { getUpcomingEvents, estimateEventExpense, INDIAN_FINANCIAL_CALENDAR } from '@/lib/indianFinancialCalendar'

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
  festival: 'bg-orange-500',
  education: 'bg-blue-500',
  travel: 'bg-purple-500',
  celebration: 'bg-pink-500',
  custom: 'bg-slate-500',
  tax: 'bg-green-500'
}

// Month names
const MONTHS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
]

// Day names
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

export default function SeasonalCalendar({
  monthlyIncome = 50000,
  familySize = 1,
  userEvents = [],
  onEventClick,
  selectedDate,
  onDateSelect
}) {
  const [currentDate, setCurrentDate] = useState(new Date())
  const [viewMode, setViewMode] = useState('month') // 'month' | 'year'

  // Get current month and year
  const currentMonth = currentDate.getMonth()
  const currentYear = currentDate.getFullYear()

  // Get all events for display
  const allEvents = useMemo(() => {
    // Get calendar events for the year
    const calendarEvents = getUpcomingEvents(12, new Date(currentYear, 0, 1))
      .map(e => ({
        ...e,
        estimatedCost: estimateEventExpense(e.id, monthlyIncome, familySize),
        source: 'calendar'
      }))

    // Combine with user events
    return [
      ...calendarEvents,
      ...userEvents.filter(e => e.enabled !== false).map(e => ({
        ...e,
        source: 'user'
      }))
    ]
  }, [currentYear, monthlyIncome, familySize, userEvents])

  // Get events for a specific date
  const getEventsForDate = (date) => {
    return allEvents.filter(event => {
      const eventDate = new Date(event.date)
      return (
        eventDate.getDate() === date.getDate() &&
        eventDate.getMonth() === date.getMonth() &&
        eventDate.getFullYear() === date.getFullYear()
      )
    })
  }

  // Get events for a specific month
  const getEventsForMonth = (month, year) => {
    return allEvents.filter(event => {
      const eventDate = new Date(event.date)
      return eventDate.getMonth() === month && eventDate.getFullYear() === year
    })
  }

  // Navigate months
  const navigateMonth = (direction) => {
    const newDate = new Date(currentDate)
    newDate.setMonth(newDate.getMonth() + direction)
    setCurrentDate(newDate)
  }

  // Navigate years
  const navigateYear = (direction) => {
    const newDate = new Date(currentDate)
    newDate.setFullYear(newDate.getFullYear() + direction)
    setCurrentDate(newDate)
  }

  // Get days in month
  const getDaysInMonth = (month, year) => {
    return new Date(year, month + 1, 0).getDate()
  }

  // Get first day of month (0 = Sunday, 1 = Monday, etc.)
  const getFirstDayOfMonth = (month, year) => {
    return new Date(year, month, 1).getDay()
  }

  // Format currency
  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(amount)
  }

  // Check if date is today
  const isToday = (date) => {
    const today = new Date()
    return (
      date.getDate() === today.getDate() &&
      date.getMonth() === today.getMonth() &&
      date.getFullYear() === today.getFullYear()
    )
  }

  // Check if date is selected
  const isSelected = (date) => {
    if (!selectedDate) return false
    return (
      date.getDate() === selectedDate.getDate() &&
      date.getMonth() === selectedDate.getMonth() &&
      date.getFullYear() === selectedDate.getFullYear()
    )
  }

  // Generate calendar grid for month view
  const generateMonthGrid = () => {
    const daysInMonth = getDaysInMonth(currentMonth, currentYear)
    const firstDay = getFirstDayOfMonth(currentMonth, currentYear)
    const grid = []

    // Add empty cells for days before the first day
    for (let i = 0; i < firstDay; i++) {
      grid.push({ day: null, events: [] })
    }

    // Add days of the month
    for (let day = 1; day <= daysInMonth; day++) {
      const date = new Date(currentYear, currentMonth, day)
      const events = getEventsForDate(date)
      grid.push({ day, date, events })
    }

    return grid
  }

  // Render month view
  const renderMonthView = () => {
    const grid = generateMonthGrid()
    const monthEvents = getEventsForMonth(currentMonth, currentYear)
    const monthTotal = monthEvents.reduce((sum, e) => sum + (e.estimatedCost || e.amount || 0), 0)

    return (
      <div className="space-y-4">
        {/* Month header with total */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={() => navigateMonth(-1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <h2 className="text-lg font-semibold min-w-[150px] text-center">
              {MONTHS[currentMonth]} {currentYear}
            </h2>
            <Button variant="ghost" size="icon" onClick={() => navigateMonth(1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>

          <div className="flex items-center gap-4">
            {monthEvents.length > 0 && (
              <div className="text-right">
                <p className="text-sm text-slate-500">{monthEvents.length} events</p>
                <p className="font-semibold text-emerald-600">{formatCurrency(monthTotal)}</p>
              </div>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setViewMode('year')}
            >
              Year View
            </Button>
          </div>
        </div>

        {/* Day headers */}
        <div className="grid grid-cols-7 gap-1">
          {DAYS.map(day => (
            <div key={day} className="text-center text-xs font-medium text-slate-500 py-2">
              {day}
            </div>
          ))}
        </div>

        {/* Calendar grid */}
        <div className="grid grid-cols-7 gap-1">
          {grid.map((cell, index) => (
            <div
              key={index}
              className={`min-h-[80px] p-1 border rounded-lg transition-all ${
                cell.day
                  ? isToday(cell.date)
                    ? 'border-emerald-500 bg-emerald-50'
                    : isSelected(cell.date)
                      ? 'border-orange-500 bg-orange-50'
                      : 'border-slate-200 hover:border-slate-300 cursor-pointer'
                  : 'border-transparent'
              }`}
              onClick={() => cell.day && onDateSelect?.(cell.date)}
            >
              {cell.day && (
                <>
                  <div className={`text-sm font-medium ${
                    isToday(cell.date)
                      ? 'text-emerald-700'
                      : 'text-slate-700'
                  }`}>
                    {cell.day}
                  </div>
                  {cell.events.length > 0 && (
                    <div className="mt-1 space-y-0.5">
                      {cell.events.slice(0, 2).map((event, i) => {
                        const EventIcon = EVENT_ICONS[event.category] || Gift
                        return (
                          <div
                            key={i}
                            className={`text-xs px-1 py-0.5 rounded truncate text-white ${
                              EVENT_COLORS[event.category] || EVENT_COLORS.custom
                            }`}
                            onClick={(e) => {
                              e.stopPropagation()
                              onEventClick?.(event)
                            }}
                            title={`${event.name} - ${formatCurrency(event.estimatedCost || event.amount)}`}
                          >
                            {event.name}
                          </div>
                        )
                      })}
                      {cell.events.length > 2 && (
                        <div className="text-xs text-slate-500 px-1">
                          +{cell.events.length - 2} more
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          ))}
        </div>
      </div>
    )
  }

  // Render year view
  const renderYearView = () => {
    return (
      <div className="space-y-4">
        {/* Year header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={() => navigateYear(-1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <h2 className="text-lg font-semibold min-w-[100px] text-center">
              {currentYear}
            </h2>
            <Button variant="ghost" size="icon" onClick={() => navigateYear(1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setViewMode('month')}
          >
            Month View
          </Button>
        </div>

        {/* Year grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
          {MONTHS.map((month, index) => {
            const events = getEventsForMonth(index, currentYear)
            const total = events.reduce((sum, e) => sum + (e.estimatedCost || e.amount || 0), 0)
            const isCurrentMonth = index === new Date().getMonth() && currentYear === new Date().getFullYear()

            return (
              <div
                key={month}
                className={`p-3 border rounded-lg cursor-pointer transition-all hover:shadow-md ${
                  isCurrentMonth
                    ? 'border-emerald-500 bg-emerald-50'
                    : 'border-slate-200 hover:border-slate-300'
                }`}
                onClick={() => {
                  setCurrentDate(new Date(currentYear, index, 1))
                  setViewMode('month')
                }}
              >
                <h3 className={`font-semibold text-sm ${
                  isCurrentMonth ? 'text-emerald-700' : 'text-slate-700'
                }`}>
                  {month}
                </h3>

                {events.length > 0 ? (
                  <div className="mt-2 space-y-1">
                    <div className="flex items-center gap-1">
                      <Calendar className="h-3 w-3 text-slate-400" />
                      <span className="text-xs text-slate-500">
                        {events.length} event{events.length > 1 ? 's' : ''}
                      </span>
                    </div>
                    <p className="text-sm font-semibold text-emerald-600">
                      {formatCurrency(total)}
                    </p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {events.slice(0, 3).map((event, i) => (
                        <div
                          key={i}
                          className={`w-2 h-2 rounded-full ${
                            EVENT_COLORS[event.category] || EVENT_COLORS.custom
                          }`}
                          title={event.name}
                        />
                      ))}
                      {events.length > 3 && (
                        <span className="text-xs text-slate-400">+{events.length - 3}</span>
                      )}
                    </div>
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-slate-400">No events</p>
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Calendar className="h-5 w-5 text-orange-600" />
          <CardTitle className="text-lg">Event Calendar</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {viewMode === 'month' ? renderMonthView() : renderYearView()}

        {/* Legend */}
        <div className="mt-4 pt-4 border-t">
          <p className="text-xs text-slate-500 mb-2">Event Types:</p>
          <div className="flex flex-wrap gap-3">
            {Object.entries(EVENT_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div className={`w-3 h-3 rounded-full ${color}`} />
                <span className="text-xs text-slate-600 capitalize">{type}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
