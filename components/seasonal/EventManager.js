'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Calendar,
  IndianRupee,
  Plus,
  Pencil,
  Trash2,
  Gift,
  GraduationCap,
  Plane,
  Heart,
  Star,
  X,
  Save,
  CheckCircle2
} from 'lucide-react'

// Event categories
const EVENT_CATEGORIES = [
  { value: 'festival', label: 'Festival', icon: Gift, color: 'bg-orange-100 text-orange-700' },
  { value: 'education', label: 'Education', icon: GraduationCap, color: 'bg-blue-100 text-blue-700' },
  { value: 'travel', label: 'Travel', icon: Plane, color: 'bg-purple-100 text-purple-700' },
  { value: 'celebration', label: 'Celebration', icon: Heart, color: 'bg-pink-100 text-pink-700' },
  { value: 'custom', label: 'Other', icon: Star, color: 'bg-slate-100 text-slate-700' }
]

// Recurrence options
const RECURRENCE_OPTIONS = [
  { value: 'once', label: 'One-time event' },
  { value: 'yearly', label: 'Every year' },
  { value: 'monthly', label: 'Every month' },
  { value: 'quarterly', label: 'Every quarter' }
]

// Priority options
const PRIORITY_OPTIONS = [
  { value: 1, label: 'Low' },
  { value: 2, label: 'Medium' },
  { value: 3, label: 'High' },
  { value: 4, label: 'Critical' }
]

const DEFAULT_EVENT = {
  name: '',
  category: 'custom',
  date: '',
  amount: '',
  description: '',
  recurrence: 'once',
  priority: 2,
  enabled: true
}

export default function EventManager({
  events = [],
  onAddEvent,
  onEditEvent,
  onDeleteEvent,
  onToggleEvent,
  isEditable = true
}) {
  const [isFormOpen, setIsFormOpen] = useState(false)
  const [editingEvent, setEditingEvent] = useState(null)
  const [deleteEvent, setDeleteEvent] = useState(null)
  const [formData, setFormData] = useState(DEFAULT_EVENT)
  const [errors, setErrors] = useState({})
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Filter and sort events
  const sortedEvents = [...events].sort((a, b) => new Date(a.date) - new Date(b.date))
  const enabledEvents = sortedEvents.filter(e => e.enabled !== false)
  const disabledEvents = sortedEvents.filter(e => e.enabled === false)

  // Open form for adding
  const handleAddClick = () => {
    setEditingEvent(null)
    setFormData(DEFAULT_EVENT)
    setErrors({})
    setIsFormOpen(true)
  }

  // Open form for editing
  const handleEditClick = (event) => {
    setEditingEvent(event)
    setFormData({
      name: event.name || '',
      category: event.category || 'custom',
      date: event.date ? new Date(event.date).toISOString().split('T')[0] : '',
      amount: event.amount?.toString() || '',
      description: event.description || '',
      recurrence: event.recurrence || 'once',
      priority: event.priority || 2,
      enabled: event.enabled !== false
    })
    setErrors({})
    setIsFormOpen(true)
  }

  // Handle form input change
  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: null }))
    }
  }

  // Validate form
  const validateForm = () => {
    const newErrors = {}

    if (!formData.name.trim()) {
      newErrors.name = 'Event name is required'
    }

    if (!formData.date) {
      newErrors.date = 'Date is required'
    } else {
      const eventDate = new Date(formData.date)
      const today = new Date()
      today.setHours(0, 0, 0, 0)
      if (eventDate < today && formData.recurrence === 'once') {
        newErrors.date = 'Date cannot be in the past for one-time events'
      }
    }

    const amount = parseFloat(formData.amount)
    if (!formData.amount || isNaN(amount)) {
      newErrors.amount = 'Estimated cost is required'
    } else if (amount < 0) {
      newErrors.amount = 'Amount cannot be negative'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  // Handle form submit
  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!validateForm()) return

    setIsSubmitting(true)

    try {
      const eventData = {
        ...formData,
        amount: parseFloat(formData.amount),
        name: formData.name.trim(),
        description: formData.description.trim()
      }

      if (editingEvent) {
        await onEditEvent?.({ ...eventData, _id: editingEvent._id })
      } else {
        await onAddEvent?.(eventData)
      }

      setIsFormOpen(false)
      setEditingEvent(null)
      setFormData(DEFAULT_EVENT)
    } catch (error) {
      console.error('Error saving event:', error)
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle delete confirmation
  const handleDeleteConfirm = async () => {
    if (deleteEvent) {
      await onDeleteEvent?.(deleteEvent)
      setDeleteEvent(null)
    }
  }

  // Format currency
  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(amount)
  }

  // Format date
  const formatDate = (dateStr) => {
    const date = new Date(dateStr)
    return date.toLocaleDateString('en-IN', {
      day: 'numeric',
      month: 'short',
      year: 'numeric'
    })
  }

  // Get days until event
  const getDaysUntil = (dateStr) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffTime = date - now
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  }

  // Get category config
  const getCategoryConfig = (category) => {
    return EVENT_CATEGORIES.find(c => c.value === category) || EVENT_CATEGORIES[4]
  }

  // Render event card
  const renderEventCard = (event, isDisabled = false) => {
    const categoryConfig = getCategoryConfig(event.category)
    const CategoryIcon = categoryConfig.icon
    const daysUntil = getDaysUntil(event.date)

    return (
      <div
        key={event._id || event.id}
        className={`p-4 border rounded-xl transition-all ${
          isDisabled
            ? 'bg-slate-50 border-slate-200 opacity-60'
            : 'bg-white border-slate-200 hover:shadow-md'
        }`}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className={`p-2.5 rounded-xl ${categoryConfig.color}`}>
              <CategoryIcon className="h-5 w-5" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="font-semibold text-slate-900 truncate">{event.name}</h4>
                {event.recurrence !== 'once' && (
                  <Badge variant="outline" className="text-xs">
                    {RECURRENCE_OPTIONS.find(r => r.value === event.recurrence)?.label}
                  </Badge>
                )}
              </div>
              <p className="text-sm text-slate-500 mt-0.5">
                {formatDate(event.date)}
                {daysUntil > 0 && ` (${daysUntil} days away)`}
                {daysUntil <= 0 && daysUntil > -30 && ' (Recently passed)'}
              </p>
              {event.description && (
                <p className="text-sm text-slate-600 mt-1 line-clamp-1">{event.description}</p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-lg font-bold text-slate-900">
                {formatCurrency(event.amount)}
              </p>
              {event.priority >= 3 && (
                <Badge className="bg-amber-100 text-amber-700 border-0 text-xs">
                  High Priority
                </Badge>
              )}
            </div>

            {isEditable && (
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => handleEditClick(event)}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-red-600 hover:text-red-700 hover:bg-red-50"
                  onClick={() => setDeleteEvent(event)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
                <Switch
                  checked={event.enabled !== false}
                  onCheckedChange={(checked) => onToggleEvent?.(event, checked)}
                  className="ml-2"
                />
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header with Add Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-900">Custom Events</h2>
          <p className="text-sm text-slate-500">
            Add birthdays, anniversaries, vacations, and other personal expenses
          </p>
        </div>
        {isEditable && (
          <Button onClick={handleAddClick} className="bg-orange-600 hover:bg-orange-700">
            <Plus className="h-4 w-4 mr-2" />
            Add Event
          </Button>
        )}
      </div>

      {/* Events List */}
      {enabledEvents.length > 0 || disabledEvents.length > 0 ? (
        <div className="space-y-6">
          {/* Active Events */}
          {enabledEvents.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                Active Events ({enabledEvents.length})
              </h3>
              {enabledEvents.map(event => renderEventCard(event, false))}
            </div>
          )}

          {/* Disabled Events */}
          {disabledEvents.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-slate-500">
                Disabled Events ({disabledEvents.length})
              </h3>
              {disabledEvents.map(event => renderEventCard(event, true))}
            </div>
          )}
        </div>
      ) : (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Calendar className="h-12 w-12 text-slate-300 mx-auto mb-4" />
            <h3 className="font-medium text-slate-900 mb-1">No custom events yet</h3>
            <p className="text-sm text-slate-500 mb-4">
              Add personal events like birthdays, anniversaries, or vacations
            </p>
            {isEditable && (
              <Button onClick={handleAddClick} variant="outline">
                <Plus className="h-4 w-4 mr-2" />
                Add Your First Event
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Add/Edit Form Dialog */}
      <Dialog open={isFormOpen} onOpenChange={setIsFormOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingEvent ? 'Edit Event' : 'Add New Event'}
            </DialogTitle>
            <DialogDescription>
              {editingEvent
                ? 'Update your event details'
                : 'Add a custom event to your seasonal planning'
              }
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Event Name */}
            <div className="space-y-2">
              <Label htmlFor="name">Event Name *</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) => handleChange('name', e.target.value)}
                placeholder="e.g., Birthday Party, Family Vacation"
                className={errors.name ? 'border-red-500' : ''}
              />
              {errors.name && (
                <p className="text-xs text-red-500">{errors.name}</p>
              )}
            </div>

            {/* Category and Date */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="category">Category</Label>
                <Select
                  value={formData.category}
                  onValueChange={(value) => handleChange('category', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                  <SelectContent>
                    {EVENT_CATEGORIES.map((cat) => {
                      const Icon = cat.icon
                      return (
                        <SelectItem key={cat.value} value={cat.value}>
                          <div className="flex items-center gap-2">
                            <Icon className="h-4 w-4" />
                            {cat.label}
                          </div>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="date">Date *</Label>
                <Input
                  id="date"
                  type="date"
                  value={formData.date}
                  onChange={(e) => handleChange('date', e.target.value)}
                  className={errors.date ? 'border-red-500' : ''}
                />
                {errors.date && (
                  <p className="text-xs text-red-500">{errors.date}</p>
                )}
              </div>
            </div>

            {/* Amount and Recurrence */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="amount">Estimated Cost *</Label>
                <div className="relative">
                  <IndianRupee className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                  <Input
                    id="amount"
                    type="number"
                    value={formData.amount}
                    onChange={(e) => handleChange('amount', e.target.value)}
                    placeholder="25000"
                    className={`pl-9 ${errors.amount ? 'border-red-500' : ''}`}
                    min="0"
                  />
                </div>
                {errors.amount && (
                  <p className="text-xs text-red-500">{errors.amount}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="recurrence">Recurrence</Label>
                <Select
                  value={formData.recurrence}
                  onValueChange={(value) => handleChange('recurrence', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select recurrence" />
                  </SelectTrigger>
                  <SelectContent>
                    {RECURRENCE_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Priority */}
            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Select
                value={formData.priority.toString()}
                onValueChange={(value) => handleChange('priority', parseInt(value))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select priority" />
                </SelectTrigger>
                <SelectContent>
                  {PRIORITY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value.toString()}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="description">
                Description <span className="text-slate-400">(optional)</span>
              </Label>
              <Input
                id="description"
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
                placeholder="Add any notes about this event..."
                maxLength={200}
              />
            </div>

            {/* Enable/Disable */}
            <div className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
              <div>
                <Label htmlFor="enabled" className="text-sm font-medium">
                  Include in planning
                </Label>
                <p className="text-xs text-slate-500">
                  Include this event in budget calculations
                </p>
              </div>
              <Switch
                id="enabled"
                checked={formData.enabled}
                onCheckedChange={(checked) => handleChange('enabled', checked)}
              />
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-3 pt-4">
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                onClick={() => setIsFormOpen(false)}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                className="flex-1 bg-orange-600 hover:bg-orange-700"
                disabled={isSubmitting}
              >
                <Save className="h-4 w-4 mr-2" />
                {isSubmitting
                  ? 'Saving...'
                  : editingEvent
                    ? 'Update Event'
                    : 'Add Event'
                }
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteEvent} onOpenChange={() => setDeleteEvent(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Event?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteEvent?.name}&quot;?
              This will remove it from your seasonal planning.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              className="bg-red-600 hover:bg-red-700"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
