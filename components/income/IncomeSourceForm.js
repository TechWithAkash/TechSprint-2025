'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import {
  Briefcase,
  Building2,
  Laptop,
  Home,
  TrendingUp,
  Wallet,
  X,
  Save,
  IndianRupee,
  Info
} from 'lucide-react'

// Income type options
const INCOME_TYPES = [
  { value: 'salary', label: 'Salary', icon: Briefcase, description: 'Regular employment income' },
  { value: 'business', label: 'Business', icon: Building2, description: 'Income from your business' },
  { value: 'freelance', label: 'Freelance', icon: Laptop, description: 'Project-based or contract work' },
  { value: 'rental', label: 'Rental', icon: Home, description: 'Income from property rent' },
  { value: 'investment', label: 'Investment', icon: TrendingUp, description: 'Dividends, interest, etc.' },
  { value: 'pension', label: 'Pension', icon: Wallet, description: 'Retirement pension income' },
  { value: 'side_hustle', label: 'Side Hustle', icon: Laptop, description: 'Part-time gigs or side income' },
  { value: 'other', label: 'Other', icon: Wallet, description: 'Any other income source' }
]

// Frequency options
const FREQUENCIES = [
  { value: 'monthly', label: 'Monthly', multiplier: 1 },
  { value: 'weekly', label: 'Weekly', multiplier: 4.33 },
  { value: 'bi-weekly', label: 'Bi-weekly', multiplier: 2.17 },
  { value: 'quarterly', label: 'Quarterly', multiplier: 0.33 },
  { value: 'annually', label: 'Annually', multiplier: 0.083 },
  { value: 'irregular', label: 'Irregular', multiplier: 1 }
]

const DEFAULT_FORM_DATA = {
  name: '',
  type: 'salary',
  amount: '',
  frequency: 'monthly',
  isStable: true,
  includeInBudget: true,
  description: ''
}

export default function IncomeSourceForm({
  initialData = null,
  onSubmit,
  onCancel,
  mode = 'add' // 'add' or 'edit'
}) {
  const [formData, setFormData] = useState(DEFAULT_FORM_DATA)
  const [errors, setErrors] = useState({})
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Initialize form with existing data in edit mode
  useEffect(() => {
    if (initialData) {
      setFormData({
        name: initialData.name || '',
        type: initialData.type || 'salary',
        amount: initialData.amount?.toString() || '',
        frequency: initialData.frequency || 'monthly',
        isStable: initialData.isStable !== false,
        includeInBudget: initialData.includeInBudget !== false,
        description: initialData.description || ''
      })
    }
  }, [initialData])

  // Calculate monthly equivalent
  const getMonthlyEquivalent = () => {
    const amount = parseFloat(formData.amount) || 0
    const freq = FREQUENCIES.find(f => f.value === formData.frequency)
    return Math.round(amount * (freq?.multiplier || 1))
  }

  // Validate form
  const validateForm = () => {
    const newErrors = {}

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required'
    } else if (formData.name.length < 2) {
      newErrors.name = 'Name must be at least 2 characters'
    }

    const amount = parseFloat(formData.amount)
    if (!formData.amount || isNaN(amount)) {
      newErrors.amount = 'Amount is required'
    } else if (amount < 0) {
      newErrors.amount = 'Amount cannot be negative'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  // Handle input changes
  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    // Clear error when user types
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: null }))
    }
  }

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!validateForm()) return

    setIsSubmitting(true)

    try {
      const submitData = {
        ...formData,
        amount: parseFloat(formData.amount),
        name: formData.name.trim(),
        description: formData.description.trim()
      }

      // If editing, include the original ID
      if (initialData?._id) {
        submitData._id = initialData._id
      }

      await onSubmit?.(submitData)
    } catch (error) {
      console.error('Error submitting income source:', error)
    } finally {
      setIsSubmitting(false)
    }
  }

  // Auto-set stability based on income type
  const handleTypeChange = (type) => {
    handleChange('type', type)

    // Set default name based on type
    if (!formData.name.trim()) {
      const typeConfig = INCOME_TYPES.find(t => t.value === type)
      handleChange('name', typeConfig?.label || '')
    }

    // Set stability based on type
    const stableTypes = ['salary', 'pension', 'rental']
    handleChange('isStable', stableTypes.includes(type))
  }

  return (
    <Card className="w-full max-w-lg mx-auto">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-lg">
              {mode === 'edit' ? 'Edit Income Source' : 'Add Income Source'}
            </CardTitle>
            <CardDescription>
              {mode === 'edit'
                ? 'Update your income source details'
                : 'Add a new source of income to your profile'}
            </CardDescription>
          </div>
          {onCancel && (
            <Button variant="ghost" size="icon" onClick={onCancel}>
              <X className="h-5 w-5" />
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Income Type */}
          <div className="space-y-2">
            <Label htmlFor="type">Income Type</Label>
            <Select value={formData.type} onValueChange={handleTypeChange}>
              <SelectTrigger>
                <SelectValue placeholder="Select income type" />
              </SelectTrigger>
              <SelectContent>
                {INCOME_TYPES.map((type) => {
                  const Icon = type.icon
                  return (
                    <SelectItem key={type.value} value={type.value}>
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-slate-500" />
                        <span>{type.label}</span>
                      </div>
                    </SelectItem>
                  )
                })}
              </SelectContent>
            </Select>
            <p className="text-xs text-slate-500">
              {INCOME_TYPES.find(t => t.value === formData.type)?.description}
            </p>
          </div>

          {/* Name */}
          <div className="space-y-2">
            <Label htmlFor="name">Source Name</Label>
            <Input
              id="name"
              value={formData.name}
              onChange={(e) => handleChange('name', e.target.value)}
              placeholder="e.g., ABC Company Salary"
              className={errors.name ? 'border-red-500' : ''}
            />
            {errors.name && (
              <p className="text-xs text-red-500">{errors.name}</p>
            )}
          </div>

          {/* Amount and Frequency */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="amount">Amount</Label>
              <div className="relative">
                <IndianRupee className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  id="amount"
                  type="number"
                  value={formData.amount}
                  onChange={(e) => handleChange('amount', e.target.value)}
                  placeholder="50000"
                  className={`pl-9 ${errors.amount ? 'border-red-500' : ''}`}
                  min="0"
                />
              </div>
              {errors.amount && (
                <p className="text-xs text-red-500">{errors.amount}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="frequency">Frequency</Label>
              <Select
                value={formData.frequency}
                onValueChange={(value) => handleChange('frequency', value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select frequency" />
                </SelectTrigger>
                <SelectContent>
                  {FREQUENCIES.map((freq) => (
                    <SelectItem key={freq.value} value={freq.value}>
                      {freq.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Monthly Equivalent Preview */}
          {formData.amount && formData.frequency !== 'monthly' && (
            <div className="flex items-center gap-2 p-3 bg-emerald-50 rounded-lg border border-emerald-200">
              <Info className="h-4 w-4 text-emerald-600" />
              <span className="text-sm text-emerald-700">
                Monthly equivalent: <strong>₹{getMonthlyEquivalent().toLocaleString('en-IN')}</strong>
              </span>
            </div>
          )}

          {/* Stability Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
            <div className="space-y-1">
              <Label htmlFor="isStable" className="text-sm font-medium">
                Stable Income
              </Label>
              <p className="text-xs text-slate-500">
                Is this income consistent every month?
              </p>
            </div>
            <Switch
              id="isStable"
              checked={formData.isStable}
              onCheckedChange={(checked) => handleChange('isStable', checked)}
            />
          </div>

          {/* Include in Budget Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
            <div className="space-y-1">
              <Label htmlFor="includeInBudget" className="text-sm font-medium">
                Include in Budget
              </Label>
              <p className="text-xs text-slate-500">
                Use this income for budget calculations
              </p>
            </div>
            <Switch
              id="includeInBudget"
              checked={formData.includeInBudget}
              onCheckedChange={(checked) => handleChange('includeInBudget', checked)}
            />
          </div>

          {/* Description (Optional) */}
          <div className="space-y-2">
            <Label htmlFor="description">
              Description <span className="text-slate-400">(optional)</span>
            </Label>
            <Input
              id="description"
              value={formData.description}
              onChange={(e) => handleChange('description', e.target.value)}
              placeholder="Any additional notes..."
              maxLength={500}
            />
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-3 pt-4">
            {onCancel && (
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                onClick={onCancel}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
            )}
            <Button
              type="submit"
              className="flex-1 bg-emerald-600 hover:bg-emerald-700"
              disabled={isSubmitting}
            >
              <Save className="h-4 w-4 mr-2" />
              {isSubmitting
                ? 'Saving...'
                : mode === 'edit'
                  ? 'Update'
                  : 'Add Income Source'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}

// Export types and frequencies for reuse
export { INCOME_TYPES, FREQUENCIES }
