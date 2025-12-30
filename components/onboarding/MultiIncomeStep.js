'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogTitle,
} from '@/components/ui/dialog'
import IncomeSourceCard, { normalizeToMonthly, INCOME_TYPE_CONFIG } from '@/components/income/IncomeSourceCard'
import IncomeSourceForm from '@/components/income/IncomeSourceForm'
import {
  Plus,
  Wallet,
  Briefcase,
  Building2,
  Laptop,
  IndianRupee,
  TrendingUp,
  CheckCircle2,
  AlertTriangle,
  Sparkles
} from 'lucide-react'

// Quick add buttons for common income types
const QUICK_ADD_TYPES = [
  { type: 'salary', label: 'Salary', icon: Briefcase, description: 'Regular job income' },
  { type: 'business', label: 'Business', icon: Building2, description: 'Business earnings' },
  { type: 'freelance', label: 'Freelance', icon: Laptop, description: 'Project-based work' }
]

export default function MultiIncomeStep({ profile, setProfile }) {
  const [isFormOpen, setIsFormOpen] = useState(false)
  const [editingSource, setEditingSource] = useState(null)
  const [quickAddType, setQuickAddType] = useState(null)

  // Get income sources from profile (support both new and legacy format)
  const incomeSources = profile.incomeSources || []

  // Calculate totals
  const totalMonthlyIncome = incomeSources.reduce((sum, source) => {
    if (!source.includeInBudget) return sum
    return sum + normalizeToMonthly(source.amount, source.frequency)
  }, 0)

  const stableMonthlyIncome = incomeSources.reduce((sum, source) => {
    if (!source.includeInBudget || !source.isStable) return sum
    return sum + normalizeToMonthly(source.amount, source.frequency)
  }, 0)

  const variableMonthlyIncome = totalMonthlyIncome - stableMonthlyIncome
  const stabilityRatio = totalMonthlyIncome > 0 ? (stableMonthlyIncome / totalMonthlyIncome) * 100 : 100

  // Format currency
  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(amount)
  }

  // Handle quick add click
  const handleQuickAdd = (type) => {
    setQuickAddType(type)
    setEditingSource(null)
    setIsFormOpen(true)
  }

  // Handle add more click
  const handleAddMore = () => {
    setQuickAddType(null)
    setEditingSource(null)
    setIsFormOpen(true)
  }

  // Handle edit click
  const handleEdit = (source) => {
    setQuickAddType(null)
    setEditingSource(source)
    setIsFormOpen(true)
  }

  // Handle form submit
  const handleFormSubmit = (data) => {
    if (editingSource) {
      // Update existing source
      const updatedSources = incomeSources.map(s =>
        s._id === editingSource._id ? { ...data, _id: editingSource._id } : s
      )
      updateProfile(updatedSources)
    } else {
      // Add new source with temporary ID
      const newSource = {
        ...data,
        _id: `temp_${Date.now()}`
      }
      updateProfile([...incomeSources, newSource])
    }
    setIsFormOpen(false)
    setEditingSource(null)
    setQuickAddType(null)
  }

  // Handle delete
  const handleDelete = (source) => {
    if (incomeSources.length <= 1) return
    const updatedSources = incomeSources.filter(s => s._id !== source._id)
    updateProfile(updatedSources)
  }

  // Update profile with new income sources
  const updateProfile = (newSources) => {
    // Calculate total for legacy field
    const total = newSources.reduce((sum, source) => {
      if (!source.includeInBudget) return sum
      return sum + normalizeToMonthly(source.amount, source.frequency)
    }, 0)

    // Find primary source type
    const primarySource = newSources.reduce((primary, source) => {
      const normalizedAmount = normalizeToMonthly(source.amount, source.frequency)
      return normalizedAmount > (primary?.normalizedAmount || 0)
        ? { ...source, normalizedAmount }
        : primary
    }, null)

    setProfile(prev => ({
      ...prev,
      incomeSources: newSources,
      monthlyIncome: total,
      incomeSource: primarySource?.type || 'salary'
    }))
  }

  // Get initial data for form
  const getFormInitialData = () => {
    if (editingSource) return editingSource
    if (quickAddType) {
      return {
        type: quickAddType,
        name: '',
        isStable: quickAddType === 'salary'
      }
    }
    return null
  }

  return (
    <div className="space-y-5">
      {/* Empty State - No Sources Yet */}
      {incomeSources.length === 0 && (
        <div className="text-center py-6 space-y-4">
          <div className="mx-auto w-16 h-16 bg-emerald-100 rounded-2xl flex items-center justify-center">
            <IndianRupee className="h-8 w-8 text-emerald-600" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 text-lg">Add Your Income Sources</h3>
            <p className="text-sm text-slate-500 mt-1">
              Tell us about all your income streams for a more accurate budget
            </p>
          </div>

          {/* Quick Add Buttons */}
          <div className="flex flex-wrap justify-center gap-3 mt-6">
            {QUICK_ADD_TYPES.map((item) => {
              const Icon = item.icon
              return (
                <Button
                  key={item.type}
                  variant="outline"
                  onClick={() => handleQuickAdd(item.type)}
                  className="flex-col h-auto py-4 px-6 gap-2 hover:bg-emerald-50 hover:border-emerald-300"
                >
                  <div className="w-10 h-10 rounded-xl bg-slate-100 flex items-center justify-center">
                    <Icon className="h-5 w-5 text-slate-600" />
                  </div>
                  <span className="font-medium">{item.label}</span>
                  <span className="text-xs text-slate-500">{item.description}</span>
                </Button>
              )
            })}
          </div>
        </div>
      )}

      {/* Income Sources List */}
      {incomeSources.length > 0 && (
        <>
          {/* Summary Card */}
          <Card className="bg-gradient-to-br from-emerald-50 to-teal-50 border-emerald-200">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium text-slate-600">Total Monthly Income</span>
                <div className="flex items-center gap-2">
                  {stabilityRatio >= 70 ? (
                    <Badge className="bg-green-100 text-green-700 border-0">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Stable
                    </Badge>
                  ) : (
                    <Badge className="bg-amber-100 text-amber-700 border-0">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      Mixed
                    </Badge>
                  )}
                </div>
              </div>

              <p className="text-3xl font-bold text-emerald-700 mb-3">
                {formatCurrency(totalMonthlyIncome)}
              </p>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-500">Stable Income</span>
                  <p className="font-semibold text-blue-600">{formatCurrency(stableMonthlyIncome)}</p>
                </div>
                <div>
                  <span className="text-slate-500">Variable Income</span>
                  <p className="font-semibold text-orange-600">{formatCurrency(variableMonthlyIncome)}</p>
                </div>
              </div>

              {/* Stability Warning */}
              {stabilityRatio < 50 && (
                <div className="mt-3 p-2 bg-amber-50 rounded-lg border border-amber-200">
                  <p className="text-xs text-amber-700 flex items-center gap-2">
                    <AlertTriangle className="h-3 w-3 shrink-0" />
                    With high variable income, we&apos;ll recommend a larger emergency fund
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Source Cards */}
          <div className="space-y-3">
            {incomeSources.map((source, index) => (
              <IncomeSourceCard
                key={source._id || index}
                source={source}
                onEdit={handleEdit}
                onDelete={incomeSources.length > 1 ? handleDelete : undefined}
                isEditable={true}
                compact={false}
              />
            ))}
          </div>

          {/* Add More Section */}
          {incomeSources.length < 10 && (
            <div className="pt-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm text-slate-500">Add more:</span>
                {QUICK_ADD_TYPES.map((item) => {
                  const Icon = item.icon
                  const exists = incomeSources.some(s => s.type === item.type)
                  return (
                    <Button
                      key={item.type}
                      variant="outline"
                      size="sm"
                      onClick={() => handleQuickAdd(item.type)}
                      className="gap-1.5 h-8 text-xs"
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {item.label}
                      {exists && <span className="text-slate-400">(+1)</span>}
                    </Button>
                  )
                })}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleAddMore}
                  className="gap-1.5 h-8 text-xs text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Other
                </Button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Info Box */}
      <div className="bg-blue-50 border border-blue-100 rounded-xl p-3">
        <div className="flex gap-2.5">
          <div className="flex-shrink-0 w-6 h-6 bg-blue-500 rounded-lg flex items-center justify-center">
            <Sparkles className="h-3.5 w-3.5 text-white" />
          </div>
          <div>
            <p className="text-xs font-medium text-blue-900 mb-0.5">Why multiple income sources?</p>
            <p className="text-[11px] text-blue-700 leading-snug">
              Adding all your income streams helps us create a more accurate budget.
              We&apos;ll adjust savings recommendations based on income stability.
            </p>
          </div>
        </div>
      </div>

      {/* Add/Edit Form Dialog */}
      <Dialog open={isFormOpen} onOpenChange={setIsFormOpen}>
        <DialogContent className="sm:max-w-lg p-0">
          <DialogTitle className="sr-only">
            {editingSource ? 'Edit Income Source' : 'Add Income Source'}
          </DialogTitle>
          <IncomeSourceForm
            initialData={getFormInitialData()}
            onSubmit={handleFormSubmit}
            onCancel={() => setIsFormOpen(false)}
            mode={editingSource ? 'edit' : 'add'}
          />
        </DialogContent>
      </Dialog>
    </div>
  )
}
