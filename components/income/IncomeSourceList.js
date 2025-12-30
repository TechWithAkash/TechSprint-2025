'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
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
import IncomeSourceCard, { normalizeToMonthly } from './IncomeSourceCard'
import IncomeSourceForm from './IncomeSourceForm'
import {
  Plus,
  Wallet,
  TrendingUp,
  PieChart,
  AlertTriangle,
  IndianRupee,
  Briefcase,
  Building2,
  Laptop
} from 'lucide-react'

// Quick add buttons for common income types
const QUICK_ADD_TYPES = [
  { type: 'salary', label: 'Salary', icon: Briefcase },
  { type: 'business', label: 'Business', icon: Building2 },
  { type: 'freelance', label: 'Freelance', icon: Laptop }
]

export default function IncomeSourceList({
  sources = [],
  onAddSource,
  onEditSource,
  onDeleteSource,
  isEditable = true,
  showSummary = true,
  showQuickAdd = true,
  maxSources = 10,
  className = ''
}) {
  const [isFormOpen, setIsFormOpen] = useState(false)
  const [editingSource, setEditingSource] = useState(null)
  const [deleteSource, setDeleteSource] = useState(null)
  const [quickAddType, setQuickAddType] = useState(null)

  // Calculate totals
  const totalMonthlyIncome = sources.reduce((sum, source) => {
    if (!source.includeInBudget) return sum
    return sum + normalizeToMonthly(source.amount, source.frequency)
  }, 0)

  const stableMonthlyIncome = sources.reduce((sum, source) => {
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

  // Handle adding new source
  const handleAddClick = (type = null) => {
    setQuickAddType(type)
    setEditingSource(null)
    setIsFormOpen(true)
  }

  // Handle editing source
  const handleEditClick = (source) => {
    setQuickAddType(null)
    setEditingSource(source)
    setIsFormOpen(true)
  }

  // Handle form submit
  const handleFormSubmit = async (data) => {
    if (editingSource) {
      await onEditSource?.({ ...data, _id: editingSource._id })
    } else {
      await onAddSource?.(data)
    }
    setIsFormOpen(false)
    setEditingSource(null)
    setQuickAddType(null)
  }

  // Handle delete confirmation
  const handleDeleteConfirm = async () => {
    if (deleteSource) {
      await onDeleteSource?.(deleteSource)
      setDeleteSource(null)
    }
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
    <div className={`space-y-4 ${className}`}>
      {/* Summary Card */}
      {showSummary && sources.length > 0 && (
        <Card className="bg-gradient-to-br from-emerald-50 to-teal-50 border-emerald-200">
          <CardContent className="p-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {/* Total Monthly */}
              <div className="text-center md:text-left">
                <p className="text-xs text-slate-600 uppercase tracking-wide">Total Monthly</p>
                <p className="text-2xl font-bold text-emerald-700">
                  {formatCurrency(totalMonthlyIncome)}
                </p>
              </div>

              {/* Stable Income */}
              <div className="text-center md:text-left">
                <p className="text-xs text-slate-600 uppercase tracking-wide">Stable</p>
                <p className="text-lg font-semibold text-blue-600">
                  {formatCurrency(stableMonthlyIncome)}
                </p>
              </div>

              {/* Variable Income */}
              <div className="text-center md:text-left">
                <p className="text-xs text-slate-600 uppercase tracking-wide">Variable</p>
                <p className="text-lg font-semibold text-orange-600">
                  {formatCurrency(variableMonthlyIncome)}
                </p>
              </div>

              {/* Stability Ratio */}
              <div className="text-center md:text-left">
                <p className="text-xs text-slate-600 uppercase tracking-wide">Stability</p>
                <div className="flex items-center gap-2">
                  <p className={`text-lg font-semibold ${
                    stabilityRatio >= 70 ? 'text-green-600' :
                    stabilityRatio >= 50 ? 'text-amber-600' :
                    'text-red-600'
                  }`}>
                    {stabilityRatio.toFixed(0)}%
                  </p>
                  {stabilityRatio < 50 && (
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                  )}
                </div>
              </div>
            </div>

            {/* Stability Warning */}
            {stabilityRatio < 50 && (
              <div className="mt-3 p-2 bg-amber-50 rounded-lg border border-amber-200">
                <p className="text-xs text-amber-700 flex items-center gap-2">
                  <AlertTriangle className="h-3 w-3" />
                  High variable income - consider building a larger emergency fund
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Income Sources List */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Wallet className="h-5 w-5 text-emerald-600" />
                Income Sources
              </CardTitle>
              <CardDescription>
                {sources.length === 0
                  ? 'Add your income sources to get started'
                  : `${sources.length} source${sources.length > 1 ? 's' : ''} added`}
              </CardDescription>
            </div>

            {isEditable && sources.length > 0 && sources.length < maxSources && (
              <Button
                size="sm"
                onClick={() => handleAddClick()}
                className="bg-emerald-600 hover:bg-emerald-700"
              >
                <Plus className="h-4 w-4 mr-1" />
                Add More
              </Button>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-3">
          {/* Empty State with Quick Add */}
          {sources.length === 0 && (
            <div className="text-center py-8 space-y-4">
              <div className="mx-auto w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center">
                <IndianRupee className="h-8 w-8 text-slate-400" />
              </div>
              <div>
                <h3 className="font-medium text-slate-900">No income sources yet</h3>
                <p className="text-sm text-slate-500 mt-1">
                  Add your income sources to create a personalized budget
                </p>
              </div>

              {/* Quick Add Buttons */}
              {showQuickAdd && isEditable && (
                <div className="flex flex-wrap justify-center gap-2 mt-4">
                  {QUICK_ADD_TYPES.map((item) => {
                    const Icon = item.icon
                    return (
                      <Button
                        key={item.type}
                        variant="outline"
                        onClick={() => handleAddClick(item.type)}
                        className="gap-2"
                      >
                        <Icon className="h-4 w-4" />
                        {item.label}
                      </Button>
                    )
                  })}
                </div>
              )}

              {isEditable && (
                <Button
                  onClick={() => handleAddClick()}
                  className="mt-2 bg-emerald-600 hover:bg-emerald-700"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Add Income Source
                </Button>
              )}
            </div>
          )}

          {/* Source Cards */}
          {sources.length > 0 && (
            <div className="space-y-3">
              {sources.map((source, index) => (
                <IncomeSourceCard
                  key={source._id || index}
                  source={source}
                  onEdit={isEditable ? handleEditClick : undefined}
                  onDelete={isEditable && sources.length > 1 ? setDeleteSource : undefined}
                  isEditable={isEditable}
                />
              ))}
            </div>
          )}

          {/* Quick Add Buttons (when sources exist) */}
          {sources.length > 0 && sources.length < maxSources && showQuickAdd && isEditable && (
            <div className="pt-3 border-t">
              <p className="text-xs text-slate-500 mb-2">Quick add:</p>
              <div className="flex flex-wrap gap-2">
                {QUICK_ADD_TYPES.map((item) => {
                  const Icon = item.icon
                  // Check if this type already exists
                  const exists = sources.some(s => s.type === item.type)
                  return (
                    <Button
                      key={item.type}
                      variant="outline"
                      size="sm"
                      onClick={() => handleAddClick(item.type)}
                      className="gap-1.5 text-xs"
                      disabled={exists}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {item.label}
                      {exists && <Badge variant="secondary" className="ml-1 text-xs">Added</Badge>}
                    </Button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Max sources reached */}
          {sources.length >= maxSources && (
            <div className="p-3 bg-slate-50 rounded-lg text-center">
              <p className="text-sm text-slate-600">
                Maximum {maxSources} income sources allowed
              </p>
            </div>
          )}
        </CardContent>
      </Card>

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

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteSource} onOpenChange={() => setDeleteSource(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Income Source?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteSource?.name}&quot;?
              This will affect your budget calculations.
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
