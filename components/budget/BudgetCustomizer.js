'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Slider } from '@/components/ui/slider'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Save,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  AlertCircle,
  CheckCircle,
  DollarSign,
  PieChart,
  BarChart3,
  Percent,
  Calculator,
  Eye,
  EyeOff,
  AlertTriangle,
  RotateCcw
} from 'lucide-react'
import toast from 'react-hot-toast'
import { useTranslation } from '@/lib/i18n'

export default function BudgetCustomizer({ budget, onSave, onCancel }) {
  const { t } = useTranslation()
  const [customBudget, setCustomBudget] = useState(null)
  const [totalAllocated, setTotalAllocated] = useState(0)
  const [showPercentages, setShowPercentages] = useState(false)
  const [isBalanced, setIsBalanced] = useState(true)
  const [originalBudget, setOriginalBudget] = useState(null)
  const [saving, setSaving] = useState(false)

  const calculateTotals = useCallback((categories) => {
    if (!categories) {
      console.warn('calculateTotals called with no categories')
      return
    }

    console.log('Calculating totals for categories:', categories)
    const total = Object.values(categories).reduce((sum, category) => {
      console.log(`Category: ${category.englishName || 'unknown'}, Amount: ${category.amount || 0}`)
      return sum + (category.amount || 0)
    }, 0)

    const budgetTotal = budget?.totalBudget || budget?.monthlyIncome || 50000
    const difference = Math.abs(total - budgetTotal)
    const balanced = difference <= 5000 || (difference / budgetTotal) <= 0.1 // Allow ₹5000 or 10% difference

    console.log('Budget calculation:', {
      total,
      budgetTotal,
      difference,
      balanced,
      percentageDiff: ((difference / budgetTotal) * 100).toFixed(2) + '%'
    })

    setTotalAllocated(total)
    setIsBalanced(balanced)
  }, [budget])

  useEffect(() => {
    console.log('BudgetCustomizer received budget:', budget)
    if (budget && budget.categories) {
      console.log('Budget categories:', Object.keys(budget.categories))
      const budgetCopy = JSON.parse(JSON.stringify(budget))
      setCustomBudget(budgetCopy)
      setOriginalBudget(JSON.parse(JSON.stringify(budget)))
      calculateTotals(budgetCopy.categories)
    } else {
      console.error('Budget or categories missing:', { budget, hasCategories: !!budget?.categories })
    }
  }, [budget, calculateTotals])

  const updateCategoryAmount = (categoryKey, newAmount) => {
    if (!customBudget) return

    const updatedCategories = { ...customBudget.categories }
    const totalBudget = budget?.totalBudget || budget?.monthlyIncome || 50000

    // Update amount
    updatedCategories[categoryKey] = {
      ...updatedCategories[categoryKey],
      amount: newAmount,
      percentage: Math.round((newAmount / totalBudget) * 100)
    }

    const updatedBudget = {
      ...customBudget,
      categories: updatedCategories
    }

    setCustomBudget(updatedBudget)
    calculateTotals(updatedCategories)
  }

  const updateCategoryPercentage = (categoryKey, newPercentage) => {
    if (!customBudget) return

    const updatedCategories = { ...customBudget.categories }
    const totalBudget = budget?.totalBudget || budget?.monthlyIncome || 50000
    const newAmount = Math.round((newPercentage / 100) * totalBudget)

    updatedCategories[categoryKey] = {
      ...updatedCategories[categoryKey],
      amount: newAmount,
      percentage: newPercentage
    }

    const updatedBudget = {
      ...customBudget,
      categories: updatedCategories
    }

    setCustomBudget(updatedBudget)
    calculateTotals(updatedCategories)
  }

  const autoBalance = () => {
    if (!customBudget) return

    const totalBudget = budget?.totalBudget || budget?.monthlyIncome || 50000
    const difference = totalBudget - totalAllocated

    console.log('Auto-balancing:', { totalBudget, totalAllocated, difference })

    if (Math.abs(difference) <= 1000) {
      toast.info(t('budget.alreadyBalanced'))
      return
    }

    const categories = { ...customBudget.categories }

    if (difference > 0) {
      // Need to add more allocation - distribute proportionally
      const totalCurrent = totalAllocated
      const factor = totalBudget / totalCurrent

      Object.keys(categories).forEach(key => {
        categories[key].amount = Math.round(categories[key].amount * factor)
        categories[key].percentage = Math.round((categories[key].amount / totalBudget) * 100)
      })
    } else {
      // Need to reduce allocation - reduce proportionally
      const totalCurrent = totalAllocated
      const factor = totalBudget / totalCurrent

      Object.keys(categories).forEach(key => {
        categories[key].amount = Math.round(categories[key].amount * factor)
        categories[key].percentage = Math.round((categories[key].amount / totalBudget) * 100)
      })
    }

    setCustomBudget({ ...customBudget, categories })
    calculateTotals(categories)
    toast.success(t('budget.autoBalanced'))
  }

  const resetToOriginal = () => {
    if (originalBudget) {
      setCustomBudget(JSON.parse(JSON.stringify(originalBudget)))
      calculateTotals(originalBudget.categories)
      toast.info(t('budget.resetToOriginal'))
    }
  }

  const handleSave = async () => {
    console.log('Save button clicked', {
      isBalanced,
      totalAllocated,
      budgetTotal: budget?.totalBudget || budget?.monthlyIncome,
      customBudget: !!customBudget
    })

    if (!customBudget) {
      toast.error(t('budget.noBudgetData'))
      return
    }

    if (!isBalanced) {
      const totalBudget = budget?.totalBudget || budget?.monthlyIncome || 50000
      const difference = Math.abs(totalBudget - totalAllocated)
      toast.error(`Please balance your budget first. Difference: ₹${difference.toLocaleString('en-IN')}`)
      return
    }

    setSaving(true)
    try {
      // Ensure budget has totalBudget field
      const customizedBudget = {
        ...customBudget,
        totalBudget: budget?.totalBudget || budget?.monthlyIncome || totalAllocated,
        isCustomized: true,
        customizedAt: new Date().toISOString(),
        originalBudget: originalBudget
      }

      console.log('Calling onSave with:', customizedBudget)
      await onSave(customizedBudget)
      console.log('onSave completed successfully')
      toast.success(t('budget.savedSuccessfully'))
    } catch (error) {
      console.error('Save error:', error)
      toast.error(`Failed to save budget: ${error.message}`)
    } finally {
      setSaving(false)
    }
  }

  const getBudgetHealthStatus = () => {
    if (!customBudget) return { status: 'unknown', message: '', color: 'gray' }

    const totalBudget = budget.totalBudget
    const savingsPercentage = (customBudget.categories.savings?.percentage || 0)
    const essentialCategories = ['food', 'housing', 'healthcare', 'utilities']
    const essentialPercentage = essentialCategories.reduce((sum, cat) =>
      sum + (customBudget.categories[cat]?.percentage || 0), 0)

    if (savingsPercentage < 10) {
      return {
        status: 'warning',
        message: t('budget.health.increaseSavings'),
        color: 'orange'
      }
    }

    if (essentialPercentage < 50) {
      return {
        status: 'good',
        message: t('budget.health.greatBalance'),
        color: 'green'
      }
    }

    if (essentialPercentage > 80) {
      return {
        status: 'concern',
        message: t('budget.health.highEssentials'),
        color: 'red'
      }
    }

    return {
      status: 'good',
      message: t('budget.health.wellBalanced'),
      color: 'green'
    }
  }

  if (!customBudget) {
    return (
      <Card>
        <CardContent className="p-6 text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500 mx-auto"></div>
          <p className="mt-2 text-gray-500">{t('budget.loadingCustomizer')}</p>
          <div className="mt-4 text-xs text-gray-400">
            Debug: Budget={!!budget}, Categories={!!budget?.categories}, TotalBudget={budget?.totalBudget}
          </div>
        </CardContent>
      </Card>
    )
  }

  const budgetHealth = getBudgetHealthStatus()
  const totalBudget = budget?.totalBudget || budget?.monthlyIncome || 50000 // Fallback values
  const difference = totalBudget - totalAllocated

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <CardTitle className="text-xl font-bold text-slate-800">
                🎯 {t('Customize Title')}
              </CardTitle>
              <CardDescription>
                {t('Customize Description')}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowPercentages(!showPercentages)}
              >
                {showPercentages ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
                {showPercentages ? t('Show Amounts') : t('Show Percentages')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {/* Budget Status */}
          <div className="bg-gradient-to-r from-slate-50 to-emerald-50 rounded-lg p-4 mb-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
              <div>
                <p className="text-sm text-slate-600">{t('Monthly Income')}</p>
                <p className="text-2xl font-bold text-slate-800">
                  ₹{totalBudget.toLocaleString('en-IN')}
                </p>
              </div>
              <div>
                <p className="text-sm text-slate-600">{t('Total Allocated')}</p>
                <p className={`text-2xl font-bold ${isBalanced ? 'text-emerald-600' : 'text-red-600'}`}>
                  ₹{totalAllocated.toLocaleString('en-IN')}
                </p>
              </div>
              <div>
                <p className="text-sm text-slate-600">{t('Budget Difference')}</p>
                <p className={`text-lg font-bold ${Math.abs(difference) <= 500 ? 'text-emerald-600' : 'text-red-600'}`}>
                  {difference > 0 ? '+' : ''}₹{difference.toLocaleString('en-IN')}
                </p>
              </div>
            </div>

            {!isBalanced && (
              <div className="mt-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-orange-600">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="text-sm">
                    Budget needs balancing (₹{Math.abs(difference).toLocaleString('en-IN')} {difference > 0 ? 'over' : 'under'})
                    <br />
                    <span className="text-xs text-gray-500">
                      Allocated: ₹{totalAllocated.toLocaleString('en-IN')} / Budget: ₹{totalBudget.toLocaleString('en-IN')}
                    </span>
                  </span>
                </div>
                <Button onClick={autoBalance} size="sm" variant="outline">
                  Auto Balance
                </Button>
              </div>
            )}
          </div>

          {/* Budget Health */}
          <div className="flex items-center gap-2 mb-4">
            {budgetHealth.status === 'good' && <CheckCircle className="h-5 w-5 text-green-500" />}
            {budgetHealth.status === 'warning' && <AlertTriangle className="h-5 w-5 text-orange-500" />}
            {budgetHealth.status === 'concern' && <AlertTriangle className="h-5 w-5 text-red-500" />}
            <span className={`text-sm font-medium text-${budgetHealth.color}-600`}>
              {budgetHealth.message}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Category Customization */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-bold text-slate-800">
            {t('Adjust Categories')}
          </CardTitle>
          <CardDescription>
            {t('Modify Amounts')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {Object.entries(customBudget.categories).map(([categoryKey, category]) => {
              const originalAmount = originalBudget.categories[categoryKey]?.amount || 0
              const currentAmount = category.amount
              const isChanged = Math.abs(originalAmount - currentAmount) > 50

              return (
                <div key={categoryKey} className="border rounded-lg p-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{category.emoji}</span>
                      <div>
                        <h3 className="font-medium text-slate-800">{category.englishName}</h3>
                        <p className="text-sm text-slate-500">{category.hinglishName}</p>
                      </div>
                      {isChanged && (
                        <Badge variant={currentAmount > originalAmount ? "default" : "secondary"}>
                          {currentAmount > originalAmount ? (
                            <TrendingUp className="h-3 w-3 mr-1" />
                          ) : (
                            <TrendingDown className="h-3 w-3 mr-1" />
                          )}
                          {currentAmount > originalAmount ? t('Increased') : t('Decreased')}
                        </Badge>
                      )}
                    </div>
                    <div className="text-right">
                      <p className="font-bold text-slate-800">
                        ₹{category.amount.toLocaleString('en-IN')}
                      </p>
                      <p className="text-sm text-slate-500">{category.percentage}%</p>
                    </div>
                  </div>

                  {/* Amount Slider */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium text-slate-700">
                        {showPercentages ? t('Percentage') : t('Amount')}
                      </label>
                      <div className="flex items-center gap-2">
                        {showPercentages ? (
                          <div className="flex items-center gap-1">
                            <Input
                              type="number"
                              min="0"
                              max="100"
                              value={category.percentage}
                              onChange={(e) => updateCategoryPercentage(categoryKey, parseInt(e.target.value) || 0)}
                              className="w-16 h-8 text-xs"
                            />
                            <Percent className="h-3 w-3 text-slate-400" />
                          </div>
                        ) : (
                          <div className="flex items-center gap-1">
                            <DollarSign className="h-3 w-3 text-slate-400" />
                            <Input
                              type="number"
                              min="0"
                              max={totalBudget}
                              value={category.amount}
                              onChange={(e) => updateCategoryAmount(categoryKey, parseInt(e.target.value) || 0)}
                              className="w-24 h-8 text-xs"
                            />
                          </div>
                        )}
                      </div>
                    </div>

                    <Slider
                      value={[showPercentages ? category.percentage : category.amount]}
                      max={showPercentages ? 100 : totalBudget}
                      min={0}
                      step={showPercentages ? 1 : 100}
                      onValueChange={([value]) => {
                        if (showPercentages) {
                          updateCategoryPercentage(categoryKey, value)
                        } else {
                          updateCategoryAmount(categoryKey, value)
                        }
                      }}
                      className="w-full"
                    />
                    <div className="flex justify-between text-xs text-slate-500">
                      <span>0{showPercentages ? '%' : ''}</span>
                      <span>{category.percentage}% of total budget</span>
                      <span>{showPercentages ? '100%' : `₹${totalBudget.toLocaleString('en-IN')}`}</span>
                    </div>
                  </div>

                  {/* Original vs Current Comparison */}
                  {isChanged && (
                    <div className="text-xs text-slate-500 bg-slate-50 p-2 rounded">
                      Original: ₹{originalAmount.toLocaleString('en-IN')} ({Math.round((originalAmount / totalBudget) * 100)}%)
                      {currentAmount > originalAmount ? ' → +' : ' → -'}₹{Math.abs(currentAmount - originalAmount).toLocaleString('en-IN')}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <div className="flex flex-col sm:flex-row gap-3 justify-end">
        <Button variant="outline" onClick={onCancel}>
          {t('Cancel')}
        </Button>
        <Button variant="outline" onClick={resetToOriginal}>
          <RotateCcw className="h-4 w-4 mr-2" />
          {t('Reset to Original')}
        </Button>
        <Button
          onClick={handleSave}
          disabled={!isBalanced || saving}
          className="bg-emerald-600 hover:bg-emerald-700"
        >
          {saving ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
              {t('Saving...')}
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              {t('Save Custom Budget')}
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
