'use client'

import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import ExpenseEntryModal from '@/components/expenses/ExpenseEntryModal'
import {
  Wallet,
  Plus,
  Search,
  Download,
  IndianRupee,
  Mic,
  Sparkles,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Trash2,
  Calendar,
  TrendingDown,
  Receipt,
  X
} from 'lucide-react'
import toast from 'react-hot-toast'
import AIInsightsModal from '@/components/expenses/AIInsightsModal'

const ITEMS_PER_PAGE = 8

// Category icons and colors
const categoryConfig = {
  'Food & Dining': { color: 'bg-orange-100 text-orange-700', icon: '🍽️' },
  'Transportation': { color: 'bg-blue-100 text-blue-700', icon: '🚗' },
  'Housing': { color: 'bg-purple-100 text-purple-700', icon: '🏠' },
  'Entertainment': { color: 'bg-pink-100 text-pink-700', icon: '🎬' },
  'Healthcare': { color: 'bg-red-100 text-red-700', icon: '🏥' },
  'Shopping': { color: 'bg-emerald-100 text-emerald-700', icon: '🛍️' },
  'Utilities': { color: 'bg-yellow-100 text-yellow-700', icon: '⚡' },
  'Other': { color: 'bg-slate-100 text-slate-700', icon: '📦' }
}

function ExpensesContent() {
  const { t } = useTranslation()
  const [expenses, setExpenses] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const [expandedExpense, setExpandedExpense] = useState(null)

  // Form state
  const [showForm, setShowForm] = useState(false)
  const [showVoiceEntry, setShowVoiceEntry] = useState(false)
  const [formData, setFormData] = useState({
    amount: '',
    category: '',
    description: '',
    date: new Date().toISOString().split('T')[0]
  })
  const [submitting, setSubmitting] = useState(false)
  const [showInsightsModal, setShowInsightsModal] = useState(false)

  const categories = [
    { key: 'food', value: 'Food & Dining' },
    { key: 'transportation', value: 'Transportation' },
    { key: 'housing', value: 'Housing' },
    { key: 'entertainment', value: 'Entertainment' },
    { key: 'healthcare', value: 'Healthcare' },
    { key: 'shopping', value: 'Shopping' },
    { key: 'utilities', value: 'Utilities' },
    { key: 'other', value: 'Other' }
  ]

  useEffect(() => {
    fetchExpenses()
  }, [])

  const fetchExpenses = async () => {
    try {
      const response = await fetch('/api/expenses')
      const data = await response.json()
      if (data.success) {
        setExpenses(data.expenses || [])
      }
    } catch (error) {
      console.error('Failed to fetch expenses:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleExpenseAdded = (expense) => {
    setExpenses(prev => [expense, ...prev])
    toast.success('Expense added successfully!')
    setShowVoiceEntry(false)
    setShowForm(false)
    setCurrentPage(1)
  }

  const handleFormSubmit = async (e) => {
    e.preventDefault()
    if (!formData.amount || !formData.category) {
      toast.error('Please fill in required fields')
      return
    }

    setSubmitting(true)
    try {
      const response = await fetch('/api/expenses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          amount: parseFloat(formData.amount),
          entryMethod: 'manual'
        })
      })

      const data = await response.json()
      if (data.success) {
        handleExpenseAdded(data.expense)
        setFormData({
          amount: '',
          category: '',
          description: '',
          date: new Date().toISOString().split('T')[0]
        })
      } else {
        toast.error(data.error || 'Failed to add expense')
      }
    } catch (error) {
      toast.error('Failed to add expense')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeleteExpense = async (expenseId) => {
    if (!confirm(t('expenses.deleteConfirm'))) return
    try {
      const res = await fetch(`/api/expenses?id=${expenseId}`, { method: 'DELETE' })
      const data = await res.json()
      if (data.success) {
        setExpenses(prev => prev.filter(e => e.id !== expenseId))
        toast.success(t('expenses.deleted'))
      } else {
        toast.error(data.error || 'Failed to delete')
      }
    } catch (err) {
      toast.error('Failed to delete expense')
    }
  }

  // Filtered and paginated expenses
  const filteredExpenses = useMemo(() => {
    return expenses.filter(expense => {
      const matchesSearch =
        (expense.description?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
        (expense.category?.toLowerCase() || '').includes(searchTerm.toLowerCase())
      const matchesCategory = selectedCategory === 'all' || expense.category === selectedCategory
      return matchesSearch && matchesCategory
    })
  }, [expenses, searchTerm, selectedCategory])

  const totalPages = Math.ceil(filteredExpenses.length / ITEMS_PER_PAGE)
  const paginatedExpenses = useMemo(() => {
    const start = (currentPage - 1) * ITEMS_PER_PAGE
    return filteredExpenses.slice(start, start + ITEMS_PER_PAGE)
  }, [filteredExpenses, currentPage])

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchTerm, selectedCategory])

  // Stats
  const totalExpenses = expenses.reduce((sum, e) => sum + e.amount, 0)
  const thisMonthExpenses = expenses.filter(e => {
    const expenseMonth = new Date(e.date).toISOString().substring(0, 7)
    const currentMonth = new Date().toISOString().substring(0, 7)
    return expenseMonth === currentMonth
  }).reduce((sum, e) => sum + e.amount, 0)

  const handleExport = async () => {
    if (expenses.length === 0) {
      toast.error('No expenses to export')
      return
    }
    try {
      const xlsx = await import('xlsx')
      const rows = expenses.map(e => ({
        Date: e.date,
        Category: e.category,
        Amount: e.amount,
        Description: e.description || '',
        Method: e.entryMethod || 'manual'
      }))
      const ws = xlsx.utils.json_to_sheet(rows)
      const wb = xlsx.utils.book_new()
      xlsx.utils.book_append_sheet(wb, ws, 'Expenses')
      const wbout = xlsx.write(wb, { bookType: 'xlsx', type: 'array' })
      const blob = new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `expenses_${new Date().toISOString().split('T')[0]}.xlsx`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success('Exported successfully')
    } catch (err) {
      toast.error('Export failed')
    }
  }

  const getCategoryStyle = (category) => {
    return categoryConfig[category] || categoryConfig['Other']
  }

  return (
    <DashboardLayout title={t('expenses.title')}>
      <div className="space-y-4 lg:space-y-6 max-w-6xl mx-auto">

        {/* Compact Header with Stats */}
        <div className="flex flex-col gap-4">
          {/* Stats Row - Horizontal on mobile */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-red-100 flex items-center justify-center">
                  <TrendingDown className="w-4 h-4 text-red-600" />
                </div>
                <span className="text-xs text-slate-500 hidden sm:inline">{t('expenses.thisMonth')}</span>
              </div>
              <p className="text-lg sm:text-xl font-bold text-red-600">
                ₹{loading ? '...' : thisMonthExpenses.toLocaleString('en-IN')}
              </p>
              <p className="text-xs text-slate-400 sm:hidden">{t('expenses.thisMonth')}</p>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
                  <Wallet className="w-4 h-4 text-blue-600" />
                </div>
                <span className="text-xs text-slate-500 hidden sm:inline">{t('expenses.total')}</span>
              </div>
              <p className="text-lg sm:text-xl font-bold text-blue-600">
                ₹{loading ? '...' : totalExpenses.toLocaleString('en-IN')}
              </p>
              <p className="text-xs text-slate-400 sm:hidden">{t('expenses.total')}</p>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-3 sm:p-4">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center">
                  <Receipt className="w-4 h-4 text-emerald-600" />
                </div>
                <span className="text-xs text-slate-500 hidden sm:inline">{t('common.transactions')}</span>
              </div>
              <p className="text-lg sm:text-xl font-bold text-emerald-600">
                {loading ? '...' : expenses.length}
              </p>
              <p className="text-xs text-slate-400 sm:hidden">Entries</p>
            </div>
          </div>

          {/* Action Buttons Row */}
          <div className="flex flex-wrap items-center gap-2">
            <Button
              onClick={() => setShowVoiceEntry(true)}
              size="sm"
              className="bg-blue-600 hover:bg-blue-700 text-white h-9"
            >
              <Mic className="w-4 h-4 mr-1.5" />
              <span className="hidden sm:inline">{t('expenses.voiceEntry')}</span>
              <span className="sm:hidden">Voice</span>
            </Button>
            <Button
              onClick={() => setShowForm(!showForm)}
              size="sm"
              variant={showForm ? "secondary" : "default"}
              className={showForm ? "bg-slate-200" : "bg-emerald-600 hover:bg-emerald-700 text-white h-9"}
            >
              {showForm ? <X className="w-4 h-4 mr-1.5" /> : <Plus className="w-4 h-4 mr-1.5" />}
              <span className="hidden sm:inline">{showForm ? 'Close' : t('expenses.manualEntry')}</span>
              <span className="sm:hidden">{showForm ? 'Close' : 'Add'}</span>
            </Button>

            <div className="flex-1" />

            <Button
              onClick={() => setShowInsightsModal(true)}
              variant="outline"
              size="sm"
              className="h-9 border-purple-200 text-purple-700 hover:bg-purple-50"
            >
              <Sparkles className="w-4 h-4 mr-1.5" />
              <span className="hidden sm:inline">AI Insights</span>
              <span className="sm:hidden">AI</span>
            </Button>
            <Button onClick={handleExport} variant="outline" size="sm" className="h-9">
              <Download className="w-4 h-4 sm:mr-1.5" />
              <span className="hidden sm:inline">{t('common.export')}</span>
            </Button>
          </div>
        </div>

        {/* Collapsible Add Expense Form */}
        {showForm && (
          <Card className="border-emerald-200 bg-emerald-50/30">
            <CardContent className="p-4">
              <form onSubmit={handleFormSubmit} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div>
                    <label className="text-xs font-medium text-slate-600 mb-1 block">
                      {t('expenses.amount')} *
                    </label>
                    <div className="relative">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">₹</span>
                      <Input
                        type="number"
                        step="0.01"
                        min="0"
                        value={formData.amount}
                        onChange={(e) => setFormData(prev => ({ ...prev, amount: e.target.value }))}
                        placeholder="0.00"
                        className="pl-7 h-10 bg-white"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-xs font-medium text-slate-600 mb-1 block">
                      {t('expenses.category')} *
                    </label>
                    <Select
                      value={formData.category}
                      onValueChange={(value) => setFormData(prev => ({ ...prev, category: value }))}
                    >
                      <SelectTrigger className="h-10 bg-white">
                        <SelectValue placeholder="Select..." />
                      </SelectTrigger>
                      <SelectContent>
                        {categories.map(cat => (
                          <SelectItem key={cat.key} value={cat.value}>
                            {categoryConfig[cat.value]?.icon} {cat.value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <label className="text-xs font-medium text-slate-600 mb-1 block">
                      {t('expenses.date')}
                    </label>
                    <Input
                      type="date"
                      value={formData.date}
                      onChange={(e) => setFormData(prev => ({ ...prev, date: e.target.value }))}
                      className="h-10 bg-white"
                    />
                  </div>

                  <div>
                    <label className="text-xs font-medium text-slate-600 mb-1 block">
                      {t('expenses.description')}
                    </label>
                    <Input
                      value={formData.description}
                      onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                      placeholder={t('expenses.descriptionPlaceholder')}
                      className="h-10 bg-white"
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => setShowForm(false)}>
                    {t('common.cancel')}
                  </Button>
                  <Button
                    type="submit"
                    size="sm"
                    disabled={submitting}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    {submitting ? (
                      <>
                        <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                        Adding...
                      </>
                    ) : (
                      <>
                        <Plus className="w-4 h-4 mr-1" />
                        {t('expenses.addExpense')}
                      </>
                    )}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Search and Filter */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <Input
              placeholder={t('expenses.searchPlaceholder')}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 h-10 bg-white"
            />
          </div>
          <Select value={selectedCategory} onValueChange={setSelectedCategory}>
            <SelectTrigger className="w-full sm:w-44 h-10 bg-white">
              <SelectValue placeholder={t('expenses.allCategories')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('expenses.allCategories')}</SelectItem>
              {categories.map(cat => (
                <SelectItem key={cat.key} value={cat.value}>
                  {categoryConfig[cat.value]?.icon} {cat.value}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Expenses List */}
        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <div className="w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
                <span className="ml-3 text-sm text-slate-500">{t('common.loading')}</span>
              </div>
            ) : filteredExpenses.length === 0 ? (
              <div className="text-center py-16 px-4">
                <Wallet className="w-12 h-12 text-slate-200 mx-auto mb-3" />
                <p className="text-slate-600 font-medium mb-1">
                  {expenses.length === 0 ? t('expenses.noExpenses') : t('expenses.noResults')}
                </p>
                <p className="text-sm text-slate-400 mb-4">
                  {expenses.length === 0 ? t('expenses.noExpensesDesc') : t('expenses.noResultsDesc')}
                </p>
                {expenses.length === 0 && (
                  <Button onClick={() => setShowForm(true)} size="sm" className="bg-emerald-600 hover:bg-emerald-700 text-white">
                    <Plus className="w-4 h-4 mr-1" /> Add First Expense
                  </Button>
                )}
              </div>
            ) : (
              <>
                {/* List Header - Desktop */}
                <div className="hidden sm:grid grid-cols-12 gap-4 px-4 py-3 bg-slate-50 border-b text-xs font-medium text-slate-500 uppercase tracking-wide">
                  <div className="col-span-5">Description</div>
                  <div className="col-span-2">Category</div>
                  <div className="col-span-2">Date</div>
                  <div className="col-span-2 text-right">Amount</div>
                  <div className="col-span-1"></div>
                </div>

                {/* Expense Items */}
                <div className="divide-y divide-slate-100">
                  {paginatedExpenses.map((expense) => {
                    const catStyle = getCategoryStyle(expense.category)
                    const isExpanded = expandedExpense === expense.id
                    const isVoice = expense.entryMethod === 'voice'

                    return (
                      <div key={expense.id} className="group">
                        {/* Main Row */}
                        <div className="px-4 py-3 hover:bg-slate-50/50 transition-colors">
                          {/* Mobile Layout */}
                          <div className="sm:hidden">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="text-lg">{catStyle.icon}</span>
                                  <p className="font-medium text-slate-800 truncate text-sm">
                                    {expense.description || expense.category}
                                  </p>
                                  {isVoice && (
                                    <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4 bg-blue-100 text-blue-700">
                                      🎤
                                    </Badge>
                                  )}
                                </div>
                                <div className="flex items-center gap-2 text-xs text-slate-400">
                                  <span>{expense.category}</span>
                                  <span>•</span>
                                  <span>{new Date(expense.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })}</span>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <p className="font-semibold text-red-600">
                                  -₹{expense.amount.toLocaleString('en-IN')}
                                </p>
                                {isVoice && expense.originalText && (
                                  <button
                                    onClick={() => setExpandedExpense(isExpanded ? null : expense.id)}
                                    className="p-1 text-slate-400 hover:text-slate-600"
                                  >
                                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                                  </button>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Desktop Layout */}
                          <div className="hidden sm:grid grid-cols-12 gap-4 items-center">
                            <div className="col-span-5 flex items-center gap-3 min-w-0">
                              <span className="text-xl flex-shrink-0">{catStyle.icon}</span>
                              <div className="min-w-0">
                                <p className="font-medium text-slate-800 truncate">
                                  {expense.description || `${expense.category} expense`}
                                </p>
                                {isVoice && (
                                  <button
                                    onClick={() => setExpandedExpense(isExpanded ? null : expense.id)}
                                    className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1 mt-0.5"
                                  >
                                    🎤 Voice entry
                                    {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                  </button>
                                )}
                              </div>
                            </div>
                            <div className="col-span-2">
                              <Badge variant="secondary" className={`text-xs ${catStyle.color}`}>
                                {expense.category}
                              </Badge>
                            </div>
                            <div className="col-span-2 text-sm text-slate-500">
                              {new Date(expense.date).toLocaleDateString('en-IN', {
                                day: 'numeric',
                                month: 'short',
                                year: 'numeric'
                              })}
                            </div>
                            <div className="col-span-2 text-right">
                              <p className="font-semibold text-red-600">
                                -₹{expense.amount.toLocaleString('en-IN')}
                              </p>
                            </div>
                            <div className="col-span-1 flex justify-end">
                              <button
                                onClick={() => handleDeleteExpense(expense.id)}
                                className="p-1.5 rounded-lg text-slate-300 hover:text-red-500 hover:bg-red-50 opacity-0 group-hover:opacity-100 transition-all"
                                title="Delete"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </div>
                        </div>

                        {/* Expanded Voice Details */}
                        {isExpanded && isVoice && expense.originalText && (
                          <div className="px-4 pb-3">
                            <div className="ml-0 sm:ml-9 p-3 bg-blue-50 rounded-lg border border-blue-100">
                              <p className="text-xs text-blue-600 font-medium mb-1">{t('expenses.voiceDetails')}:</p>
                              <p className="text-sm text-blue-800 italic">&quot;{expense.originalText}&quot;</p>
                              {expense.confidence && (
                                <p className="text-xs text-blue-500 mt-1.5">
                                  {t('expenses.confidence')}: {Math.round(expense.confidence * 100)}%
                                </p>
                              )}
                            </div>
                            {/* Mobile Delete Button */}
                            <div className="sm:hidden mt-2 flex justify-end">
                              <button
                                onClick={() => handleDeleteExpense(expense.id)}
                                className="text-xs text-red-500 hover:text-red-600 flex items-center gap-1"
                              >
                                <Trash2 className="w-3 h-3" /> Delete
                              </button>
                            </div>
                          </div>
                        )}

                        {/* Mobile Delete - swipe hint */}
                        {!isExpanded && (
                          <div className="sm:hidden px-4 pb-2">
                            <button
                              onClick={() => handleDeleteExpense(expense.id)}
                              className="text-xs text-slate-400 hover:text-red-500 flex items-center gap-1"
                            >
                              <Trash2 className="w-3 h-3" /> Delete
                            </button>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between px-4 py-3 border-t bg-slate-50">
                    <p className="text-sm text-slate-500">
                      {t('common.showing')} {((currentPage - 1) * ITEMS_PER_PAGE) + 1}-{Math.min(currentPage * ITEMS_PER_PAGE, filteredExpenses.length)} {t('common.of')} {filteredExpenses.length}
                    </p>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                        className="h-8 w-8 p-0"
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </Button>

                      {/* Page numbers - show on desktop */}
                      <div className="hidden sm:flex items-center gap-1">
                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                          let pageNum
                          if (totalPages <= 5) {
                            pageNum = i + 1
                          } else if (currentPage <= 3) {
                            pageNum = i + 1
                          } else if (currentPage >= totalPages - 2) {
                            pageNum = totalPages - 4 + i
                          } else {
                            pageNum = currentPage - 2 + i
                          }
                          return (
                            <Button
                              key={pageNum}
                              variant={currentPage === pageNum ? "default" : "outline"}
                              size="sm"
                              onClick={() => setCurrentPage(pageNum)}
                              className={`h-8 w-8 p-0 ${currentPage === pageNum ? 'bg-emerald-600 hover:bg-emerald-700' : ''}`}
                            >
                              {pageNum}
                            </Button>
                          )
                        })}
                      </div>

                      {/* Mobile page indicator */}
                      <span className="sm:hidden text-sm text-slate-600 px-2">
                        {currentPage} / {totalPages}
                      </span>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                        disabled={currentPage === totalPages}
                        className="h-8 w-8 p-0"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Voice Entry Modal */}
      <ExpenseEntryModal
        isOpen={showVoiceEntry}
        onClose={() => setShowVoiceEntry(false)}
        onExpenseAdded={handleExpenseAdded}
      />

      {/* AI Insights Modal */}
      <AIInsightsModal
        isOpen={showInsightsModal}
        onClose={() => setShowInsightsModal(false)}
      />
    </DashboardLayout>
  )
}

export default function ExpensesPage() {
  return (
    <OnboardingGuard>
      <ExpensesContent />
    </OnboardingGuard>
  )
}
