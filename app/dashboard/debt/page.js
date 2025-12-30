'use client'

import { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Plus,
  TrendingDown,
  TrendingUp,
  Edit,
  Trash2,
  DollarSign,
  PieChart,
  LineChart,
  CheckCircle,
  X,
  Wallet,
  Receipt
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { PieChart as RechartsPieChart, Cell, ResponsiveContainer, LineChart as RechartsLineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Pie } from 'recharts'

// Skeleton component
function SkeletonBox({ className }) {
  return <div className={`animate-pulse bg-slate-200 rounded ${className}`} />
}

function DebtSkeleton() {
  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {[1, 2].map(i => (
          <div key={i} className="space-y-4">
            <div className="flex justify-between items-center">
              <SkeletonBox className="h-6 w-40" />
              <SkeletonBox className="h-9 w-24" />
            </div>
            <div className="bg-white rounded-xl border p-4">
              <div className="grid grid-cols-2 gap-4">
                <SkeletonBox className="h-16" />
                <SkeletonBox className="h-16" />
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {[1, 2, 3].map(i => (
          <SkeletonBox key={i} className="h-48" />
        ))}
      </div>
    </div>
  )
}

// Modal Component
function DebtModal({ isOpen, onClose, onSave, debt = null, type = 'taken' }) {
  const [formData, setFormData] = useState({
    type: type,
    name: '',
    amount: '',
    interestRate: '',
    duration: '',
    monthlyInstallment: '',
    dueDate: '',
    description: ''
  })
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    return () => setMounted(false)
  }, [])

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }
    return () => { document.body.style.overflow = 'unset' }
  }, [isOpen])

  useEffect(() => {
    const handleEsc = (e) => { if (e.key === 'Escape' && isOpen) onClose() }
    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [isOpen, onClose])

  // Calculate EMI and due date
  const calculateLoanDetails = (amount, interestRate, duration) => {
    if (!amount || !duration || amount <= 0 || duration <= 0) {
      return { monthlyInstallment: '', dueDate: '' }
    }
    const principal = parseFloat(amount)
    const months = parseInt(duration)
    const monthlyRate = parseFloat(interestRate || 0) / 100 / 12
    let monthlyInstallment
    if (monthlyRate > 0) {
      monthlyInstallment = principal * (monthlyRate * Math.pow(1 + monthlyRate, months)) / (Math.pow(1 + monthlyRate, months) - 1)
    } else {
      monthlyInstallment = principal / months
    }
    const today = new Date()
    const dueDate = new Date(today.getFullYear(), today.getMonth() + months, today.getDate())
    return {
      monthlyInstallment: monthlyInstallment.toFixed(2),
      dueDate: dueDate.toISOString().split('T')[0]
    }
  }

  useEffect(() => {
    const { monthlyInstallment, dueDate } = calculateLoanDetails(formData.amount, formData.interestRate, formData.duration)
    if (monthlyInstallment && dueDate) {
      setFormData(prev => ({ ...prev, monthlyInstallment, dueDate }))
    }
  }, [formData.amount, formData.interestRate, formData.duration])

  useEffect(() => {
    if (debt) {
      const today = new Date()
      const existingDueDate = new Date(debt.dueDate)
      const monthsDiff = (existingDueDate.getFullYear() - today.getFullYear()) * 12 + (existingDueDate.getMonth() - today.getMonth())
      setFormData({
        type: debt.type,
        name: debt.name,
        amount: debt.amount.toString(),
        interestRate: debt.interestRate.toString(),
        duration: Math.max(1, monthsDiff).toString(),
        monthlyInstallment: debt.monthlyInstallment.toString(),
        dueDate: new Date(debt.dueDate).toISOString().split('T')[0],
        description: debt.description || ''
      })
    } else {
      setFormData({
        type: type,
        name: '',
        amount: '',
        interestRate: '',
        duration: '',
        monthlyInstallment: '',
        dueDate: '',
        description: ''
      })
    }
  }, [debt, type])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!formData.name || !formData.amount || !formData.duration) {
      toast.error('Please fill in all required fields')
      return
    }
    await onSave({
      ...formData,
      amount: parseFloat(formData.amount),
      interestRate: parseFloat(formData.interestRate) || 0,
      duration: parseInt(formData.duration),
      monthlyInstallment: parseFloat(formData.monthlyInstallment) || 0
    })
  }

  if (!isOpen || !mounted) return null

  const modalContent = (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[9999] p-4" onClick={onClose}>
      <div className="bg-white rounded-xl p-6 max-w-md w-full max-h-[90vh] overflow-y-auto shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-800">
            {debt ? 'Edit' : 'Add'} {type === 'taken' ? 'Debt Taken' : 'Debt Given'}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              {type === 'taken' ? 'Lender Name' : 'Borrower Name'} *
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full p-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm"
              placeholder={type === 'taken' ? 'e.g., Bank Name' : 'e.g., Friend Name'}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Amount (₹) *</label>
              <input
                type="number"
                value={formData.amount}
                onChange={(e) => setFormData({ ...formData, amount: e.target.value })}
                className="w-full p-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm"
                placeholder="0"
                min="0"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Interest Rate (%)</label>
              <input
                type="number"
                value={formData.interestRate}
                onChange={(e) => setFormData({ ...formData, interestRate: e.target.value })}
                className="w-full p-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm"
                placeholder="0"
                min="0"
                max="100"
                step="0.1"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Duration (months) *</label>
            <input
              type="number"
              value={formData.duration}
              onChange={(e) => setFormData({ ...formData, duration: e.target.value })}
              className="w-full p-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm"
              placeholder="12"
              min="1"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-slate-500 mb-1">Monthly EMI</label>
              <input
                type="text"
                value={formData.monthlyInstallment ? `₹${parseFloat(formData.monthlyInstallment).toLocaleString('en-IN')}` : ''}
                className="w-full p-2.5 border border-slate-200 rounded-lg bg-slate-50 text-sm text-slate-600"
                disabled
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-500 mb-1">Due Date</label>
              <input
                type="text"
                value={formData.dueDate ? new Date(formData.dueDate).toLocaleDateString('en-IN') : ''}
                className="w-full p-2.5 border border-slate-200 rounded-lg bg-slate-50 text-sm text-slate-600"
                disabled
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full p-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm"
              placeholder="Optional notes..."
              rows="2"
            />
          </div>

          <div className="flex gap-3 pt-2">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              className={`flex-1 text-white ${type === 'taken' ? 'bg-red-500 hover:bg-red-600' : 'bg-emerald-500 hover:bg-emerald-600'}`}
            >
              {debt ? 'Update' : 'Add'} Debt
            </Button>
          </div>
        </form>
      </div>
    </div>
  )

  return createPortal(modalContent, document.body)
}

function DebtOverview() {
  const { t } = useTranslation()
  const [debts, setDebts] = useState([])
  const [summary, setSummary] = useState({ taken: {}, given: {} })
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [modalType, setModalType] = useState('taken')
  const [editingDebt, setEditingDebt] = useState(null)
  const [userProfile, setUserProfile] = useState(null)

  useEffect(() => {
    fetchDebts()
    fetchUserProfile()
  }, [])

  const fetchDebts = async () => {
    try {
      const response = await fetch('/api/debt')
      const data = await response.json()
      if (response.ok) {
        setDebts(data.debts)
        setSummary(data.summary)
      }
    } catch (error) {
      console.error('Fetch error:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchUserProfile = async () => {
    try {
      const response = await fetch('/api/user')
      const data = await response.json()
      if (response.ok) setUserProfile(data.user)
    } catch (error) {
      console.error('Profile fetch error:', error)
    }
  }

  const handleAddDebt = (type) => {
    setModalType(type)
    setEditingDebt(null)
    setShowModal(true)
  }

  const handleEditDebt = (debt) => {
    setEditingDebt(debt)
    setModalType(debt.type)
    setShowModal(true)
  }

  const handleSaveDebt = async (debtData) => {
    try {
      const url = editingDebt ? `/api/debt/${editingDebt._id}` : '/api/debt'
      const method = editingDebt ? 'PUT' : 'POST'
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(debtData)
      })
      const data = await response.json()
      if (response.ok) {
        toast.success(editingDebt ? 'Debt updated' : 'Debt added')
        setShowModal(false)
        setEditingDebt(null)
        fetchDebts()
      } else {
        toast.error(data.error || 'Failed to save')
      }
    } catch (error) {
      toast.error('Failed to save debt')
    }
  }

  const handleDeleteDebt = async (debtId) => {
    if (!confirm('Delete this debt?')) return
    try {
      const response = await fetch(`/api/debt/${debtId}`, { method: 'DELETE' })
      if (response.ok) {
        toast.success('Debt deleted')
        fetchDebts()
      }
    } catch (error) {
      toast.error('Failed to delete')
    }
  }

  const formatCurrency = (amount) => `₹${(amount || 0).toLocaleString('en-IN')}`

  const formatDate = (date) => new Date(date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })

  const getDaysUntilDue = (dueDate) => {
    const today = new Date()
    const due = new Date(dueDate)
    return Math.ceil((due.getTime() - today.getTime()) / (1000 * 3600 * 24))
  }

  const calculateDebtScore = () => {
    const monthlyIncome = userProfile?.monthlyIncome || 0
    const totalDebtTaken = summary.taken.totalRemaining || 0
    const totalDebtGiven = summary.given.totalRemaining || 0
    const totalDebts = debts.length
    const overdueDebts = debts.filter(debt => new Date(debt.dueDate) < new Date() && debt.remainingBalance > 0).length

    if (totalDebts === 0) return 95

    let score = 50
    if (monthlyIncome > 0) {
      const debtRatio = (totalDebtTaken / monthlyIncome) * 100
      if (debtRatio <= 10) score += 40
      else if (debtRatio <= 20) score += 30
      else if (debtRatio <= 30) score += 20
      else if (debtRatio <= 40) score += 10
      else score -= 10
    } else {
      if (totalDebtTaken <= 100000) score += 25
      else if (totalDebtTaken <= 500000) score += 15
      else if (totalDebtTaken <= 1000000) score += 5
      else score -= 10
    }

    const debtBalance = totalDebtTaken > 0 && totalDebtGiven > 0
    if (debtBalance && totalDebtGiven >= totalDebtTaken * 0.5) score += 20
    else if (totalDebtTaken === 0 && totalDebtGiven > 0) score += 15
    else if (totalDebtTaken > 0 && totalDebtGiven === 0) score += 5

    if (overdueDebts === 0) score += 20
    else {
      const overdueRatio = overdueDebts / totalDebts
      if (overdueRatio <= 0.1) score += 10
      else if (overdueRatio <= 0.25) score += 5
      else score -= 15
    }

    if (totalDebts <= 2) score += 10
    else if (totalDebts <= 5) score += 5
    else score -= 5

    return Math.max(0, Math.min(100, Math.round(score)))
  }

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-emerald-600'
    if (score >= 60) return 'text-blue-600'
    if (score >= 40) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getScoreLabel = (score) => {
    if (score >= 80) return t('debt.excellent')
    if (score >= 60) return t('debt.good')
    if (score >= 40) return t('debt.fair')
    if (score >= 20) return t('debt.poor')
    return t('debt.critical')
  }

  const getScoreRingColor = (score) => {
    if (score >= 80) return '#10b981'
    if (score >= 60) return '#3b82f6'
    if (score >= 40) return '#f59e0b'
    return '#ef4444'
  }

  const pieChartData = [
    { name: t('debt.debtsTaken'), value: summary.taken.totalRemaining || 0, color: '#ef4444' },
    { name: t('debt.debtsGiven'), value: summary.given.totalRemaining || 0, color: '#10b981' }
  ]

  const lineChartData = debts.reduce((acc, debt) => {
    const month = new Date(debt.createdAt).toISOString().slice(0, 7)
    const existing = acc.find(item => item.month === month)
    if (existing) {
      if (debt.type === 'taken') existing.taken += debt.amount
      else existing.given += debt.amount
    } else {
      acc.push({
        month,
        taken: debt.type === 'taken' ? debt.amount : 0,
        given: debt.type === 'given' ? debt.amount : 0
      })
    }
    return acc
  }, []).sort((a, b) => a.month.localeCompare(b.month)).slice(-6)

  const debtScore = calculateDebtScore()

  return (
    <DashboardLayout title={t('debt.title')}>
      <div className="space-y-6 max-w-6xl mx-auto">

        {loading ? (
          <DebtSkeleton />
        ) : (
          <>
            {/* Debt Summary Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Debt Taken */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold text-red-600 flex items-center gap-2">
                    <TrendingDown className="w-5 h-5" />
                    {t('debt.debtsTaken')}
                    <span className="text-sm font-normal text-slate-400">({t('debt.liabilities')})</span>
                  </h2>
                  <Button onClick={() => handleAddDebt('taken')} size="sm" className="bg-red-500 hover:bg-red-600 text-white h-9">
                    <Plus className="w-4 h-4 mr-1" />
                    {t('debt.addDebt')}
                  </Button>
                </div>

                <Card className="border-red-200 bg-red-50/50">
                  <CardContent className="p-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-xs text-red-600 font-medium">{t('debt.totalAmount')}</p>
                        <p className="text-lg font-bold text-red-700">{formatCurrency(summary.taken.totalAmount)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-red-600 font-medium">{t('debt.remainingAmount')}</p>
                        <p className="text-lg font-bold text-red-700">{formatCurrency(summary.taken.totalRemaining)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-red-600 font-medium">{t('debt.monthlyPayments')}</p>
                        <p className="text-sm font-semibold text-red-700">{formatCurrency(summary.taken.totalMonthlyPayments)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-red-600 font-medium">{t('debt.activeDebts')}</p>
                        <p className="text-sm font-semibold text-red-700">{summary.taken.count || 0}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Debt Taken List */}
                <div className="space-y-2">
                  {debts.filter(d => d.type === 'taken').slice(0, 3).map((debt) => {
                    const daysLeft = getDaysUntilDue(debt.dueDate)
                    const progress = ((debt.amount - debt.remainingBalance) / debt.amount) * 100

                    return (
                      <div key={debt._id} className="bg-white border border-slate-200 rounded-lg p-3 hover:shadow-sm transition-shadow">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-slate-800 text-sm">{debt.name}</span>
                          <div className="flex gap-1">
                            <button onClick={() => handleEditDebt(debt)} className="p-1 text-slate-400 hover:text-slate-600">
                              <Edit className="w-3.5 h-3.5" />
                            </button>
                            <button onClick={() => handleDeleteDebt(debt._id)} className="p-1 text-slate-400 hover:text-red-500">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-xs mb-2">
                          <span className="text-slate-500">{t('debt.remaining')}: <span className="font-medium text-red-600">{formatCurrency(debt.remainingBalance)}</span></span>
                          <span className={daysLeft < 30 ? 'text-red-600 font-medium' : 'text-slate-500'}>
                            {daysLeft > 0 ? `${daysLeft} ${t('debt.days')}` : t('debt.overdue')}
                          </span>
                        </div>
                        <div className="w-full bg-red-100 rounded-full h-1.5">
                          <div className="bg-red-500 h-1.5 rounded-full" style={{ width: `${progress}%` }} />
                        </div>
                      </div>
                    )
                  })}

                  {debts.filter(d => d.type === 'taken').length === 0 && (
                    <div className="text-center py-8 text-slate-400">
                      <Receipt className="w-10 h-10 mx-auto mb-2 text-slate-200" />
                      <p className="text-sm">{t('debt.noDebtsTaken')}</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Debt Given */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold text-emerald-600 flex items-center gap-2">
                    <TrendingUp className="w-5 h-5" />
                    {t('debt.debtsGiven')}
                    <span className="text-sm font-normal text-slate-400">({t('debt.assets')})</span>
                  </h2>
                  <Button onClick={() => handleAddDebt('given')} size="sm" className="bg-emerald-500 hover:bg-emerald-600 text-white h-9">
                    <Plus className="w-4 h-4 mr-1" />
                    {t('debt.addDebt')}
                  </Button>
                </div>

                <Card className="border-emerald-200 bg-emerald-50/50">
                  <CardContent className="p-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-xs text-emerald-600 font-medium">{t('debt.totalAmount')}</p>
                        <p className="text-lg font-bold text-emerald-700">{formatCurrency(summary.given.totalAmount)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-emerald-600 font-medium">{t('debt.remainingAmount')}</p>
                        <p className="text-lg font-bold text-emerald-700">{formatCurrency(summary.given.totalRemaining)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-emerald-600 font-medium">{t('debt.monthlyPayments')}</p>
                        <p className="text-sm font-semibold text-emerald-700">{formatCurrency(summary.given.totalMonthlyPayments)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-emerald-600 font-medium">{t('debt.activeDebts')}</p>
                        <p className="text-sm font-semibold text-emerald-700">{summary.given.count || 0}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Debt Given List */}
                <div className="space-y-2">
                  {debts.filter(d => d.type === 'given').slice(0, 3).map((debt) => {
                    const daysLeft = getDaysUntilDue(debt.dueDate)
                    const progress = ((debt.amount - debt.remainingBalance) / debt.amount) * 100

                    return (
                      <div key={debt._id} className="bg-white border border-slate-200 rounded-lg p-3 hover:shadow-sm transition-shadow">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-slate-800 text-sm">{debt.name}</span>
                          <div className="flex gap-1">
                            <button onClick={() => handleEditDebt(debt)} className="p-1 text-slate-400 hover:text-slate-600">
                              <Edit className="w-3.5 h-3.5" />
                            </button>
                            <button onClick={() => handleDeleteDebt(debt._id)} className="p-1 text-slate-400 hover:text-red-500">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-xs mb-2">
                          <span className="text-slate-500">{t('debt.remaining')}: <span className="font-medium text-emerald-600">{formatCurrency(debt.remainingBalance)}</span></span>
                          <span className={daysLeft < 30 ? 'text-emerald-600 font-medium' : 'text-slate-500'}>
                            {daysLeft > 0 ? `${daysLeft} ${t('debt.days')}` : t('debt.overdue')}
                          </span>
                        </div>
                        <div className="w-full bg-emerald-100 rounded-full h-1.5">
                          <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: `${progress}%` }} />
                        </div>
                      </div>
                    )
                  })}

                  {debts.filter(d => d.type === 'given').length === 0 && (
                    <div className="text-center py-8 text-slate-400">
                      <DollarSign className="w-10 h-10 mx-auto mb-2 text-slate-200" />
                      <p className="text-sm">{t('debt.noDebtsGiven')}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Analytics Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Debt Score */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    {t('debt.debtScore')}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex items-center justify-center">
                    <div className="relative w-24 h-24">
                      <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" stroke="#e5e7eb" strokeWidth="8" fill="none" />
                        <circle
                          cx="50" cy="50" r="40"
                          stroke={getScoreRingColor(debtScore)}
                          strokeWidth="8"
                          fill="none"
                          strokeDasharray={`${debtScore * 2.51} 251`}
                          strokeLinecap="round"
                          className="transition-all duration-700"
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <div className="text-center">
                          <div className={`text-2xl font-bold ${getScoreColor(debtScore)}`}>{debtScore}</div>
                          <div className="text-[10px] text-slate-400">{t('debt.outOf100')}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="text-center mt-2">
                    <Badge className={`${debtScore >= 80 ? 'bg-emerald-100 text-emerald-700' : debtScore >= 60 ? 'bg-blue-100 text-blue-700' : debtScore >= 40 ? 'bg-yellow-100 text-yellow-700' : 'bg-red-100 text-red-700'}`}>
                      {getScoreLabel(debtScore)}
                    </Badge>
                  </div>
                  <div className="mt-3 pt-3 border-t border-slate-100 space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-500">{t('debt.totalDebts')}:</span>
                      <span className="font-medium">{debts.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">{t('debt.totalBorrowed')}:</span>
                      <span className="font-medium text-red-600">{formatCurrency(summary.taken.totalRemaining)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">{t('debt.totalLent')}:</span>
                      <span className="font-medium text-emerald-600">{formatCurrency(summary.given.totalRemaining)}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Distribution */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <PieChart className="w-4 h-4 text-blue-500" />
                    {t('debt.debtDistribution')}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  {pieChartData.some(d => d.value > 0) ? (
                    <ResponsiveContainer width="100%" height={140}>
                      <RechartsPieChart>
                        <Pie data={pieChartData.filter(d => d.value > 0)} cx="50%" cy="50%" innerRadius={30} outerRadius={50} dataKey="value">
                          {pieChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip formatter={(value) => formatCurrency(value)} />
                      </RechartsPieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-[140px] text-slate-400">
                      <div className="text-center">
                        <PieChart className="w-8 h-8 mx-auto mb-1 text-slate-200" />
                        <p className="text-xs">{t('debt.noData')}</p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Trends */}
              <Card className="border-slate-200">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <LineChart className="w-4 h-4 text-purple-500" />
                    {t('debt.debtTrends')}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  {lineChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={140}>
                      <RechartsLineChart data={lineChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                        <XAxis dataKey="month" fontSize={9} stroke="#94a3b8" />
                        <YAxis fontSize={9} stroke="#94a3b8" tickFormatter={(v) => `₹${(v/1000).toFixed(0)}k`} />
                        <Tooltip formatter={(value) => formatCurrency(value)} />
                        <Line type="monotone" dataKey="taken" stroke="#ef4444" strokeWidth={2} dot={{ r: 2 }} />
                        <Line type="monotone" dataKey="given" stroke="#10b981" strokeWidth={2} dot={{ r: 2 }} />
                      </RechartsLineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-[140px] text-slate-400">
                      <div className="text-center">
                        <LineChart className="w-8 h-8 mx-auto mb-1 text-slate-200" />
                        <p className="text-xs">{t('debt.noTrendData')}</p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </>
        )}

        <DebtModal
          isOpen={showModal}
          onClose={() => setShowModal(false)}
          onSave={handleSaveDebt}
          debt={editingDebt}
          type={modalType}
        />
      </div>
    </DashboardLayout>
  )
}

export default function DebtOverviewPage() {
  return <DebtOverview />
}
