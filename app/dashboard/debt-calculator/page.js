'use client'

import { useState, useEffect, useRef } from 'react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Calculator,
  Bot,
  Send,
  TrendingUp,
  DollarSign,
  Calendar,
  PieChart,
  Lightbulb,
  User,
  Copy,
  Check,
  Sparkles,
  IndianRupee,
  Clock,
  ChevronRight
} from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'
import { toast } from 'react-hot-toast'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

// Skeleton components
function SkeletonBox({ className }) {
  return <div className={`animate-pulse bg-slate-200 rounded ${className}`} />
}

// EMI Calculator Component
function EMICalculator({ onCalculate }) {
  const { t } = useTranslation()
  const [formData, setFormData] = useState({
    principal: '',
    interestRate: '',
    duration: '',
    durationType: 'months',
    compoundingFrequency: 'monthly'
  })
  const [results, setResults] = useState(null)
  const [chartData, setChartData] = useState([])
  const [errors, setErrors] = useState({})
  const [calculating, setCalculating] = useState(false)

  const validateForm = () => {
    const newErrors = {}
    if (!formData.principal || parseFloat(formData.principal) <= 0) {
      newErrors.principal = t('debtCalculator.validPrincipalError')
    }
    if (!formData.interestRate || parseFloat(formData.interestRate) < 0) {
      newErrors.interestRate = t('debtCalculator.validInterestError')
    }
    if (!formData.duration || parseInt(formData.duration) <= 0) {
      newErrors.duration = t('debtCalculator.validDurationError')
    }
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const calculateEMI = async () => {
    if (!validateForm()) {
      toast.error(t('debtCalculator.fixFormErrors'))
      return
    }

    setCalculating(true)

    // Simulate calculation delay for better UX
    await new Promise(resolve => setTimeout(resolve, 300))

    const { principal, interestRate, duration, durationType } = formData
    const P = parseFloat(principal)
    const annualRate = parseFloat(interestRate) / 100
    const months = durationType === 'years' ? parseInt(duration) * 12 : parseInt(duration)
    const monthlyRate = annualRate / 12

    let emi = 0
    if (monthlyRate > 0) {
      emi = P * (monthlyRate * Math.pow(1 + monthlyRate, months)) / (Math.pow(1 + monthlyRate, months) - 1)
    } else {
      emi = P / months
    }

    const totalPayable = emi * months
    const totalInterest = totalPayable - P

    const calculationResults = {
      emi,
      totalPayable,
      totalInterest,
      months,
      principal: P,
      interestRate: parseFloat(interestRate),
      monthlyRate
    }

    setResults(calculationResults)
    generateChartData(calculationResults)
    onCalculate(calculationResults)
    setCalculating(false)
    toast.success(t('debtCalculator.emiSuccess'))
  }

  const generateChartData = (results) => {
    const data = []
    let remainingPrincipal = results.principal
    let cumulativeInterest = 0

    for (let month = 1; month <= Math.min(results.months, 120); month++) {
      const interestPayment = remainingPrincipal * results.monthlyRate
      const principalPayment = results.emi - interestPayment
      remainingPrincipal = Math.max(0, remainingPrincipal - principalPayment)
      cumulativeInterest += interestPayment

      data.push({
        month,
        remainingPrincipal: Math.round(remainingPrincipal),
        cumulativeInterest: Math.round(cumulativeInterest)
      })
    }
    setChartData(data)
  }

  const formatCurrency = (amount) => `₹${Math.round(amount).toLocaleString('en-IN')}`

  return (
    <div className="space-y-4">
      {/* Calculator Form */}
      <Card className="border-slate-200">
        <CardHeader className="pb-3">
          <CardTitle className="text-base font-semibold text-slate-800 flex items-center gap-2">
            <Calculator className="w-5 h-5 text-emerald-600" />
            {t('debtCalculator.title')}
          </CardTitle>
          <p className="text-xs text-slate-500">{t('debtCalculator.subtitle')}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Amount and Interest Row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">
                {t('debtCalculator.loanAmount')} (₹) *
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">₹</span>
                <input
                  type="number"
                  value={formData.principal}
                  onChange={(e) => setFormData({ ...formData, principal: e.target.value })}
                  className={`w-full pl-7 pr-3 py-2.5 border rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm ${errors.principal ? 'border-red-400' : 'border-slate-300'}`}
                  placeholder="500000"
                />
              </div>
              {errors.principal && <p className="text-red-500 text-xs mt-1">{errors.principal}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">
                {t('debtCalculator.interestRate')} (%) *
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={formData.interestRate}
                  onChange={(e) => setFormData({ ...formData, interestRate: e.target.value })}
                  className={`w-full px-3 py-2.5 border rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm ${errors.interestRate ? 'border-red-400' : 'border-slate-300'}`}
                  placeholder="10.5"
                  step="0.1"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs">{t('common.perAnnum')}</span>
              </div>
              {errors.interestRate && <p className="text-red-500 text-xs mt-1">{errors.interestRate}</p>}
            </div>
          </div>

          {/* Duration Row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">
                {t('debtCalculator.loanTerm')} *
              </label>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={formData.duration}
                  onChange={(e) => setFormData({ ...formData, duration: e.target.value })}
                  className={`flex-1 px-3 py-2.5 border rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 text-sm ${errors.duration ? 'border-red-400' : 'border-slate-300'}`}
                  placeholder="36"
                  min="1"
                />
                <select
                  value={formData.durationType}
                  onChange={(e) => setFormData({ ...formData, durationType: e.target.value })}
                  className="px-2 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 bg-white text-sm"
                >
                  <option value="months">{t('common.months')}</option>
                  <option value="years">{t('common.years')}</option>
                </select>
              </div>
              {errors.duration && <p className="text-red-500 text-xs mt-1">{errors.duration}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">
                {t('debtCalculator.compoundingFrequency')}
              </label>
              <select
                value={formData.compoundingFrequency}
                onChange={(e) => setFormData({ ...formData, compoundingFrequency: e.target.value })}
                className="w-full px-3 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 bg-white text-sm"
              >
                <option value="monthly">{t('common.monthly')}</option>
                <option value="quarterly">{t('common.quarterly')}</option>
                <option value="annually">{t('common.annually')}</option>
              </select>
            </div>
          </div>

          <Button
            onClick={calculateEMI}
            disabled={calculating}
            className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3"
          >
            {calculating ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                Calculating...
              </>
            ) : (
              <>
                <Calculator className="w-4 h-4 mr-2" />
                {t('debtCalculator.calculate')} EMI
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Results Cards */}
      {results && (
        <div className="grid grid-cols-3 gap-3">
          <Card className="border-blue-200 bg-blue-50/50">
            <CardContent className="p-3 text-center">
              <IndianRupee className="w-6 h-6 mx-auto mb-1 text-blue-600" />
              <p className="text-[10px] text-blue-600 font-medium">{t('debtCalculator.monthlyEmi')}</p>
              <p className="text-lg font-bold text-blue-700">{formatCurrency(results.emi)}</p>
            </CardContent>
          </Card>

          <Card className="border-emerald-200 bg-emerald-50/50">
            <CardContent className="p-3 text-center">
              <TrendingUp className="w-6 h-6 mx-auto mb-1 text-emerald-600" />
              <p className="text-[10px] text-emerald-600 font-medium">{t('debtCalculator.totalPayable')}</p>
              <p className="text-lg font-bold text-emerald-700">{formatCurrency(results.totalPayable)}</p>
            </CardContent>
          </Card>

          <Card className="border-red-200 bg-red-50/50">
            <CardContent className="p-3 text-center">
              <PieChart className="w-6 h-6 mx-auto mb-1 text-red-600" />
              <p className="text-[10px] text-red-600 font-medium">{t('debtCalculator.totalInterest')}</p>
              <p className="text-lg font-bold text-red-700">{formatCurrency(results.totalInterest)}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Chart */}
      {chartData.length > 0 && (
        <Card className="border-slate-200">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Calendar className="w-4 h-4 text-purple-600" />
              {t('debtCalculator.repaymentTimeline')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="month" fontSize={10} stroke="#94a3b8" tickLine={false} />
                <YAxis fontSize={10} stroke="#94a3b8" tickLine={false} tickFormatter={(v) => `₹${(v/1000).toFixed(0)}k`} />
                <Tooltip
                  formatter={(value) => [formatCurrency(value)]}
                  contentStyle={{ backgroundColor: 'white', border: '1px solid #e2e8f0', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="remainingPrincipal" stroke="#3b82f6" fill="#93c5fd" fillOpacity={0.5} name={t('debtCalculator.remainingPrincipal')} />
                <Area type="monotone" dataKey="cumulativeInterest" stroke="#ef4444" fill="#fca5a5" fillOpacity={0.5} name={t('debtCalculator.cumulativeInterest')} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// AI Loan Advisor Chat
function LoanAdvisorChat({ calculationResults }) {
  const { t } = useTranslation()
  const [messages, setMessages] = useState([{
    id: 1,
    type: 'bot',
    content: `**Hi! I'm your AI Loan Advisor.**

I can help you with:
- **EMI calculations** and comparisons
- **Debt repayment strategies** (snowball vs avalanche)
- **Bank recommendations** with current rates
- **Credit score** improvement tips

**Try asking:**
- "Calculate EMI for ₹5L at 10% for 2 years"
- "Which repayment strategy is better?"
- "Best banks for personal loans?"

What would you like to know?`,
    timestamp: new Date()
  }])
  const [newMessage, setNewMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [copiedId, setCopiedId] = useState(null)
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const getContextualPrompt = (userMessage) => {
    let prompt = userMessage
    if (calculationResults) {
      prompt += `\n\nContext: User just calculated EMI with these details:
      - Principal: ₹${calculationResults.principal.toLocaleString()}
      - Interest Rate: ${calculationResults.interestRate}%
      - Duration: ${calculationResults.months} months
      - Monthly EMI: ₹${calculationResults.emi.toFixed(0)}
      - Total Interest: ₹${calculationResults.totalInterest.toFixed(0)}

      Please provide advice relevant to these calculations.`
    }
    return prompt
  }

  const sendMessage = async () => {
    if (!newMessage.trim() || isLoading) return

    const userMessage = {
      id: Date.now(),
      type: 'user',
      content: newMessage.trim(),
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setNewMessage('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/loan-advisor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: getContextualPrompt(userMessage.content),
          calculationData: calculationResults
        })
      })

      const data = await response.json()

      if (response.ok) {
        setMessages(prev => [...prev, {
          id: Date.now() + 1,
          type: 'bot',
          content: data.response,
          timestamp: new Date()
        }])
      } else {
        throw new Error(data.error)
      }
    } catch (error) {
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        type: 'bot',
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date()
      }])
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const copyMessage = async (content, id) => {
    await navigator.clipboard.writeText(content)
    setCopiedId(id)
    toast.success(t('debtCalculator.copied'))
    setTimeout(() => setCopiedId(null), 2000)
  }

  const quickActions = [
    "Calculate EMI for ₹10L at 12% for 5 years",
    "Best repayment strategy?",
    "How to improve credit score?",
    "Which banks offer lowest rates?"
  ]

  return (
    <Card className="border-slate-200 h-full flex flex-col">
      <CardHeader className="pb-3 border-b">
        <CardTitle className="text-base font-semibold text-slate-800 flex items-center gap-2">
          <Bot className="w-5 h-5 text-blue-600" />
          {t('debtCalculator.aiAdvisor')}
        </CardTitle>
        <p className="text-xs text-slate-500">{t('debtCalculator.aiAdvisorDesc')}</p>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col p-0 min-h-0">
        {/* Quick Actions */}
        {messages.length <= 1 && (
          <div className="p-3 border-b bg-slate-50">
            <p className="text-xs text-slate-500 mb-2">{t('debtCalculator.quickQuestions')}:</p>
            <div className="flex flex-wrap gap-1.5">
              {quickActions.map((action, i) => (
                <button
                  key={i}
                  onClick={() => setNewMessage(action)}
                  className="text-xs px-2 py-1 bg-white border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-200 transition-colors"
                >
                  {action}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3" style={{ maxHeight: '400px' }}>
          {messages.map((message) => (
            <div key={message.id} className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex max-w-[85%] ${message.type === 'user' ? 'flex-row-reverse' : ''} items-start gap-2`}>
                <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${message.type === 'user' ? 'bg-emerald-500' : 'bg-blue-500'}`}>
                  {message.type === 'user' ? <User className="w-3.5 h-3.5 text-white" /> : <Bot className="w-3.5 h-3.5 text-white" />}
                </div>

                <div className={`group rounded-xl px-3 py-2 ${message.type === 'user' ? 'bg-emerald-500 text-white rounded-br-sm' : 'bg-white border border-slate-200 rounded-bl-sm'}`}>
                  {message.type === 'bot' ? (
                    <div className="prose prose-sm max-w-none">
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          p: ({ children }) => <p className="mb-1.5 last:mb-0 text-xs leading-relaxed text-slate-700">{children}</p>,
                          ul: ({ children }) => <ul className="mb-1.5 text-xs space-y-0.5 text-slate-700">{children}</ul>,
                          li: ({ children }) => <li className="ml-3">{children}</li>,
                          strong: ({ children }) => <strong className="font-semibold text-slate-800">{children}</strong>,
                          h2: ({ children }) => <h2 className="text-sm font-semibold mb-1.5 text-slate-800">{children}</h2>,
                          h3: ({ children }) => <h3 className="text-xs font-semibold mb-1 text-slate-800">{children}</h3>,
                          table: ({ children }) => <table className="text-xs border-collapse my-2">{children}</table>,
                          th: ({ children }) => <th className="border border-slate-200 px-2 py-1 bg-slate-50 text-left font-medium">{children}</th>,
                          td: ({ children }) => <td className="border border-slate-200 px-2 py-1">{children}</td>
                        }}
                      >
                        {message.content}
                      </ReactMarkdown>
                    </div>
                  ) : (
                    <p className="text-xs">{message.content}</p>
                  )}

                  <div className={`flex items-center justify-between mt-1.5 ${message.type === 'user' ? 'text-emerald-100' : 'text-slate-400'}`}>
                    <span className="text-[10px]">{new Date(message.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</span>
                    <button
                      onClick={() => copyMessage(message.content, message.id)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5"
                    >
                      {copiedId === message.id ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="flex justify-start">
              <div className="flex items-start gap-2">
                <div className="w-7 h-7 bg-blue-500 rounded-full flex items-center justify-center">
                  <Bot className="w-3.5 h-3.5 text-white" />
                </div>
                <div className="bg-white border border-slate-200 rounded-xl rounded-bl-sm px-3 py-2">
                  <div className="flex space-x-1">
                    <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce" />
                    <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                    <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                  </div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-3 border-t bg-slate-50">
          <div className="flex gap-2">
            <input
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={t('debtCalculator.askAboutLoans')}
              className="flex-1 px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm"
              disabled={isLoading}
            />
            <Button
              onClick={sendMessage}
              disabled={isLoading || !newMessage.trim()}
              className="bg-blue-500 hover:bg-blue-600 text-white px-3"
            >
              <Send className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// Smart Insights Component
function SmartInsights({ calculationResults }) {
  const { t } = useTranslation()

  const generateInsights = () => {
    if (!calculationResults) return []

    const { emi, totalInterest, principal, months, interestRate } = calculationResults
    const insights = []

    // Extra payment insight
    const extraPayment = Math.round(emi * 0.1)
    const savedMonths = Math.floor(months * 0.15)
    const savedInterest = Math.round(totalInterest * 0.12)
    insights.push({
      type: 'tip',
      icon: '💡',
      title: 'Extra Payment Strategy',
      content: `Pay extra ₹${extraPayment.toLocaleString()}/month to save ${savedMonths} months and ~₹${savedInterest.toLocaleString()} interest.`
    })

    // Interest percentage insight
    const interestPercentage = ((totalInterest / principal) * 100).toFixed(1)
    if (interestPercentage > 50) {
      insights.push({
        type: 'warning',
        icon: '⚠️',
        title: 'High Interest',
        content: `Total interest is ${interestPercentage}% of principal. Consider shorter tenure or prepayment.`
      })
    } else {
      insights.push({
        type: 'success',
        icon: '✅',
        title: 'Reasonable Interest',
        content: `Interest burden (${interestPercentage}% of principal) is reasonable.`
      })
    }

    // EMI guideline
    insights.push({
      type: 'info',
      icon: '📊',
      title: 'EMI Guidelines',
      content: `Keep total EMIs under 40% of monthly income. Current EMI: ₹${emi.toFixed(0)}/month.`
    })

    return insights
  }

  const allInsights = generateInsights()

  const getInsightStyle = (type) => {
    switch (type) {
      case 'success': return 'border-emerald-200 bg-emerald-50'
      case 'warning': return 'border-yellow-200 bg-yellow-50'
      case 'tip': return 'border-blue-200 bg-blue-50'
      default: return 'border-slate-200 bg-slate-50'
    }
  }

  return (
    <Card className="border-slate-200">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-purple-600" />
          {t('debtCalculator.smartInsights')}
        </CardTitle>
        <p className="text-xs text-slate-500">{t('debtCalculator.smartInsightsDesc')}</p>
      </CardHeader>
      <CardContent>
        {allInsights.length > 0 ? (
          <div className="space-y-2">
            {allInsights.map((insight, index) => (
              <div key={index} className={`rounded-lg p-3 border ${getInsightStyle(insight.type)}`}>
                <div className="flex items-start gap-2">
                  <span className="text-base">{insight.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-slate-800 text-xs mb-0.5">{insight.title}</p>
                    <p className="text-xs text-slate-600">{insight.content}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-6 text-slate-400">
            <Lightbulb className="w-8 h-8 mx-auto mb-2 text-slate-200" />
            <p className="text-xs">Calculate a loan to get personalized insights</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// Main Page Component
export default function DebtCalculatorPage() {
  const { t } = useTranslation()
  const [calculationResults, setCalculationResults] = useState(null)

  return (
    <DashboardLayout title={t('debtCalculator.title')}>
      <div className="space-y-4 max-w-6xl mx-auto">
        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Calculator */}
          <div className="space-y-4">
            <EMICalculator onCalculate={setCalculationResults} />
            <SmartInsights calculationResults={calculationResults} />
          </div>

          {/* Right: AI Chat */}
          <LoanAdvisorChat calculationResults={calculationResults} />
        </div>

        {/* How to Use */}
        <Card className="border-slate-200">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-amber-500" />
              {t('debtCalculator.howToUse')}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-600">
              <div className="flex items-start gap-2">
                <div className="w-6 h-6 rounded-full bg-emerald-100 flex items-center justify-center flex-shrink-0">
                  <Calculator className="w-3 h-3 text-emerald-600" />
                </div>
                <div>
                  <p className="font-medium text-slate-800 mb-0.5">Calculate EMI</p>
                  <p>Enter loan amount, interest rate, and duration for accurate EMI calculations.</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <div className="w-6 h-6 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-3 h-3 text-blue-600" />
                </div>
                <div>
                  <p className="font-medium text-slate-800 mb-0.5">Ask AI Advisor</p>
                  <p>Get personalized advice on repayment strategies and loan optimization.</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <div className="w-6 h-6 rounded-full bg-purple-100 flex items-center justify-center flex-shrink-0">
                  <Sparkles className="w-3 h-3 text-purple-600" />
                </div>
                <div>
                  <p className="font-medium text-slate-800 mb-0.5">Smart Insights</p>
                  <p>View automated recommendations for prepayment and interest optimization.</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}
