'use client'

import { useState, useEffect } from 'react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import GoalTracker from '@/components/goals/GoalTracker'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Target,
  TrendingUp,
  Trophy,
  Zap,
  PiggyBank
} from 'lucide-react'

// Skeleton Component
function GoalsSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {/* Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-slate-200 rounded-lg" />
              <div className="space-y-2">
                <div className="h-6 w-12 bg-slate-200 rounded" />
                <div className="h-3 w-16 bg-slate-100 rounded" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Summary Card */}
      <div className="bg-white rounded-xl border border-slate-200 p-4">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-5 w-32 bg-slate-200 rounded" />
            <div className="h-4 w-48 bg-slate-100 rounded" />
          </div>
          <div className="h-8 w-24 bg-slate-200 rounded" />
        </div>
      </div>

      {/* Goal Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[1, 2].map(i => (
          <div key={i} className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="flex items-start gap-3 mb-4">
              <div className="w-12 h-12 bg-slate-200 rounded-lg" />
              <div className="flex-1 space-y-2">
                <div className="h-5 w-3/4 bg-slate-200 rounded" />
                <div className="h-3 w-1/2 bg-slate-100 rounded" />
              </div>
            </div>
            <div className="h-2 w-full bg-slate-100 rounded-full" />
            <div className="flex justify-between mt-2">
              <div className="h-3 w-20 bg-slate-100 rounded" />
              <div className="h-3 w-20 bg-slate-100 rounded" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function GoalsContent() {
  const { t } = useTranslation()
  const [goalsData, setGoalsData] = useState({
    goals: [],
    totalGoals: 0,
    totalTargetAmount: 0,
    totalCurrentAmount: 0
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchGoalsData()
  }, [])

  const fetchGoalsData = async () => {
    try {
      const response = await fetch('/api/goals')
      const data = await response.json()

      if (data.success) {
        setGoalsData({
          goals: data.goals || [],
          totalGoals: data.totalGoals || 0,
          totalTargetAmount: data.totalTargetAmount || 0,
          totalCurrentAmount: data.totalCurrentAmount || 0
        })
      }
    } catch (error) {
      console.error('Failed to fetch goals data:', error)
    } finally {
      setLoading(false)
    }
  }

  const activeGoals = goalsData.goals.filter(goal => goal.status === 'active').length
  const completedGoals = goalsData.goals.filter(goal => goal.status === 'completed').length
  const totalProgress = goalsData.totalTargetAmount > 0
    ? (goalsData.totalCurrentAmount / goalsData.totalTargetAmount) * 100
    : 0

  if (loading) {
    return (
      <DashboardLayout title={t('goals.title')}>
        <GoalsSkeleton />
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title={t('goals.title')}>
      <div className="space-y-4 max-w-5xl mx-auto">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
              <Target className="w-5 h-5 text-purple-600" />
              {t('goals.title')}
            </h2>
            <p className="text-sm text-slate-500">{t('goals.subtitle') || 'Track and achieve your financial goals'}</p>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-50 rounded-lg flex items-center justify-center">
                  <Target className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-800">{goalsData.totalGoals}</p>
                  <p className="text-xs text-slate-500">{t('goals.totalGoals') || 'Total Goals'}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-emerald-50 rounded-lg flex items-center justify-center">
                  <Zap className="w-5 h-5 text-emerald-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-800">{activeGoals}</p>
                  <p className="text-xs text-slate-500">{t('goals.active') || 'Active'}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-amber-50 rounded-lg flex items-center justify-center">
                  <Trophy className="w-5 h-5 text-amber-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-800">{completedGoals}</p>
                  <p className="text-xs text-slate-500">{t('goals.completed') || 'Completed'}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-purple-50 rounded-lg flex items-center justify-center">
                  <TrendingUp className="w-5 h-5 text-purple-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-800">{totalProgress.toFixed(0)}%</p>
                  <p className="text-xs text-slate-500">{t('goals.progress') || 'Progress'}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Summary Card - Only show if there are goals */}
        {goalsData.totalGoals > 0 && (
          <Card className="border-slate-200 border-l-4 border-l-emerald-500">
            <CardContent className="p-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-emerald-100 rounded-lg flex items-center justify-center">
                    <PiggyBank className="w-5 h-5 text-emerald-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-800">{t('goals.financialProgress') || 'Financial Progress'}</h3>
                    <p className="text-sm text-slate-600">
                      {t('goals.savedProgress', {
                        saved: goalsData.totalCurrentAmount.toLocaleString('en-IN'),
                        target: goalsData.totalTargetAmount.toLocaleString('en-IN')
                      }) || `You've saved ₹${goalsData.totalCurrentAmount.toLocaleString('en-IN')} of ₹${goalsData.totalTargetAmount.toLocaleString('en-IN')}`}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-24 sm:w-32 h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full transition-all"
                      style={{ width: `${Math.min(totalProgress, 100)}%` }}
                    />
                  </div>
                  <span className="text-sm font-semibold text-slate-700 whitespace-nowrap">
                    {totalProgress.toFixed(0)}%
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Goal Tracker Component */}
        <GoalTracker userSavings={goalsData.totalCurrentAmount} />
      </div>
    </DashboardLayout>
  )
}

export default function GoalsPage() {
  return (
    <OnboardingGuard>
      <GoalsContent />
    </OnboardingGuard>
  )
}
