'use client'

import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import BudgetDisplay from '@/components/dashboard/BudgetDisplay'

function BudgetContent() {
  const { t } = useTranslation()

  return (
    <DashboardLayout title={t('budget.title')}>
      <BudgetDisplay />
    </DashboardLayout>
  )
}

export default function BudgetPage() {
  return (
    <OnboardingGuard>
      <BudgetContent />
    </OnboardingGuard>
  )
}
