'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import toast from 'react-hot-toast'

export default function OnboardingGuard({ children }) {
  const { data: session, status } = useSession()
  const router = useRouter()

  useEffect(() => {
    const checkAndRedirect = async () => {
      try {
        const response = await fetch('/api/onboarding')
        const data = await response.json()

        if (response.ok && data.profile) {
          // If onboarding is not complete, redirect immediately
          if (!data.profile.onboardingCompleted || !data.profile.monthlyIncome || !data.profile.city || !data.profile.familySize || !data.profile.age) {
            console.log('OnboardingGuard: Redirecting to onboarding')
            try {
              toast.info('Please complete your profile setup first')
            } catch (toastError) {
              console.warn('Toast error:', toastError)
            }
            router.replace('/onboarding')
            return
          }
        } else {
          // No profile found, redirect to onboarding
          console.log('OnboardingGuard: No profile found, redirecting to onboarding')
          router.replace('/onboarding')
        }
      } catch (error) {
        console.error('OnboardingGuard error:', error)
        router.replace('/onboarding')
      }
    }

    if (status === 'authenticated' && session?.user) {
      checkAndRedirect()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, session])

  // Only render children if authenticated
  if (status === 'authenticated') {
    return children
  }

  return null
}
