'use client'

import { useEffect, useState, useCallback } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import OnboardingFlow from '@/components/onboarding/OnboardingFlow'
import Logo from '@/components/ui/Logo'
import { Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'

export default function OnboardingPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [checkingOnboarding, setCheckingOnboarding] = useState(true)
  const [onboardingComplete, setOnboardingComplete] = useState(false)

  useEffect(() => {
    const checkOnboardingStatus = async () => {
      try {
        console.log('Checking onboarding status...')
        const response = await fetch('/api/onboarding', {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          }
        })

        if (response.ok) {
          const data = await response.json()
          console.log('Onboarding API response:', { status: response.status, data })

          if (data.profile) {
            // Check if onboarding is complete
            const isComplete = data.profile.onboardingCompleted && data.profile.onboardingProgress >= 100

            if (isComplete) {
              console.log('Onboarding is complete, redirecting to dashboard')
              router.replace('/dashboard')
              return
            }
          }
        } else {
          console.log('Onboarding API returned error status:', response.status)
        }
      } catch (error) {
        console.error('Failed to check onboarding status:', error)
      }
      setCheckingOnboarding(false)
    }

    if (status === 'unauthenticated') {
      router.push('/auth/signin?message=login-required')
      return
    }

    if (status === 'authenticated' && session?.user) {
      checkOnboardingStatus()
    }
  }, [status, session, router])

  if (status === 'loading' || checkingOnboarding) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-emerald-50 to-blue-50">
        <div className="text-center">
          <div className="w-16 h-16 bg-gradient-to-r from-emerald-500 to-blue-500 rounded-2xl flex items-center justify-center mx-auto mb-4 animate-pulse">
            <Loader2 className="w-8 h-8 animate-spin text-white" />
          </div>
          <h2 className="text-xl font-semibold text-slate-800 mb-2">
            {checkingOnboarding ? 'Checking your profile...' : 'Setting up your experience...'}
          </h2>
          <p className="text-slate-600">Please wait while we prepare your profile</p>
        </div>
      </div>
    )
  }

  if (status === 'unauthenticated' || onboardingComplete) {
    return null // Will redirect
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Minimal Header */}
      <div className="sticky top-0 z-50 bg-white/90 backdrop-blur-lg border-b border-slate-100">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center space-x-2">
              <Logo size="large" />
              {/* <span className="text-lg font-bold text-slate-900">WealthWise</span> */}
            </div>

            {/* User Avatar */}
            <div className="flex items-center space-x-3">
              <span className="text-sm text-slate-600 hidden sm:block">
                {session?.user?.name?.split(' ')[0] || 'User'}
              </span>
              <div className="w-9 h-9 rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 flex items-center justify-center text-white font-semibold text-sm">
                {session?.user?.name?.charAt(0).toUpperCase() || 'U'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <OnboardingFlow />
    </div>
  )
}
