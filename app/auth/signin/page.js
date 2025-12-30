'use client'

import { useState, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { signIn } from 'next-auth/react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import Link from 'next/link'
import { useTranslation } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Eye, EyeOff, TrendingUp, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'

function SignInForm() {
  const { t } = useTranslation()
  const router = useRouter()
  const searchParams = useSearchParams()
  const callbackUrl = searchParams.get('callbackUrl') || '/dashboard'
  const message = searchParams.get('message')
  const emailParam = searchParams.get('email')
  const errorParam = searchParams.get('error')

  const [isLoading, setIsLoading] = useState(false)
  const [isGoogleLoading, setIsGoogleLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [authError, setAuthError] = useState(null)

  const signinSchema = z.object({
    email: z.string().email(t('auth.signin.emailRequired')),
    password: z.string().min(1, t('auth.signin.passwordRequired')),
    rememberMe: z.boolean().optional()
  })

  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm({
    resolver: zodResolver(signinSchema),
    defaultValues: {
      email: emailParam || '',
      rememberMe: false
    }
  })

  useEffect(() => {
    if (message === 'registration-complete') {
      toast.success(t('auth.signin.registrationComplete'), { duration: 5000 })
    }

    if (errorParam) {
      const errorMessages = {
        'OAuthAccountNotLinked': 'This email is already linked to another account.',
        'OAuthSignin': 'Error connecting to Google. Please try again.',
        'OAuthCallback': 'Authentication error. Please try again.',
        'CredentialsSignin': 'Invalid email or password.',
        'default': 'An authentication error occurred.'
      }
      setAuthError(errorMessages[errorParam] || errorMessages.default)
    }
  }, [message, errorParam, t])

  const onSubmit = async (data) => {
    setIsLoading(true)
    setAuthError(null)

    try {
      const result = await signIn('credentials', {
        email: data.email,
        password: data.password,
        redirect: false
      })

      if (result?.error) {
        toast.error(t('auth.signin.invalidCredentials'))
      } else {
        toast.success(t('auth.signin.welcomeBack'))
        router.push(callbackUrl)
        router.refresh()
      }
    } catch (error) {
      toast.error(t('auth.signin.networkError'))
    } finally {
      setIsLoading(false)
    }
  }

  const handleGoogleSignIn = async () => {
    setIsGoogleLoading(true)
    setAuthError(null)

    try {
      await signIn('google', { callbackUrl, redirect: true })
    } catch (error) {
      setAuthError('Failed to sign in with Google. Please try again.')
      toast.error(t('auth.signin.googleError'))
      setIsGoogleLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Header */}
      <header className="p-4">
        <Link href="/" className="flex items-center gap-2 w-fit">
          <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-lg flex items-center justify-center">
            <TrendingUp className="w-5 h-5 text-white" />
          </div>
          <span className="text-xl font-bold text-slate-800">
            Wealth<span className="text-emerald-600">Wise</span>
          </span>
        </Link>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center px-4 py-8">
        <div className="w-full max-w-sm">
          {/* Title */}
          <div className="text-center mb-8">
            <h1 className="text-2xl font-bold text-slate-900 mb-2">
              {t('auth.signin.title')}
            </h1>
            <p className="text-slate-600">
              {t('auth.signin.subtitle')}
            </p>
          </div>

          {/* Error Alert */}
          {authError && (
            <div className="mb-6 p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-red-700">{authError}</p>
                <p className="text-xs text-red-600 mt-1">
                  Try disabling ad blockers or use incognito mode.
                </p>
              </div>
            </div>
          )}

          {/* Auth Card */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            {/* Google Sign In */}
            <Button
              type="button"
              variant="outline"
              className="w-full h-11 mb-4 border-slate-200 hover:bg-slate-50 font-medium"
              onClick={handleGoogleSignIn}
              disabled={isGoogleLoading || isLoading}
            >
              {isGoogleLoading ? (
                <div className="w-5 h-5 border-2 border-slate-300 border-t-slate-600 rounded-full animate-spin" />
              ) : (
                <>
                  <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  {t('auth.signin.googleButton')}
                </>
              )}
            </Button>

            {/* Divider */}
            <div className="relative my-4">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-200" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-white px-2 text-slate-500">{t('auth.signin.orContinue')}</span>
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-slate-700 mb-1.5">
                  {t('auth.signin.email')}
                </label>
                <Input
                  id="email"
                  type="email"
                  placeholder={t('auth.signin.emailPlaceholder')}
                  autoComplete="email"
                  disabled={isLoading}
                  {...register('email')}
                  className="h-11"
                />
                {errors.email && (
                  <p className="text-sm text-red-600 mt-1">{errors.email.message}</p>
                )}
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="password" className="block text-sm font-medium text-slate-700">
                    {t('auth.signin.password')}
                  </label>
                  <Link
                    href="/auth/forgot-password"
                    className="text-sm text-emerald-600 hover:text-emerald-700"
                  >
                    {t('auth.signin.forgotPassword')}
                  </Link>
                </div>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder={t('auth.signin.passwordPlaceholder')}
                    autoComplete="current-password"
                    disabled={isLoading}
                    {...register('password')}
                    className="h-11 pr-10"
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {errors.password && (
                  <p className="text-sm text-red-600 mt-1">{errors.password.message}</p>
                )}
              </div>

              <div className="flex items-center">
                <input
                  id="rememberMe"
                  type="checkbox"
                  {...register('rememberMe')}
                  className="h-4 w-4 text-emerald-600 border-slate-300 rounded focus:ring-emerald-500"
                />
                <label htmlFor="rememberMe" className="ml-2 text-sm text-slate-600">
                  {t('auth.signin.rememberMe')}
                </label>
              </div>

              <Button
                type="submit"
                className="w-full h-11 bg-emerald-600 hover:bg-emerald-700"
                disabled={isLoading}
              >
                {isLoading ? (
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  t('auth.signin.signinButton')
                )}
              </Button>
            </form>
          </div>

          {/* Sign Up Link */}
          <p className="text-center text-sm text-slate-600 mt-6">
            {t('auth.signin.noAccount')}{' '}
            <Link href="/auth/signup" className="font-medium text-emerald-600 hover:text-emerald-700">
              {t('auth.signin.createAccount')}
            </Link>
          </p>
        </div>
      </main>
    </div>
  )
}

export default function SignInPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <SignInForm />
    </Suspense>
  )
}
