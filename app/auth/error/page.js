'use client'

import { Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { AlertCircle, ArrowLeft, Mail, RefreshCw, Home } from 'lucide-react'
import Logo from '@/components/ui/Logo'

function ErrorContent() {
  const searchParams = useSearchParams()
  const error = searchParams?.get('error') || 'Default'

  // Map NextAuth errors to user-friendly messages
  const errorMessages = {
    Configuration: {
      title: 'Configuration Error',
      message: 'There is a problem with the authentication configuration. This is likely temporary.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'Please wait a few minutes and try again. If the problem persists, contact support.'
    },
    AccessDenied: {
      title: 'Access Denied',
      message: 'You do not have permission to sign in.',
      icon: AlertCircle,
      color: 'orange',
      suggestion: 'Please check your account status or contact an administrator.'
    },
    Verification: {
      title: 'Verification Failed',
      message: 'The verification link has expired or has already been used.',
      icon: Mail,
      color: 'blue',
      suggestion: 'Please request a new verification email from the sign-in page.'
    },
    OAuthSignin: {
      title: 'OAuth Sign In Error',
      message: 'Could not initiate sign in with your OAuth provider.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'This may be caused by browser extensions blocking the request. Try disabling ad blockers.'
    },
    OAuthCallback: {
      title: 'OAuth Callback Error',
      message: 'An error occurred while processing the OAuth response.',
      icon: RefreshCw,
      color: 'orange',
      suggestion: 'Please try signing in again. Make sure third-party cookies are enabled.'
    },
    OAuthCreateAccount: {
      title: 'Account Creation Failed',
      message: 'Could not create an account with your OAuth provider.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'This email may already be registered. Try signing in with email/password instead.'
    },
    EmailCreateAccount: {
      title: 'Email Account Creation Failed',
      message: 'Could not create an account with this email address.',
      icon: Mail,
      color: 'orange',
      suggestion: 'This email may already be in use. Try using the forgot password option.'
    },
    Callback: {
      title: 'Callback Error',
      message: 'An error occurred during the authentication process.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'Please try again. If the problem continues, try clearing your browser cache.'
    },
    OAuthAccountNotLinked: {
      title: 'Account Not Linked',
      message: 'This email is already associated with a different sign-in method.',
      icon: AlertCircle,
      color: 'orange',
      suggestion: 'Please sign in using the method you originally used to create your account.'
    },
    EmailSignin: {
      title: 'Email Sign In Error',
      message: 'Unable to send the sign-in email.',
      icon: Mail,
      color: 'red',
      suggestion: 'Please check that your email address is correct and try again.'
    },
    CredentialsSignin: {
      title: 'Sign In Failed',
      message: 'The email or password you entered is incorrect.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'Please check your credentials or use the forgot password option.'
    },
    SessionRequired: {
      title: 'Session Required',
      message: 'You must be signed in to access this page.',
      icon: AlertCircle,
      color: 'blue',
      suggestion: 'Please sign in to continue.'
    },
    Default: {
      title: 'Authentication Error',
      message: 'An unexpected error occurred during authentication.',
      icon: AlertCircle,
      color: 'red',
      suggestion: 'Please try again. If the problem persists, contact support.'
    }
  }

  const errorInfo = errorMessages[error] || errorMessages.Default
  const ErrorIcon = errorInfo.icon

  const colorClasses = {
    red: {
      bg: 'bg-red-100',
      text: 'text-red-500',
      border: 'border-red-200'
    },
    orange: {
      bg: 'bg-orange-100',
      text: 'text-orange-500',
      border: 'border-orange-200'
    },
    blue: {
      bg: 'bg-blue-100',
      text: 'text-blue-500',
      border: 'border-blue-200'
    }
  }

  const colors = colorClasses[errorInfo.color] || colorClasses.red

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <Logo size="large" />
        </div>

        {/* Error Card */}
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-slate-200">
          {/* Error Icon */}
          <div className="flex justify-center mb-6">
            <div className={`w-16 h-16 rounded-full ${colors.bg} flex items-center justify-center`}>
              <ErrorIcon className={`w-8 h-8 ${colors.text}`} />
            </div>
          </div>

          {/* Error Content */}
          <div className="text-center mb-8">
            <h1 className="text-2xl font-bold text-slate-800 mb-3">
              {errorInfo.title}
            </h1>
            <p className="text-slate-600 leading-relaxed mb-4">
              {errorInfo.message}
            </p>
            <p className="text-sm text-slate-500 italic">
              {errorInfo.suggestion}
            </p>

            {/* Show technical error for debugging (only in dev) */}
            {process.env.NODE_ENV === 'development' && error && (
              <div className="mt-4 p-3 bg-slate-100 rounded-lg border border-slate-200">
                <p className="text-xs text-slate-500 font-mono">
                  Error Code: {error}
                </p>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="space-y-3">
            <Link
              href="/auth/signin"
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-500 to-teal-500 text-white py-3 px-4 rounded-xl font-semibold hover:from-emerald-600 hover:to-teal-600 transition-all duration-200 shadow-md hover:shadow-lg transform hover:scale-[1.02]"
            >
              <ArrowLeft className="w-5 h-5" />
              Back to Sign In
            </Link>

            <Link
              href="/"
              className="w-full flex items-center justify-center gap-2 bg-slate-100 text-slate-700 py-3 px-4 rounded-xl font-semibold hover:bg-slate-200 transition-all duration-200 transform hover:scale-[1.02]"
            >
              <Home className="w-5 h-5" />
              Go to Home
            </Link>
          </div>

          {/* Support Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-slate-500">
              Need help?{' '}
              <a
                href="mailto:support@mywealthwise.tech"
                className="text-emerald-600 hover:text-emerald-700 font-semibold"
              >
                Contact Support
              </a>
            </p>
          </div>
        </div>

        {/* Additional Help */}
        <div className="mt-6 bg-white/60 backdrop-blur rounded-xl p-4 border border-slate-200">
          <p className="text-sm font-semibold text-slate-700 mb-2">
            Common Solutions:
          </p>
          <ul className="text-xs text-slate-600 space-y-1.5">
            <li className="flex items-start gap-2">
              <span className="text-emerald-600 font-bold">•</span>
              <span>Clear your browser cache and cookies</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-600 font-bold">•</span>
              <span>Disable ad blockers and privacy extensions</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-600 font-bold">•</span>
              <span>Enable third-party cookies in browser settings</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-600 font-bold">•</span>
              <span>Try using a different browser or incognito mode</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  )
}

export default function AuthErrorPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-emerald-600 mx-auto"></div>
          <p className="text-slate-600 mt-4">Loading...</p>
        </div>
      </div>
    }>
      <ErrorContent />
    </Suspense>
  )
}