'use client'

import { useEffect } from 'react'
import Link from 'next/link'

export default function Error({ error, reset }) {
  useEffect(() => {
    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('Dashboard Error:', error)
    }
  }, [error])

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-orange-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-3xl shadow-2xl p-8 text-center space-y-6">
        {/* Error Icon */}
        <div className="relative">
          <div className="w-20 h-20 bg-gradient-to-r from-red-500 to-orange-500 rounded-2xl mx-auto flex items-center justify-center">
            <svg className="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
        </div>

        {/* Error Message */}
        <div className="space-y-2">
          <h2 className="text-2xl font-bold text-slate-800">Oops! Something went wrong</h2>
          <p className="text-slate-600">
            We encountered an error while loading your dashboard.
          </p>
        </div>

        {/* Error Details (Development only) */}
        {process.env.NODE_ENV === 'development' && error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-left">
            <p className="text-sm text-red-700 font-mono break-all">
              {error.message || 'Unknown error'}
            </p>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={reset}
            className="flex-1 bg-gradient-to-r from-emerald-600 to-blue-600 hover:from-emerald-700 hover:to-blue-700 text-white px-6 py-3 rounded-xl font-semibold transition-all duration-300 shadow-lg hover:shadow-xl"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-3 rounded-xl font-semibold transition-all duration-300"
          >
            Go Home
          </Link>
        </div>

        {/* Support Link */}
        <p className="text-sm text-slate-500">
          If the problem persists, please{' '}
          <a href="mailto:support@mywealthwise.tech" className="text-emerald-600 hover:underline">
            contact support
          </a>
        </p>
      </div>
    </div>
  )
}
