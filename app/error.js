'use client'

import Link from 'next/link'

export default function GlobalError({ error, reset }) {
  return (
    <html>
      <body>
        <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
          <div className="max-w-lg w-full bg-white rounded-3xl shadow-2xl p-10 text-center space-y-6">
            <div className="w-24 h-24 bg-gradient-to-r from-red-500 to-orange-500 rounded-3xl mx-auto flex items-center justify-center">
              <svg className="w-12 h-12 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>

            <div className="space-y-3">
              <h1 className="text-3xl font-bold text-slate-800">
                Something went wrong!
              </h1>
              <p className="text-slate-600 text-lg">
                We&apos;re sorry for the inconvenience. Please try refreshing the page.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4">
              <button
                onClick={reset}
                className="flex-1 bg-gradient-to-r from-emerald-600 to-blue-600 hover:from-emerald-700 hover:to-blue-700 text-white px-8 py-4 rounded-xl font-semibold transition-all duration-300 shadow-lg hover:shadow-xl text-lg"
              >
                Try Again
              </button>
              <Link
                href="/"
                className="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 px-8 py-4 rounded-xl font-semibold transition-all duration-300 text-lg text-center"
              >
                Go Home
              </Link>
            </div>
          </div>
        </div>
      </body>
    </html>
  )
}
