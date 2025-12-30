'use client'

import Link from 'next/link'
import { WifiOff, Home, RefreshCw } from 'lucide-react'

// Force dynamic rendering
export const dynamic = 'force-dynamic'

export default function OfflinePage() {
    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center p-4">
            <div className="max-w-md w-full">
                {/* Offline Icon */}
                <div className="flex justify-center mb-6">
                    <div className="w-24 h-24 bg-gradient-to-br from-slate-200 to-slate-300 rounded-full flex items-center justify-center">
                        <WifiOff className="w-12 h-12 text-slate-600" />
                    </div>
                </div>

                {/* Content */}
                <div className="bg-white rounded-2xl shadow-xl p-8 text-center">
                    <h1 className="text-2xl font-bold text-slate-800 mb-2">
                        You&apos;re Offline
                    </h1>
                    <p className="text-slate-600 mb-6">
                        Please check your internet connection and try again.
                    </p>

                    {/* Actions */}
                    <div className="space-y-3">
                        <button
                            onClick={() => window.location.reload()}
                            className="w-full bg-gradient-to-r from-emerald-500 to-teal-500 text-white font-semibold py-3 px-6 rounded-xl hover:shadow-lg transition-all active:scale-95 flex items-center justify-center gap-2"
                        >
                            <RefreshCw className="w-5 h-5" />
                            Try Again
                        </button>

                        <Link
                            href="/dashboard"
                            className="w-full bg-slate-100 text-slate-700 font-semibold py-3 px-6 rounded-xl hover:bg-slate-200 transition-all flex items-center justify-center gap-2"
                        >
                            <Home className="w-5 h-5" />
                            Go to Dashboard
                        </Link>
                    </div>

                    {/* Info */}
                    <div className="mt-6 p-4 bg-blue-50 rounded-xl">
                        <p className="text-xs text-blue-900">
                            <span className="font-semibold">💡 Tip:</span> Some features may still work offline thanks to PWA caching!
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}
