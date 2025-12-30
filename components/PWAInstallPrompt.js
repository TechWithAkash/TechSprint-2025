'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Download, X, Smartphone, Zap } from 'lucide-react'

export default function PWAInstallPrompt() {
    const [deferredPrompt, setDeferredPrompt] = useState(null)
    const [showPrompt, setShowPrompt] = useState(false)
    const [isIOS, setIsIOS] = useState(false)
    const [isStandalone, setIsStandalone] = useState(false)

    useEffect(() => {
        // Check if already installed
        const isInStandaloneMode = () => {
            return (
                window.matchMedia('(display-mode: standalone)').matches ||
                window.navigator.standalone ||
                document.referrer.includes('android-app://')
            )
        }

        // Check if iOS
        const checkIsIOS = () => {
            const userAgent = window.navigator.userAgent.toLowerCase()
            return /iphone|ipad|ipod/.test(userAgent)
        }

        setIsStandalone(isInStandaloneMode())
        setIsIOS(checkIsIOS())

        // Don't show if already installed
        if (isInStandaloneMode()) {
            return
        }

        // Check if user dismissed the prompt before
        const dismissed = localStorage.getItem('pwa-prompt-dismissed')
        const dismissedTime = localStorage.getItem('pwa-prompt-dismissed-time')

        // Show again after 7 days
        if (dismissed && dismissedTime) {
            const daysSinceDismissed = (Date.now() - parseInt(dismissedTime)) / (1000 * 60 * 60 * 24)
            if (daysSinceDismissed < 7) {
                return
            }
        }

        // For iOS, show manual instructions after 3 seconds
        if (checkIsIOS()) {
            const timer = setTimeout(() => {
                setShowPrompt(true)
            }, 3000)
            return () => clearTimeout(timer)
        }

        // Listen for beforeinstallprompt event (Android/Chrome)
        const handleBeforeInstallPrompt = (e) => {
            e.preventDefault()
            setDeferredPrompt(e)

            // Show prompt after 3 seconds
            setTimeout(() => {
                setShowPrompt(true)
            }, 3000)
        }

        window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt)

        return () => {
            window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
        }
    }, [])

    const handleInstallClick = async () => {
        if (!deferredPrompt) return

        // Show native install prompt
        deferredPrompt.prompt()

        // Wait for user choice
        const { outcome } = await deferredPrompt.userChoice

        console.log(`User ${outcome} the install prompt`)

        // Clear the deferred prompt
        setDeferredPrompt(null)
        setShowPrompt(false)

        // Track installation
        if (outcome === 'accepted') {
            localStorage.setItem('pwa-installed', 'true')
        }
    }

    const handleDismiss = () => {
        setShowPrompt(false)
        localStorage.setItem('pwa-prompt-dismissed', 'true')
        localStorage.setItem('pwa-prompt-dismissed-time', Date.now().toString())
    }

    // Don't render if already in standalone mode
    if (isStandalone) return null

    return (
        <AnimatePresence>
            {showPrompt && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-black/20 backdrop-blur-sm z-[100]"
                        onClick={handleDismiss}
                    />

                    {/* Prompt Card */}
                    <motion.div
                        initial={{ opacity: 0, y: 100, scale: 0.9 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 100, scale: 0.9 }}
                        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
                        className="fixed bottom-20 left-4 right-4 md:left-auto md:right-6 md:bottom-6 md:w-96 z-[101] safe-area-inset-bottom"
                    >
                        <div className="bg-white rounded-2xl shadow-2xl border-2 border-emerald-100 overflow-hidden">
                            {/* Close Button */}
                            <button
                                onClick={handleDismiss}
                                className="absolute top-3 right-3 p-1.5 rounded-full hover:bg-slate-100 transition-colors z-10"
                            >
                                <X className="w-4 h-4 text-slate-500" />
                            </button>

                            {/* Header with Gradient */}
                            <div className="bg-gradient-to-r from-emerald-500 to-teal-500 p-4 text-white">
                                <div className="flex items-center gap-3">
                                    <div className="w-12 h-12 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center">
                                        <Smartphone className="w-6 h-6" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-lg">Install WealthWise</h3>
                                        <p className="text-xs text-white/90">Get the app experience</p>
                                    </div>
                                </div>
                            </div>

                            {/* Content */}
                            <div className="p-4 space-y-3">
                                <div className="flex items-start gap-3">
                                    <div className="mt-1">
                                        <Zap className="w-5 h-5 text-emerald-600" />
                                    </div>
                                    <div>
                                        <p className="text-sm text-slate-700 leading-relaxed">
                                            <span className="font-semibold">Install the app for a faster and smoother experience!</span>
                                        </p>
                                    </div>
                                </div>

                                {/* Benefits */}
                                <div className="grid grid-cols-2 gap-2 pt-2">
                                    <div className="flex items-center gap-2 text-xs text-slate-600">
                                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                                        <span>Works offline</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-xs text-slate-600">
                                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                                        <span>Instant loading</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-xs text-slate-600">
                                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                                        <span>No app store</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-xs text-slate-600">
                                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                                        <span>Home screen</span>
                                    </div>
                                </div>

                                {/* iOS Instructions */}
                                {isIOS && (
                                    <div className="mt-3 p-3 bg-blue-50 rounded-xl border border-blue-100">
                                        <p className="text-xs text-blue-900 font-medium mb-2">📱 How to install on iOS:</p>
                                        <ol className="text-xs text-blue-800 space-y-1 list-decimal list-inside">
                                            <li>Tap the <span className="font-semibold">Share</span> button below</li>
                                            <li>Scroll and tap <span className="font-semibold">&quot;Add to Home Screen&quot;</span></li>
                                            <li>Tap <span className="font-semibold">&quot;Add&quot;</span> in the top-right</li>
                                        </ol>
                                    </div>
                                )}

                                {/* Action Buttons */}
                                <div className="flex gap-2 pt-2">
                                    {!isIOS && deferredPrompt && (
                                        <button
                                            onClick={handleInstallClick}
                                            className="flex-1 bg-gradient-to-r from-emerald-500 to-teal-500 text-white font-semibold py-3 px-4 rounded-xl hover:shadow-lg transition-all active:scale-95 flex items-center justify-center gap-2"
                                        >
                                            <Download className="w-4 h-4" />
                                            Install Now
                                        </button>
                                    )}
                                    <button
                                        onClick={handleDismiss}
                                        className="px-4 py-3 text-sm font-medium text-slate-600 hover:bg-slate-50 rounded-xl transition-colors"
                                    >
                                        {isIOS ? 'Got it' : 'Maybe Later'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    )
}
