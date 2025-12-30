'use client'

import { useEffect } from 'react'

export default function PWARegister() {
    useEffect(() => {
        if (
            typeof window !== 'undefined' &&
            'serviceWorker' in navigator &&
            process.env.NODE_ENV === 'production'
        ) {
            // Register service worker
            navigator.serviceWorker
                .register('/sw.js', { scope: '/' })
                .then((registration) => {
                    console.log('✅ Service Worker registered:', registration.scope)

                    // Check for updates periodically
                    registration.addEventListener('updatefound', () => {
                        const newWorker = registration.installing

                        newWorker?.addEventListener('statechange', () => {
                            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                                // New service worker available
                                console.log('🔄 New version available! Refresh to update.')

                                // Optional: Show update notification
                                if (window.confirm('New version available! Refresh to update?')) {
                                    newWorker.postMessage({ type: 'SKIP_WAITING' })
                                    window.location.reload()
                                }
                            }
                        })
                    })
                })
                .catch((error) => {
                    console.error('❌ Service Worker registration failed:', error)
                })

            // Handle controller change
            navigator.serviceWorker.addEventListener('controllerchange', () => {
                console.log('🔄 Service Worker controller changed')
                window.location.reload()
            })

            // Check for updates every 60 minutes
            setInterval(() => {
                navigator.serviceWorker.getRegistration().then((registration) => {
                    registration?.update()
                })
            }, 60 * 60 * 1000)
        }
    }, [])

    return null
}
