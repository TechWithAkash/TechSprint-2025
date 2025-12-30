'use client'

import { useSession } from 'next-auth/react'
import { useEffect, useState } from 'react'
import { usePathname } from 'next/navigation'

/**
 * OmnidimAuthWidget - Authenticated Voice Widget Component
 * 
 * This component dynamically loads the OmniDim Voice Widget script
 * ONLY for authenticated users on protected pages.
 * 
 * Features:
 * - ✅ Loads script only after successful authentication
 * - ✅ Hides on home page and authentication pages
 * - ✅ Automatically removes widget on logout
 * - ✅ Prevents unauthorized access to voice features
 * - ✅ Handles script loading states and errors
 * - ✅ Cleans up properly on component unmount
 * 
 * Usage: Place this component inside SessionProvider context
 */
export default function OmnidimAuthWidget() {
    const { data: session, status } = useSession()
    const pathname = usePathname()
    const [scriptLoaded, setScriptLoaded] = useState(false)

    // Pages where the widget should NOT be shown
    const excludedPages = [
        '/',                    // Home page
        '/auth/signin',         // Sign in page
        '/auth/signup',         // Sign up page
        '/auth/error',          // Auth error page
        '/auth/verify-email',   // Email verification
        '/auth/forgot-password',// Forgot password
        '/auth/reset-password', // Reset password
        '/privacy-policy',      // Privacy policy (optional)
        '/terms',               // Terms (optional)
    ]

    // Check if current page is excluded
    const isExcludedPage = excludedPages.some(page => pathname === page || pathname?.startsWith('/auth'))

    // Function to apply responsive styles to the widget
    const applyResponsiveStyles = () => {
        // Wait a bit for the widget DOM to be ready
        setTimeout(() => {
            // Try multiple selectors that OmniDim might use
            const possibleSelectors = [
                '[data-omnidim-widget]',
                '#omnidim-widget',
                '.omnidim-widget',
                '[class*="omnidim"]',
                '[id*="omnidim"]',
                'iframe[src*="omnidim"]'
            ]

            let widgetElement = null
            for (const selector of possibleSelectors) {
                widgetElement = document.querySelector(selector)
                if (widgetElement) break
            }

            // If we find the widget element or its container
            if (widgetElement) {
                const style = document.createElement('style')
                style.id = 'omnidim-responsive-fix'

                // Remove existing style if present
                const existingStyle = document.getElementById('omnidim-responsive-fix')
                if (existingStyle) {
                    existingStyle.remove()
                }

                style.textContent = `
                    /* Responsive positioning for OmniDim Widget */
                    [data-omnidim-widget],
                    #omnidim-widget,
                    .omnidim-widget,
                    [class*="omnidim"][class*="widget"],
                    [id*="omnidim"][id*="widget"] {
                        position: fixed !important;
                        z-index: 999 !important;
                        transition: all 0.3s ease !important;
                    }

                    /* Desktop: Bottom right corner */
                    @media (min-width: 1024px) {
                        [data-omnidim-widget],
                        #omnidim-widget,
                        .omnidim-widget,
                        [class*="omnidim"][class*="widget"],
                        [id*="omnidim"][id*="widget"] {
                            bottom: 24px !important;
                            right: 24px !important;
                            left: auto !important;
                        }
                    }

                    /* Tablet: Bottom right, with spacing */
                    @media (min-width: 768px) and (max-width: 1023px) {
                        [data-omnidim-widget],
                        #omnidim-widget,
                        .omnidim-widget,
                        [class*="omnidim"][class*="widget"],
                        [id*="omnidim"][id*="widget"] {
                            bottom: 20px !important;
                            right: 20px !important;
                            left: auto !important;
                        }
                    }

                    /* Mobile: Above bottom navigation (80px from bottom) */
                    @media (max-width: 767px) {
                        [data-omnidim-widget],
                        #omnidim-widget,
                        .omnidim-widget,
                        [class*="omnidim"][class*="widget"],
                        [id*="omnidim"][id*="widget"] {
                            bottom: 80px !important;
                            right: 16px !important;
                            left: auto !important;
                            max-width: calc(100vw - 32px) !important;
                        }
                    }

                    /* Extra safety for very small screens */
                    @media (max-width: 480px) {
                        [data-omnidim-widget],
                        #omnidim-widget,
                        .omnidim-widget,
                        [class*="omnidim"][class*="widget"],
                        [id*="omnidim"][id*="widget"] {
                            bottom: 85px !important;
                            right: 12px !important;
                            max-width: calc(100vw - 24px) !important;
                            scale: 0.95 !important;
                        }
                    }

                    /* Ensure it doesn't interfere with bottom navigation */
                    @media (max-height: 700px) and (max-width: 767px) {
                        [data-omnidim-widget],
                        #omnidim-widget,
                        .omnidim-widget,
                        [class*="omnidim"][class*="widget"],
                        [id*="omnidim"][id*="widget"] {
                            bottom: 90px !important;
                        }
                    }
                `

                document.head.appendChild(style)
                console.log('📱 Responsive styles applied to OmniDim widget')
            }
        }, 500) // Wait 500ms for widget to initialize
    }

    useEffect(() => {
        // Only load the script if:
        // 1. User is authenticated
        // 2. Not on an excluded page
        // 3. Script not already loaded
        if (status === 'authenticated' && session && !scriptLoaded && !isExcludedPage) {
            // Check if script already exists
            const existingScript = document.getElementById('omnidimension-web-widget')

            if (!existingScript) {
                // Create and inject the script
                const script = document.createElement('script')
                script.id = 'omnidimension-web-widget'
                script.src = 'https://backend.omnidim.io/web_widget.js?secret_key=0ed29bf08c262a06ac0aed7394bedf18'
                script.async = true

                // <script script id = "omnidimension-web-widget" async src = "https://omnidim.io/web_widget.js?secret_key=0ed29bf08c262a06ac0aed7394bedf18" ></script >

                // Add script to document head
                document.head.appendChild(script)

                script.onload = () => {
                    setScriptLoaded(true)
                    console.log('✅ OmniDim Voice Widget loaded for authenticated user')

                    // Apply responsive positioning after widget loads
                    applyResponsiveStyles()
                }

                script.onerror = () => {
                    console.error('❌ Failed to load OmniDim Voice Widget')
                }
            } else {
                setScriptLoaded(true)
                applyResponsiveStyles()
            }
        }

        // Apply responsive styles to prevent overlap with bottom navigation
        if (scriptLoaded && !isExcludedPage) {
            applyResponsiveStyles()
        }

        // Hide widget if on excluded page (even if authenticated)
        if (isExcludedPage && scriptLoaded) {
            const widgetContainer = document.querySelector('[data-omnidim-widget]')
            if (widgetContainer) {
                widgetContainer.style.display = 'none'
            }
        } else if (!isExcludedPage && scriptLoaded) {
            // Show widget if not on excluded page
            const widgetContainer = document.querySelector('[data-omnidim-widget]')
            if (widgetContainer) {
                widgetContainer.style.display = 'block'
            }
        }

        // Cleanup function to remove script when user logs out or navigates to excluded pages
        return () => {
            if (status === 'unauthenticated' || isExcludedPage) {
                const script = document.getElementById('omnidimension-web-widget')
                if (script && status === 'unauthenticated') {
                    script.remove()
                    setScriptLoaded(false)

                    // Also try to remove the widget element if it exists
                    const widgetContainer = document.querySelector('[data-omnidim-widget]')
                    if (widgetContainer) {
                        widgetContainer.remove()
                    }

                    // Remove responsive styles
                    const responsiveStyle = document.getElementById('omnidim-responsive-fix')
                    if (responsiveStyle) {
                        responsiveStyle.remove()
                    }

                    console.log('🔒 OmniDim Voice Widget removed (user logged out)')
                } else if (isExcludedPage) {
                    // Just hide on excluded pages, don't remove
                    const widgetContainer = document.querySelector('[data-omnidim-widget]')
                    if (widgetContainer) {
                        widgetContainer.style.display = 'none'
                    }
                }
            }
        }
    }, [status, session, scriptLoaded, pathname, isExcludedPage])

    // Don't render anything visible - the script handles its own UI
    return null
}
