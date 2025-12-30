'use client'

import { useEffect, useRef } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { motion, useMotionValue, useTransform, animate } from 'framer-motion'

const triggerHaptic = () => {
  if (typeof window !== 'undefined' && 'vibrate' in navigator) {
    navigator.vibrate(10)
  }
}

// Navigation flow map
const NAVIGATION_MAP = {
  '/dashboard': {
    left: '/dashboard/budget',
    right: '/dashboard/goals'
  },
  '/dashboard/expenses': {
    left: '/dashboard/analytics',
    right: '/dashboard'
  },
  '/dashboard/goals': {
    left: '/dashboard',
    right: '/dashboard/budget'
  },
  '/dashboard/analytics': {
    left: '/dashboard/expenses',
    right: '/dashboard/goals'
  },
  '/dashboard/budget': {
    left: '/dashboard/goals',
    right: '/dashboard/expenses'
  }
}

export default function SwipeGestureHandler({ children }) {
  const router = useRouter()
  const pathname = usePathname()
  const x = useMotionValue(0)
  const containerRef = useRef(null)
  const startX = useRef(0)
  const isDragging = useRef(false)

  const opacity = useTransform(x, [-200, 0, 200], [0.5, 1, 0.5])
  const scale = useTransform(x, [-200, 0, 200], [0.95, 1, 0.95])

  // Create transforms for hints (always call hooks unconditionally)
  const leftHintOpacity = useTransform(x, [0, 100], [0, 1])
  const leftHintScale = useTransform(x, [0, 100], [0.8, 1])
  const rightHintOpacity = useTransform(x, [-100, 0], [1, 0])
  const rightHintScale = useTransform(x, [-100, 0], [1, 0.8])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    let touchStartX = 0
    let touchStartY = 0
    let isHorizontalSwipe = false
    let hasVibratedThreshold = false

    const handleTouchStart = (e) => {
      // Don't interfere with scrollable content
      const target = e.target
      const isScrollable =
        target.scrollHeight > target.clientHeight ||
        target.closest('[data-scrollable="true"]')

      if (isScrollable) return

      touchStartX = e.touches[0].clientX
      touchStartY = e.touches[0].clientY
      startX.current = touchStartX
      isDragging.current = false
      isHorizontalSwipe = false
      hasVibratedThreshold = false
    }

    const handleTouchMove = (e) => {
      if (!touchStartX) return

      const currentX = e.touches[0].clientX
      const currentY = e.touches[0].clientY
      const diffX = currentX - touchStartX
      const diffY = currentY - touchStartY

      // Determine if this is a horizontal swipe
      if (!isDragging.current && !isHorizontalSwipe) {
        if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 10) {
          isHorizontalSwipe = true
          isDragging.current = true
        } else if (Math.abs(diffY) > 10) {
          // Vertical scroll detected, cancel swipe
          return
        }
      }

      if (isHorizontalSwipe && isDragging.current) {
        e.preventDefault()

        const navMap = NAVIGATION_MAP[pathname]
        if (!navMap) return

        // Check if swipe direction has a destination
        const hasLeftNav = diffX > 0 && navMap.left
        const hasRightNav = diffX < 0 && navMap.right

        if (hasLeftNav || hasRightNav) {
          x.set(diffX * 0.5) // Apply resistance

          // Haptic feedback at threshold
          if (!hasVibratedThreshold && Math.abs(diffX) > 100) {
            triggerHaptic()
            hasVibratedThreshold = true
          }
        }
      }
    }

    const handleTouchEnd = () => {
      if (!isDragging.current || !isHorizontalSwipe) {
        x.set(0)
        return
      }

      const currentX = x.get()
      const threshold = 80
      const navMap = NAVIGATION_MAP[pathname]

      if (Math.abs(currentX) > threshold && navMap) {
        let targetPath = null

        if (currentX > 0 && navMap.left) {
          targetPath = navMap.left
        } else if (currentX < 0 && navMap.right) {
          targetPath = navMap.right
        }

        if (targetPath) {
          triggerHaptic()

          // Animate out
          animate(x, currentX > 0 ? 400 : -400, {
            duration: 0.3,
            ease: 'easeOut',
            onComplete: () => {
              router.push(targetPath)
              x.set(0)
            }
          })
          return
        }
      }

      // Snap back
      animate(x, 0, {
        type: 'spring',
        stiffness: 300,
        damping: 30
      })

      isDragging.current = false
      isHorizontalSwipe = false
    }

    container.addEventListener('touchstart', handleTouchStart, { passive: true })
    container.addEventListener('touchmove', handleTouchMove, { passive: false })
    container.addEventListener('touchend', handleTouchEnd)

    return () => {
      container.removeEventListener('touchstart', handleTouchStart)
      container.removeEventListener('touchmove', handleTouchMove)
      container.removeEventListener('touchend', handleTouchEnd)
    }
  }, [pathname, router, x])

  const navMap = NAVIGATION_MAP[pathname]

  return (
    <div ref={containerRef} className="relative overflow-hidden h-full">
      {/* Left Hint */}
      {navMap?.left && (
        <motion.div
          className="absolute left-4 top-1/2 -translate-y-1/2 z-0 pointer-events-none"
          style={{
            opacity: leftHintOpacity,
            scale: leftHintScale
          }}
        >
          <div className="bg-gradient-to-r from-emerald-500 to-teal-500 text-white px-4 py-2 rounded-full shadow-lg font-semibold text-sm whitespace-nowrap">
            ← Previous
          </div>
        </motion.div>
      )}

      {/* Right Hint */}
      {navMap?.right && (
        <motion.div
          className="absolute right-4 top-1/2 -translate-y-1/2 z-0 pointer-events-none"
          style={{
            opacity: rightHintOpacity,
            scale: rightHintScale
          }}
        >
          <div className="bg-gradient-to-r from-blue-500 to-purple-500 text-white px-4 py-2 rounded-full shadow-lg font-semibold text-sm whitespace-nowrap">
            Next →
          </div>
        </motion.div>
      )}

      {/* Content */}
      <motion.div style={{ x, opacity, scale }} className="relative z-10">
        {children}
      </motion.div>
    </div>
  )
}
