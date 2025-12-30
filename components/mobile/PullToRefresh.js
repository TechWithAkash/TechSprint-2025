'use client'

import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RefreshCw } from 'lucide-react'

export default function PullToRefresh({ onRefresh, children }) {
  const [pullDistance, setPullDistance] = useState(0)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [canPull, setCanPull] = useState(false)
  const startY = useRef(0)
  const containerRef = useRef(null)

  const threshold = 80 // Pull distance needed to trigger refresh

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    let touchStartY = 0
    let isTouching = false

    const handleTouchStart = (e) => {
      // Only allow pull if at top of scroll
      if (container.scrollTop === 0) {
        setCanPull(true)
        touchStartY = e.touches[0].clientY
        startY.current = touchStartY
        isTouching = true
      }
    }

    const handleTouchMove = (e) => {
      if (!isTouching || !canPull || isRefreshing) return

      const currentY = e.touches[0].clientY
      const distance = currentY - touchStartY

      // Only allow pulling down, not up
      if (distance > 0 && container.scrollTop === 0) {
        setPullDistance(Math.min(distance * 0.5, threshold + 20)) // Apply resistance

        // Prevent default scroll when pulling
        if (distance > 10) {
          e.preventDefault()
        }
      }
    }

    const handleTouchEnd = () => {
      isTouching = false
      setCanPull(false)

      if (pullDistance >= threshold && !isRefreshing) {
        setIsRefreshing(true)
        setPullDistance(threshold)

        // Trigger refresh
        onRefresh?.().finally(() => {
          setIsRefreshing(false)
          setPullDistance(0)
        })
      } else {
        setPullDistance(0)
      }
    }

    container.addEventListener('touchstart', handleTouchStart, { passive: true })
    container.addEventListener('touchmove', handleTouchMove, { passive: false })
    container.addEventListener('touchend', handleTouchEnd)

    return () => {
      container.removeEventListener('touchstart', handleTouchStart)
      container.removeEventListener('touchmove', handleTouchMove)
      container.removeEventListener('touchend', handleTouchEnd)
    }
  }, [canPull, pullDistance, isRefreshing, onRefresh, threshold])

  const progress = Math.min((pullDistance / threshold) * 100, 100)
  const rotation = (pullDistance / threshold) * 360

  return (
    <div ref={containerRef} className="relative overflow-auto h-full">
      {/* Pull Indicator */}
      <AnimatePresence>
        {pullDistance > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{
              opacity: 1,
              y: Math.min(pullDistance - 40, 40)
            }}
            exit={{ opacity: 0 }}
            className="absolute top-0 left-1/2 -translate-x-1/2 z-50 pointer-events-none"
          >
            <div className="bg-white rounded-full shadow-lg p-3 border-2 border-emerald-200">
              <motion.div
                animate={{
                  rotate: isRefreshing ? 360 : rotation,
                  scale: pullDistance >= threshold ? 1.1 : 1
                }}
                transition={{
                  rotate: isRefreshing ? {
                    duration: 1,
                    repeat: Infinity,
                    ease: 'linear'
                  } : {
                    duration: 0
                  },
                  scale: { type: 'spring', stiffness: 300 }
                }}
              >
                <RefreshCw
                  className={`w-6 h-6 ${
                    pullDistance >= threshold
                      ? 'text-emerald-600'
                      : 'text-slate-400'
                  }`}
                  strokeWidth={2.5}
                />
              </motion.div>
            </div>

            {/* Progress Ring */}
            <svg
              className="absolute inset-0 w-full h-full -rotate-90"
              viewBox="0 0 100 100"
            >
              <circle
                cx="50"
                cy="50"
                r="45"
                fill="none"
                stroke="#e5e7eb"
                strokeWidth="3"
              />
              <motion.circle
                cx="50"
                cy="50"
                r="45"
                fill="none"
                stroke="url(#gradient)"
                strokeWidth="3"
                strokeLinecap="round"
                strokeDasharray={283}
                strokeDashoffset={283 - (283 * progress) / 100}
                transition={{ duration: 0.1 }}
              />
              <defs>
                <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#14b8a6" />
                </linearGradient>
              </defs>
            </svg>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Content */}
      <div
        style={{
          transform: `translateY(${isRefreshing ? '60px' : '0px'})`,
          transition: isRefreshing ? 'transform 0.2s' : 'transform 0.3s'
        }}
      >
        {children}
      </div>
    </div>
  )
}
