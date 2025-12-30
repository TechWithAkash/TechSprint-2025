'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import AchievementBadge from './AchievementBadge'
import {
  Trophy, Target, PiggyBank, Wallet, X,
  Sparkles, ChevronRight
} from 'lucide-react'

const CATEGORY_INFO = {
  tracking: {
    title: 'Tracking',
    description: 'Master expense logging',
    icon: Target,
    color: 'text-blue-600',
    bg: 'bg-blue-50'
  },
  savings: {
    title: 'Savings',
    description: 'Build your wealth',
    icon: PiggyBank,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50'
  },
  budget: {
    title: 'Budget',
    description: 'Stay within limits',
    icon: Wallet,
    color: 'text-purple-600',
    bg: 'bg-purple-50'
  },
  goals: {
    title: 'Goals',
    description: 'Achieve your dreams',
    icon: Trophy,
    color: 'text-amber-600',
    bg: 'bg-amber-50'
  }
}

export default function AchievementsModal({ isOpen, onClose }) {
  const [loading, setLoading] = useState(true)
  const [achievements, setAchievements] = useState({})
  const [stats, setStats] = useState(null)
  const [activeCategory, setActiveCategory] = useState('all')
  const [celebrating, setCelebrating] = useState(null)

  useEffect(() => {
    if (isOpen) {
      fetchAchievements()
    }
  }, [isOpen])

  const fetchAchievements = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/retention/achievements')
      const data = await response.json()

      if (data.success) {
        setAchievements(data.achievements)
        setStats(data.stats)

        // Celebrate uncelebrated achievements
        if (data.uncelebrated?.length > 0) {
          setCelebrating(data.uncelebrated[0])
        }
      }
    } catch (error) {
      console.error('Failed to fetch achievements:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCelebrate = async () => {
    if (!celebrating) return

    try {
      await fetch('/api/retention/achievements', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'celebrate',
          achievementId: celebrating.id
        })
      })
    } catch (error) {
      console.error('Failed to mark as celebrated:', error)
    }

    setCelebrating(null)
    fetchAchievements()
  }

  const filteredAchievements = activeCategory === 'all'
    ? Object.values(achievements).flat()
    : achievements[activeCategory] || []

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        <DialogHeader className="pb-2">
          <DialogTitle className="flex items-center gap-2 text-xl">
            <Trophy className="w-6 h-6 text-amber-500" />
            Your Achievements
          </DialogTitle>
          <DialogDescription>
            Celebrate your financial journey milestones
          </DialogDescription>
        </DialogHeader>

        {/* Celebration overlay */}
        <AnimatePresence>
          {celebrating && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-gradient-to-b from-amber-500/20 to-transparent z-10 flex items-center justify-center"
            >
              <motion.div
                initial={{ scale: 0, rotate: -10 }}
                animate={{ scale: 1, rotate: 0 }}
                exit={{ scale: 0 }}
                transition={{ type: 'spring', stiffness: 300 }}
                className="bg-white rounded-2xl shadow-2xl p-8 text-center max-w-sm mx-4"
              >
                <motion.div
                  animate={{
                    scale: [1, 1.2, 1],
                    rotate: [0, 10, -10, 0]
                  }}
                  transition={{ duration: 0.5, delay: 0.2 }}
                  className="text-6xl mb-4"
                >
                  {celebrating.emoji}
                </motion.div>
                <h3 className="text-xl font-bold text-slate-800 mb-1">
                  {celebrating.name}
                </h3>
                <p className="text-slate-600 mb-2">{celebrating.description}</p>
                <div className="flex items-center justify-center gap-1 text-amber-600 font-semibold mb-4">
                  <Sparkles className="w-4 h-4" />
                  +{celebrating.points} points
                </div>
                <Button onClick={handleCelebrate} className="bg-amber-500 hover:bg-amber-600">
                  Awesome!
                </Button>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Stats bar */}
        {stats && (
          <div className="grid grid-cols-3 gap-4 py-3 px-4 bg-slate-50 rounded-xl mb-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-800">{stats.unlocked}</div>
              <div className="text-xs text-slate-500">Unlocked</div>
            </div>
            <div className="text-center border-x border-slate-200">
              <div className="text-2xl font-bold text-amber-600">{stats.points}</div>
              <div className="text-xs text-slate-500">Points</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-emerald-600">{stats.percentComplete}%</div>
              <div className="text-xs text-slate-500">Complete</div>
            </div>
          </div>
        )}

        {/* Category filter */}
        <div className="flex gap-2 mb-4 overflow-x-auto pb-1">
          <button
            onClick={() => setActiveCategory('all')}
            className={`
              px-3 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap
              ${activeCategory === 'all'
                ? 'bg-slate-800 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }
            `}
          >
            All
          </button>
          {Object.entries(CATEGORY_INFO).map(([key, info]) => {
            const CategoryIcon = info.icon
            return (
              <button
                key={key}
                onClick={() => setActiveCategory(key)}
                className={`
                  px-3 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap
                  flex items-center gap-1.5
                  ${activeCategory === key
                    ? `${info.bg} ${info.color}`
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }
                `}
              >
                <CategoryIcon className="w-3.5 h-3.5" />
                {info.title}
              </button>
            )
          })}
        </div>

        {/* Achievements grid */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-4 p-2">
              {[...Array(10)].map((_, i) => (
                <div key={i} className="flex flex-col items-center animate-pulse">
                  <div className="w-14 h-14 bg-slate-200 rounded-2xl mb-2" />
                  <div className="w-16 h-3 bg-slate-200 rounded" />
                </div>
              ))}
            </div>
          ) : (
            <>
              {/* Unlocked section */}
              {filteredAchievements.filter(a => a.isUnlocked).length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium text-slate-500 mb-3 px-2">Unlocked</h4>
                  <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-4 px-2">
                    {filteredAchievements
                      .filter(a => a.isUnlocked)
                      .map(achievement => (
                        <AchievementBadge
                          key={achievement.id}
                          achievement={achievement}
                          size="default"
                          showDetails={true}
                        />
                      ))
                    }
                  </div>
                </div>
              )}

              {/* In Progress section */}
              {filteredAchievements.filter(a => !a.isUnlocked && a.progressPercent > 0).length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium text-slate-500 mb-3 px-2">In Progress</h4>
                  <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-4 px-2">
                    {filteredAchievements
                      .filter(a => !a.isUnlocked && a.progressPercent > 0)
                      .sort((a, b) => b.progressPercent - a.progressPercent)
                      .map(achievement => (
                        <AchievementBadge
                          key={achievement.id}
                          achievement={achievement}
                          size="default"
                          showDetails={true}
                          showProgress={true}
                        />
                      ))
                    }
                  </div>
                </div>
              )}

              {/* Locked section */}
              {filteredAchievements.filter(a => !a.isUnlocked && a.progressPercent === 0).length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium text-slate-500 mb-3 px-2">Locked</h4>
                  <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-4 px-2">
                    {filteredAchievements
                      .filter(a => !a.isUnlocked && a.progressPercent === 0)
                      .map(achievement => (
                        <AchievementBadge
                          key={achievement.id}
                          achievement={achievement}
                          size="default"
                          showDetails={true}
                        />
                      ))
                    }
                  </div>
                </div>
              )}

              {/* Empty state */}
              {filteredAchievements.length === 0 && (
                <div className="text-center py-12 text-slate-500">
                  <Trophy className="w-12 h-12 mx-auto mb-3 text-slate-300" />
                  <p>No achievements in this category yet</p>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-slate-100 flex justify-end">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
