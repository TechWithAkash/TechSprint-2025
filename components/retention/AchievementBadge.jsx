'use client'

import { motion } from 'framer-motion'
import {
  Sprout, ClipboardList, Target, Trophy, Mic,
  Coins, PiggyBank, Gem, TrendingUp,
  CheckCircle, Shield, Zap, Rocket, Flag, Lock
} from 'lucide-react'

const ICON_MAP = {
  'Sprout': Sprout,
  'ClipboardList': ClipboardList,
  'Target': Target,
  'Trophy': Trophy,
  'Mic': Mic,
  'Coins': Coins,
  'PiggyBank': PiggyBank,
  'Gem': Gem,
  'TrendingUp': TrendingUp,
  'CheckCircle': CheckCircle,
  'Shield': Shield,
  'Zap': Zap,
  'Rocket': Rocket,
  'Flag': Flag
}

const CATEGORY_COLORS = {
  tracking: {
    bg: 'bg-blue-100',
    border: 'border-blue-300',
    text: 'text-blue-700',
    icon: 'text-blue-500',
    progress: 'bg-blue-500',
    glow: 'shadow-blue-200'
  },
  savings: {
    bg: 'bg-emerald-100',
    border: 'border-emerald-300',
    text: 'text-emerald-700',
    icon: 'text-emerald-500',
    progress: 'bg-emerald-500',
    glow: 'shadow-emerald-200'
  },
  budget: {
    bg: 'bg-purple-100',
    border: 'border-purple-300',
    text: 'text-purple-700',
    icon: 'text-purple-500',
    progress: 'bg-purple-500',
    glow: 'shadow-purple-200'
  },
  goals: {
    bg: 'bg-amber-100',
    border: 'border-amber-300',
    text: 'text-amber-700',
    icon: 'text-amber-500',
    progress: 'bg-amber-500',
    glow: 'shadow-amber-200'
  }
}

export default function AchievementBadge({
  achievement,
  size = 'default', // 'small', 'default', 'large'
  showProgress = true,
  showDetails = true,
  onClick,
  className = ''
}) {
  const {
    name,
    description,
    emoji,
    icon,
    category,
    isUnlocked,
    progressPercent,
    currentValue,
    unlockedAt,
    points
  } = achievement

  const colors = CATEGORY_COLORS[category] || CATEGORY_COLORS.tracking
  const IconComponent = ICON_MAP[icon] || Target

  const sizeClasses = {
    small: {
      container: 'w-16',
      iconContainer: 'w-10 h-10',
      emoji: 'text-xl',
      icon: 'w-4 h-4',
      name: 'text-[10px]',
      description: 'hidden',
      progress: 'h-1'
    },
    default: {
      container: 'w-24',
      iconContainer: 'w-14 h-14',
      emoji: 'text-2xl',
      icon: 'w-5 h-5',
      name: 'text-xs',
      description: 'text-[10px]',
      progress: 'h-1.5'
    },
    large: {
      container: 'w-32',
      iconContainer: 'w-18 h-18',
      emoji: 'text-3xl',
      icon: 'w-6 h-6',
      name: 'text-sm',
      description: 'text-xs',
      progress: 'h-2'
    }
  }

  const s = sizeClasses[size]

  return (
    <motion.div
      onClick={onClick}
      whileHover={onClick ? { scale: 1.05 } : {}}
      whileTap={onClick ? { scale: 0.95 } : {}}
      className={`
        flex flex-col items-center text-center
        ${s.container}
        ${onClick ? 'cursor-pointer' : ''}
        ${className}
      `}
    >
      {/* Badge Icon Container */}
      <div
        className={`
          relative ${s.iconContainer} rounded-2xl flex items-center justify-center mb-2
          transition-all duration-300
          ${isUnlocked
            ? `${colors.bg} ${colors.border} border-2 shadow-lg ${colors.glow}`
            : 'bg-slate-100 border-2 border-slate-200'
          }
        `}
      >
        {isUnlocked ? (
          <motion.span
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 400, damping: 10 }}
            className={s.emoji}
          >
            {emoji}
          </motion.span>
        ) : (
          <Lock className={`${s.icon} text-slate-400`} />
        )}

        {/* Points badge */}
        {isUnlocked && points && size !== 'small' && (
          <div className="absolute -top-1 -right-1 bg-amber-400 text-amber-900 text-[9px] font-bold px-1.5 py-0.5 rounded-full">
            +{points}
          </div>
        )}
      </div>

      {/* Name */}
      <span
        className={`
          font-medium leading-tight mb-0.5
          ${s.name}
          ${isUnlocked ? colors.text : 'text-slate-400'}
        `}
      >
        {name}
      </span>

      {/* Description */}
      {showDetails && (
        <span
          className={`
            ${s.description} leading-tight
            ${isUnlocked ? 'text-slate-500' : 'text-slate-400'}
          `}
        >
          {description}
        </span>
      )}

      {/* Progress bar (for locked achievements) */}
      {!isUnlocked && showProgress && progressPercent > 0 && (
        <div className="w-full mt-2">
          <div className={`w-full ${s.progress} bg-slate-200 rounded-full overflow-hidden`}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressPercent}%` }}
              transition={{ duration: 0.5 }}
              className={`h-full ${colors.progress} rounded-full`}
            />
          </div>
          {size !== 'small' && (
            <span className="text-[9px] text-slate-400 mt-0.5 block">
              {progressPercent}%
            </span>
          )}
        </div>
      )}

      {/* Unlocked date */}
      {isUnlocked && unlockedAt && size === 'large' && (
        <span className="text-[9px] text-slate-400 mt-1">
          Unlocked {new Date(unlockedAt).toLocaleDateString('en-IN', {
            month: 'short',
            day: 'numeric'
          })}
        </span>
      )}
    </motion.div>
  )
}
