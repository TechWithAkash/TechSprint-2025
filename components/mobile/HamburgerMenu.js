'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { useRouter, usePathname } from 'next/navigation'
import { signOut } from 'next-auth/react'
import {
  X,
  CreditCard,
  Calculator,
  Upload,
  Receipt,
  Settings,
  User,
  HelpCircle,
  LogOut,
  ChevronRight,
  Sparkles,
  TrendingUp
} from 'lucide-react'

const triggerHaptic = () => {
  if (typeof window !== 'undefined' && 'vibrate' in navigator) {
    navigator.vibrate(20)
  }
}

const SECONDARY_MENU_ITEMS = [
  {
    section: 'Finance Tools',
    items: [
      {
        id: 'budget',
        name: 'Budget Manager',
        description: 'Track your monthly budget',
        icon: Sparkles,
        href: '/dashboard/budget',
        color: 'from-violet-500 to-purple-500'
      },
      {
        id: 'debt',
        name: 'Debt Manager',
        description: 'Manage your debts & loans',
        icon: CreditCard,
        href: '/dashboard/debt',
        color: 'from-red-500 to-pink-500'
      },
      {
        id: 'debt-calculator',
        name: 'Debt Calculator',
        description: 'Calculate loan payments',
        icon: Calculator,
        href: '/dashboard/debt-calculator',
        color: 'from-orange-500 to-amber-500'
      }
    ]
  },
  {
    section: 'Data Management',
    items: [
      {
        id: 'transactions',
        name: 'All Transactions',
        description: 'View complete history',
        icon: Receipt,
        href: '/dashboard/transactions',
        color: 'from-blue-500 to-cyan-500'
      },
      {
        id: 'upload',
        name: 'Upload Data',
        description: 'Import your statements',
        icon: Upload,
        href: '/dashboard/upload',
        color: 'from-teal-500 to-emerald-500'
      }
    ]
  },
  {
    section: 'Account',
    items: [
      {
        id: 'profile',
        name: 'Profile',
        description: 'Manage your account',
        icon: User,
        href: '/dashboard/profile',
        color: 'from-indigo-500 to-blue-500'
      },
      {
        id: 'settings',
        name: 'Settings',
        description: 'App preferences',
        icon: Settings,
        href: '/dashboard/settings',
        color: 'from-slate-500 to-gray-500'
      },
      {
        id: 'help',
        name: 'Help & Support',
        description: 'Get assistance',
        icon: HelpCircle,
        href: '/dashboard/help',
        color: 'from-green-500 to-emerald-500'
      }
    ]
  }
]

export default function HamburgerMenu({ isOpen, onClose }) {
  const router = useRouter()
  const pathname = usePathname()

  const handleNavigation = (href) => {
    triggerHaptic()
    onClose()
    router.push(href)
  }

  const handleSignOut = () => {
    triggerHaptic()
    onClose()
    signOut({ callbackUrl: window.location.origin })
  }

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-[60]"
            onClick={onClose}
          />

          {/* Menu Panel */}
          <motion.div
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="fixed left-0 top-0 bottom-0 w-[85vw] max-w-sm bg-white z-[70] shadow-2xl overflow-hidden"
          >
            {/* Header */}
            <div className="bg-gradient-to-r from-emerald-600 via-teal-600 to-blue-600 p-6 pb-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-white/20 backdrop-blur-xl rounded-xl flex items-center justify-center">
                    <TrendingUp className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white">WealthWise</h2>
                    <p className="text-xs text-emerald-100">Smart Finance</p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="w-10 h-10 rounded-xl bg-white/10 hover:bg-white/20 flex items-center justify-center transition-colors"
                >
                  <X className="w-5 h-5 text-white" />
                </button>
              </div>

              <div className="bg-white/10 backdrop-blur-xl rounded-xl p-4">
                <p className="text-sm text-emerald-100 mb-1">Quick Access</p>
                <p className="text-lg font-bold text-white">More Features</p>
              </div>
            </div>

            {/* Menu Content */}
            <div className="overflow-y-auto h-[calc(100vh-200px)] px-4 py-4">
              {SECONDARY_MENU_ITEMS.map((section, sectionIndex) => (
                <div key={section.section} className="mb-6">
                  {/* Section Header */}
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">
                    {section.section}
                  </h3>

                  {/* Section Items */}
                  <div className="space-y-2">
                    {section.items.map((item, itemIndex) => {
                      const Icon = item.icon
                      const isActive = pathname === item.href
                      const delay = sectionIndex * 0.1 + itemIndex * 0.05

                      return (
                        <motion.button
                          key={item.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay }}
                          onClick={() => handleNavigation(item.href)}
                          className={`w-full group relative overflow-hidden rounded-xl transition-all duration-200 ${
                            isActive
                              ? 'bg-gradient-to-r from-emerald-50 to-teal-50 shadow-md'
                              : 'hover:bg-slate-50'
                          }`}
                        >
                          <div className="flex items-center gap-4 p-4">
                            {/* Icon */}
                            <div
                              className={`w-12 h-12 rounded-xl bg-gradient-to-r ${item.color} flex items-center justify-center flex-shrink-0 shadow-lg ${
                                isActive ? 'scale-110' : 'group-hover:scale-105'
                              } transition-transform duration-200`}
                            >
                              <Icon className="w-6 h-6 text-white" strokeWidth={2.5} />
                            </div>

                            {/* Text */}
                            <div className="flex-1 text-left min-w-0">
                              <p
                                className={`font-semibold text-sm ${
                                  isActive
                                    ? 'text-emerald-700'
                                    : 'text-slate-700 group-hover:text-emerald-600'
                                } transition-colors truncate`}
                              >
                                {item.name}
                              </p>
                              <p className="text-xs text-slate-500 truncate">
                                {item.description}
                              </p>
                            </div>

                            {/* Arrow */}
                            <ChevronRight
                              className={`w-5 h-5 flex-shrink-0 transition-all duration-200 ${
                                isActive
                                  ? 'text-emerald-600 translate-x-1'
                                  : 'text-slate-300 group-hover:text-emerald-500 group-hover:translate-x-1'
                              }`}
                            />
                          </div>

                          {/* Active Indicator */}
                          {isActive && (
                            <motion.div
                              layoutId="activeMenuItem"
                              className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-emerald-500 to-teal-500"
                              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                            />
                          )}
                        </motion.button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>

            {/* Footer - Sign Out */}
            <div className="absolute bottom-0 left-0 right-0 p-4 bg-white border-t border-slate-200">
              <button
                onClick={handleSignOut}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-red-50 hover:bg-red-100 border-2 border-red-200 hover:border-red-300 text-red-600 rounded-xl transition-all duration-200 font-semibold"
              >
                <LogOut className="w-5 h-5" />
                <span>Sign Out</span>
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
