'use client'

import { usePathname, useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import { useProfile } from '@/contexts/ProfileContext'
import { motion } from 'framer-motion'
import Image from 'next/image'
import {
  Home,
  Wallet,
  PieChart,
  BarChart3,
  User
} from 'lucide-react'

// Haptic Feedback
const triggerHaptic = (intensity = 'medium') => {
  if (typeof window !== 'undefined' && 'vibrate' in navigator) {
    const patterns = {
      light: 10,
      medium: 20,
      heavy: 30
    }
    navigator.vibrate(patterns[intensity] || 20)
  }
}

const NAV_ITEMS = [
  {
    id: 'dashboard',
    name: 'Home',
    icon: Home,
    href: '/dashboard',
    color: 'from-blue-500 to-cyan-500'
  },
  {
    id: 'expenses',
    name: 'Expenses',
    icon: Wallet,
    href: '/dashboard/expenses',
    color: 'from-purple-500 to-pink-500'
  },
  {
    id: 'budget',
    name: 'Budget',
    icon: PieChart,
    href: '/dashboard/budget',
    color: 'from-orange-500 to-red-500'
  },
  {
    id: 'analytics',
    name: 'Analytics',
    icon: BarChart3,
    href: '/dashboard/analytics',
    color: 'from-indigo-500 to-purple-500'
  },
  {
    id: 'profile',
    name: 'Profile',
    icon: User,
    href: '/dashboard/profile',
    color: 'from-emerald-500 to-teal-500'
  }
]

export default function MobileBottomNav() {
  const pathname = usePathname()
  const router = useRouter()
  const { data: session } = useSession()
  const { profileImage, profileData } = useProfile()

  const handleNavClick = (item) => {
    triggerHaptic('medium')
    if (item.href) {
      router.push(item.href)
    }
  }

  const isActive = (href) => {
    if (!href) return false
    return pathname === href
  }

  return (
    <>
      {/* Safe area spacer for content */}
      <div className="h-20 lg:hidden" />

      {/* Bottom Navigation Bar */}
      <motion.div
        className="lg:hidden fixed bottom-0 left-0 right-0 z-50 bg-white border-t border-slate-200 safe-area-bottom"
        initial={{ y: 100 }}
        animate={{ y: 0 }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      >
        {/* iOS Safe Area Bottom Padding */}
        <div className="bg-white pb-safe">
          <nav className="flex items-center justify-around h-16 px-2 relative">
            {NAV_ITEMS.map((item, index) => {
              const Icon = item.icon
              const active = isActive(item.href)
              const isProfileIcon = item.id === 'profile'

              return (
                <motion.button
                  key={item.id}
                  onClick={() => handleNavClick(item)}
                  className={`flex flex-col items-center justify-center min-w-[60px] py-1 relative ${isProfileIcon ? 'ml-2' : ''
                    }`}
                  whileTap={{ scale: 0.95 }}
                >
                  {/* Active Indicator Background */}
                  {active && !isProfileIcon && (
                    <motion.div
                      layoutId="activeTab"
                      className="absolute inset-0 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl"
                      initial={false}
                      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                    />
                  )}

                  {/* Icon Container */}
                  <div className="relative z-10">
                    <motion.div
                      animate={{
                        scale: active ? 1.1 : 1,
                        y: active && !isProfileIcon ? -2 : 0
                      }}
                      transition={{ type: 'spring', stiffness: 300 }}
                    >
                      {isProfileIcon ? (
                        // Profile Avatar with Image
                        <div className={`relative w-9 h-9 rounded-full ${active
                          ? 'ring-2 ring-emerald-400 ring-offset-2'
                          : 'ring-2 ring-slate-300'
                          } overflow-hidden shadow-md`}>
                          {profileImage ? (
                            <Image
                              src={profileImage}
                              alt={session?.user?.name || 'Profile'}
                              fill
                              className="object-cover"
                              sizes="36px"
                              priority
                            />
                          ) : (
                            <div className={`w-full h-full ${active
                              ? 'bg-gradient-to-r from-emerald-500 to-teal-500'
                              : 'bg-gradient-to-r from-slate-400 to-slate-500'
                              } flex items-center justify-center text-white font-semibold text-sm`}>
                              {session?.user?.name?.charAt(0).toUpperCase() || 'U'}
                            </div>
                          )}
                        </div>
                      ) : active ? (
                        <div className={`p-2 rounded-xl bg-gradient-to-r ${item.color}`}>
                          <Icon className="w-5 h-5 text-white" strokeWidth={2.5} />
                        </div>
                      ) : (
                        <Icon className="w-6 h-6 text-slate-400" strokeWidth={2} />
                      )}
                    </motion.div>
                  </div>

                  {/* Label */}
                  {!isProfileIcon && (
                    <motion.span
                      className={`text-xs font-medium mt-1 relative z-10 ${active
                        ? 'text-transparent bg-gradient-to-r bg-clip-text from-emerald-600 to-teal-600'
                        : 'text-slate-500'
                        }`}
                      animate={{
                        scale: active ? 1.05 : 1,
                        fontWeight: active ? 600 : 500
                      }}
                    >
                      {item.name}
                    </motion.span>
                  )}

                  {/* Profile Label - Smaller */}
                  {isProfileIcon && (
                    <motion.span
                      className={`text-[10px] font-medium mt-0.5 relative z-10 ${active
                        ? 'text-emerald-600'
                        : 'text-slate-500'
                        }`}
                    >
                      {item.name}
                    </motion.span>
                  )}

                  {/* Active Dot Indicator */}
                  {active && !isProfileIcon && (
                    <motion.div
                      className="absolute bottom-0 w-1 h-1 bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full"
                      layoutId="activeDot"
                      initial={false}
                      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                    />
                  )}
                </motion.button>
              )
            })}
          </nav>
        </div>
      </motion.div>

      {/* Add custom CSS for safe areas */}
      <style jsx global>{`
        .safe-area-bottom {
          padding-bottom: env(safe-area-inset-bottom);
        }

        .pb-safe {
          padding-bottom: max(0px, env(safe-area-inset-bottom));
        }

        /* Prevent scrolling behind nav on mobile */
        @media (max-width: 1024px) {
          body {
            padding-bottom: env(safe-area-inset-bottom);
          }
        }
      `}</style>
    </>
  )
}
