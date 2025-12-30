'use client'

import { useState, useRef, useEffect } from 'react'
import { useSession, signOut } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import { useProfile } from '@/contexts/ProfileContext'
import { usePathname, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import Sidebar from '@/components/layout/Sidebar'
import MobileBottomNav from '@/components/mobile/MobileBottomNav'
import SwipeGestureHandler from '@/components/mobile/SwipeGestureHandler'
import PullToRefresh from '@/components/mobile/PullToRefresh'
import LanguageSelector from '@/components/ui/LanguageSelector'
import Logo from '@/components/ui/Logo'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LogOut,
  User,
  Settings,
  HelpCircle,
  ChevronDown,
  Bell
} from 'lucide-react'

export default function DashboardLayout({ children, title = "Dashboard", onRefresh }) {
  const { data: session } = useSession()
  const { profileImage } = useProfile()
  const { t } = useTranslation()
  const pathname = usePathname()
  const router = useRouter()
  const [showProfileDropdown, setShowProfileDropdown] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const dropdownRef = useRef(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowProfileDropdown(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [])

  // Handle refresh
  const handleRefresh = async () => {
    if (onRefresh) {
      await onRefresh()
    } else {
      // Default refresh behavior
      return new Promise((resolve) => {
        setTimeout(() => {
          window.location.reload()
          resolve()
        }, 1000)
      })
    }
  }

  // Determine if current page should show mobile nav
  const showMobileNav = [
    '/dashboard',
    '/dashboard/expenses',
    '/dashboard/goals',
    '/dashboard/analytics',
    '/dashboard/budget',
    '/dashboard/profile',
    '/dashboard/notifications'
  ].some(path => pathname === path)

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-emerald-50">
      <div className="flex">
        {/* Desktop Sidebar - Hidden on Mobile */}
        <div className="hidden lg:block">
          <div className="sticky top-0 h-screen">
            <Sidebar />
          </div>
        </div>

        {/* Mobile Sidebar Overlay - Only show when sidebarOpen is true */}
        {sidebarOpen && (
          <Sidebar
            isOpen={sidebarOpen}
            onClose={() => setSidebarOpen(false)}
          />
        )}

        {/* Main Content */}
        <div className="flex-1 min-w-0">
          {/* Fixed Header with Consistent Height */}
          <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-xl border-b border-slate-200/60 shadow-sm">
            <div className="h-16 px-3 sm:px-4 lg:px-6">
              <div className="flex items-center justify-between h-full">
                {/* Left Section: Logo (Mobile) or Title (Desktop) */}
                <div className="flex items-center min-w-0 flex-1">
                  {/* Mobile Logo - Show only on mobile */}
                  <div className="lg:hidden mr-3">
                    <Logo size="medium" />
                  </div>

                  {/* Title Section - Hidden on mobile, shown on desktop */}
                  <div className="min-w-0 flex-1 hidden lg:block">
                    <motion.h1
                      key={pathname}
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                      className="text-lg sm:text-xl lg:text-2xl font-bold text-slate-800 truncate"
                    >
                      {title}
                    </motion.h1>
                    <p className="text-xs sm:text-sm text-slate-500 hidden sm:block truncate">
                      {new Date().toLocaleDateString('en-US', {
                        weekday: 'long',
                        month: 'long',
                        day: 'numeric',
                        year: 'numeric'
                      })}
                    </p>
                  </div>
                </div>

                {/* Right Section: Actions */}
                <div className="flex items-center space-x-2">
                  {/* Language Selector */}
                  <LanguageSelector variant="dashboard" />

                  {/* Notification Bell Button - Redirects to notifications page */}
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => router.push('/dashboard/notifications')}
                    className="relative h-10 w-10 rounded-xl hover:bg-slate-100 transition-colors active:scale-95"
                  >
                    <Bell className="h-5 w-5 text-slate-600" />
                    {/* Optional: Add notification badge */}
                    {/* <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white"></span> */}
                  </Button>

                  {/* User Profile Dropdown - Hidden on mobile */}
                  <div className="relative hidden lg:block" ref={dropdownRef}>
                    <Button
                      variant="ghost"
                      className="flex items-center space-x-2 bg-slate-100/50 hover:bg-slate-200/50 rounded-xl px-3 py-2 h-10 transition-all duration-200 active:scale-95"
                      onClick={() => setShowProfileDropdown(!showProfileDropdown)}
                    >
                      <Avatar className="h-7 w-7 sm:h-8 sm:w-8 ring-2 ring-emerald-100">
                        <AvatarImage src={profileImage} />
                        <AvatarFallback className="text-sm bg-gradient-to-r from-emerald-500 to-teal-500 text-white font-bold">
                          {session?.user?.name?.[0] || 'A'}
                        </AvatarFallback>
                      </Avatar>
                      <div className="hidden sm:block text-left">
                        <p className="text-sm font-semibold text-slate-700 truncate max-w-24 lg:max-w-none">
                          {session?.user?.name?.split(' ')[0] || 'User'}
                        </p>
                      </div>
                      <ChevronDown className={`h-4 w-4 text-slate-500 transition-transform duration-200 ${showProfileDropdown ? 'rotate-180' : ''} hidden sm:block`} />
                    </Button>

                    {/* Profile Dropdown Menu */}
                    <AnimatePresence>
                      {showProfileDropdown && (
                        <motion.div
                          initial={{ opacity: 0, scale: 0.95, y: -10 }}
                          animate={{ opacity: 1, scale: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.95, y: -10 }}
                          transition={{ duration: 0.15 }}
                          className="absolute right-0 mt-2 w-64 sm:w-72 bg-white rounded-2xl shadow-xl border border-slate-200 py-2 z-50"
                        >
                          {/* User Info Header */}
                          <div className="px-4 py-3 border-b border-slate-100">
                            <div className="flex items-center space-x-3">
                              <Avatar className="h-12 w-12 ring-2 ring-emerald-100">
                                <AvatarImage src={profileImage} />
                                <AvatarFallback className="text-lg bg-gradient-to-r from-emerald-500 to-teal-500 text-white font-bold">
                                  {session?.user?.name?.[0] || 'A'}
                                </AvatarFallback>
                              </Avatar>
                              <div className="flex-1 min-w-0">
                                <p className="text-lg font-bold text-slate-900 truncate">
                                  {session?.user?.name || 'User'}
                                </p>
                                <p className="text-sm text-slate-500 truncate">
                                  {session?.user?.email || 'user@example.com'}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Menu Items */}
                          <div className="py-2">
                            <MenuItem
                              icon={User}
                              label="Profile"
                              onClick={() => {
                                setShowProfileDropdown(false)
                                router.push('/dashboard/profile')
                              }}
                            />
                            <MenuItem
                              icon={Settings}
                              label="Settings"
                              onClick={() => {
                                setShowProfileDropdown(false)
                                router.push('/dashboard/settings')
                              }}
                            />
                            <MenuItem
                              icon={HelpCircle}
                              label="Help & Support"
                              onClick={() => {
                                setShowProfileDropdown(false)
                                router.push('/dashboard/help')
                              }}
                            />
                            <div className="border-t border-slate-100 my-2"></div>
                            <MenuItem
                              icon={LogOut}
                              label="Sign Out"
                              onClick={() => {
                                setShowProfileDropdown(false)
                                signOut({ callbackUrl: window.location.origin })
                              }}
                              className="text-red-600 hover:bg-red-50"
                            />
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              </div>
            </div>
          </header>

          {/* Page Content with Swipe Gestures & Pull to Refresh */}
          <main className="relative">
            <SwipeGestureHandler>
              <PullToRefresh onRefresh={handleRefresh}>
                <motion.div
                  key={pathname}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3 }}
                  className="p-3 sm:p-4 lg:p-6"
                  data-scrollable="true"
                >
                  {children}
                </motion.div>
              </PullToRefresh>
            </SwipeGestureHandler>
          </main>

          {/* Mobile Bottom Navigation */}
          {showMobileNav && (
            <MobileBottomNav />
          )}
        </div>
      </div>
    </div>
  )
}

// Menu Item Component
function MenuItem({ icon: Icon, label, onClick, className = "" }) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center space-x-3 px-4 py-3 text-left text-slate-700 hover:bg-slate-50 active:bg-slate-100 transition-colors duration-150 ${className}`}
    >
      <Icon className="h-5 w-5 text-slate-500" />
      <span className="font-medium">{label}</span>
    </button>
  )
}
