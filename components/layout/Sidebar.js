'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { signOut } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import {
  Home,
  Wallet,
  Target,
  TrendingUp,
  PieChart,
  ChevronLeft,
  ChevronRight,
  User,
  CreditCard,
  BarChart3,
  X,
  LogOut,
  Calculator
} from 'lucide-react'
import Logo from '@/components/ui/Logo'

const navigationItems = [
  {
    name: 'sidebar.dashboard',
    href: '/dashboard',
    icon: Home,
    description: 'sidebar.dashboard_desc'
  },
  {
    name: 'sidebar.expenses',
    href: '/dashboard/expenses',
    icon: Wallet,
    description: 'sidebar.expenses_desc'
  },
  {
    name: 'sidebar.budget',
    href: '/dashboard/budget',
    icon: PieChart,
    description: 'sidebar.budget_desc'
  },
  {
    name: 'sidebar.debt',
    href: '/dashboard/debt',
    icon: CreditCard,
    description: 'sidebar.debt_desc'
  },
  {
    name: 'sidebar.debt_calculator',
    href: '/dashboard/debt-calculator',
    icon: Calculator,
    description: 'sidebar.debt_calculator_desc'
  },
  {
    name: 'sidebar.goals',
    href: '/dashboard/goals',
    icon: Target,
    description: 'sidebar.goals_desc'
  },
  {
    name: 'sidebar.analytics',
    href: '/dashboard/analytics',
    icon: BarChart3,
    description: 'sidebar.analytics_desc'
  },
  {
    name: 'sidebar.profile',
    href: '/dashboard/profile',
    icon: User,
    description: 'sidebar.profile_desc'
  }
]

export default function Sidebar({ isOpen, onClose }) {
  const { t } = useTranslation()
  const [isCollapsed, setIsCollapsed] = useState(false)
  const pathname = usePathname()

  return (
    <>
      {/* Mobile overlay - Full screen like Codolio */}
      {isOpen && (
        <div className="lg:hidden fixed inset-0 z-50">
          {/* Background overlay */}
          <div 
            className="absolute inset-0 bg-black/20 backdrop-blur-sm"
            onClick={onClose}
          />
          
          {/* Sidebar panel - Full height, slides from left */}
          <div className="relative w-80 max-w-[85vw] h-full bg-white shadow-2xl animate-in slide-in-from-left duration-300">
            {/* Header with close button */}
            <div className="flex items-center justify-between p-4 border-b border-slate-200 bg-white h-16">
              <Logo size="medium" textClassName="text-lg" />
              
              {/* Close button - Top right like Codolio */}
              <Button
                variant="ghost"
                size="sm"
                onClick={onClose}
                className="text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg w-8 h-8 p-0"
              >
                <X className="h-5 w-5" />
              </Button>
            </div>

            {/* Navigation for mobile */}
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
              {navigationItems.map((item) => {
                const isActive = pathname === item.href
                const Icon = item.icon

                return (
                  <Link key={item.name} href={item.href} onClick={onClose}>
                    <div
                      className={`group relative flex items-center px-3 py-3 rounded-lg transition-all duration-150 cursor-pointer ${
                        isActive
                          ? 'bg-emerald-50 text-emerald-700'
                          : 'text-slate-600 hover:bg-slate-50'
                      }`}
                    >
                      {/* Active indicator bar */}
                      {isActive && (
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-7 bg-emerald-500 rounded-r-full" />
                      )}

                      <Icon className={`h-5 w-5 ${
                        isActive
                          ? 'text-emerald-600'
                          : 'text-slate-400 group-hover:text-slate-600'
                      } transition-colors flex-shrink-0`} />

                      <div className="ml-3 flex-1 min-w-0">
                        <p className={`text-sm font-medium ${
                          isActive ? 'text-emerald-700' : 'text-slate-700 group-hover:text-slate-900'
                        }`}>
                          {t(item.name)}
                        </p>
                        <p className={`text-xs ${
                          isActive ? 'text-emerald-600/70' : 'text-slate-400'
                        }`}>
                          {t(item.description)}
                        </p>
                      </div>
                    </div>
                  </Link>
                )
              })}
            </nav>

            {/* Bottom Signout Section for mobile */}
            <div className="p-4 border-t border-slate-200">
              <Button
                onClick={() => {
                  signOut({ callbackUrl: window.location.origin })
                  onClose()
                }}
                variant="outline"
                className="w-full flex items-center justify-center gap-3 px-4 py-3 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 rounded-xl transition-all duration-200"
              >
                <LogOut className="w-5 h-5" />
                <span className="font-medium">Sign Out</span>
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Desktop Sidebar - Sticky and Enhanced */}
      <div className={`
        hidden lg:flex
        bg-white border-r border-slate-200 
        transition-all duration-300 ease-in-out
        ${isCollapsed ? 'w-20' : 'w-72'} 
        h-screen
        flex-col
      `}>
          
        {/* Header */}
        <div className="p-4 border-b border-slate-200 bg-slate-50 h-16 flex items-center">
          <div className="flex items-center justify-between w-full">
            {!isCollapsed && (
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-gradient-to-r from-emerald-500 to-teal-500 rounded-lg flex items-center justify-center shadow-lg border-2 border-white">
                  <TrendingUp className="w-6 h-6 text-white" />
                </div>
                <div className="flex flex-col justify-center">
                  <h1 className="text-xl font-bold leading-tight">
                    <span className="text-slate-800">Wealth</span>
                    <span className="bg-gradient-to-r from-emerald-500 to-teal-500 bg-clip-text text-transparent">Wise</span>
                  </h1>
                  <p className="text-xs text-slate-500 leading-tight">Smart Finance Platform</p>
                </div>
              </div>
            )}

            {/* Collapsed state - Show just the logo */}
            {isCollapsed && (
              <div className="w-10 h-10 bg-gradient-to-r from-emerald-500 to-teal-500 rounded-lg flex items-center justify-center shadow-lg border-2 border-white mx-auto">
                <TrendingUp className="w-6 h-6 text-white" />
              </div>
            )}
            
            {/* Collapse Toggle - Desktop Only */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg w-8 h-8 p-0 flex-shrink-0"
            >
              {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            </Button>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => {
            const isActive = pathname === item.href
            const Icon = item.icon

            return (
              <Link key={item.name} href={item.href}>
                <div
                  className={`group relative flex items-center px-3 py-2.5 rounded-lg transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-emerald-50 text-emerald-700'
                      : 'text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  {/* Active indicator bar */}
                  {isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-emerald-500 rounded-r-full" />
                  )}

                  <Icon className={`h-5 w-5 ${
                    isActive
                      ? 'text-emerald-600'
                      : 'text-slate-400 group-hover:text-slate-600'
                  } transition-colors flex-shrink-0`} />

                  {!isCollapsed && (
                    <div className="ml-3 flex-1 min-w-0">
                      <p className={`text-sm font-medium ${
                        isActive ? 'text-emerald-700' : 'text-slate-700 group-hover:text-slate-900'
                      }`}>
                        {t(item.name)}
                      </p>
                      <p className={`text-xs ${
                        isActive ? 'text-emerald-600/70' : 'text-slate-400'
                      }`}>
                        {t(item.description)}
                      </p>
                    </div>
                  )}
                </div>
              </Link>
            )
          })}
        </nav>

        {/* Bottom Signout Section */}
        {!isCollapsed && (
          <div className="p-4 border-t border-slate-200">
            <Button
              onClick={() => signOut({ callbackUrl: window.location.origin })}
              variant="outline"
              className="w-full flex items-center justify-center gap-3 px-4 py-3 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 rounded-xl transition-all duration-200"
            >
              <LogOut className="w-5 h-5" />
              <span className="font-medium">Sign Out</span>
            </Button>
          </div>
        )}

        {/* Collapsed Signout Indicator */}
        {isCollapsed && (
          <div className="p-4 border-t border-slate-200">
            <Button
              onClick={() => signOut({ callbackUrl: window.location.origin })}
              variant="outline"
              className="w-12 h-12 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 rounded-xl mx-auto flex items-center justify-center transition-all duration-200"
            >
              <LogOut className="w-6 h-6" />
            </Button>
          </div>
        )}
      </div>
    </>
  )
}
