'use client'

import { useRouter, usePathname } from 'next/navigation'
import {
    Sparkles,
    CreditCard,
    Calculator,
    User,
    Settings,
    HelpCircle,
    TrendingUp,
    ChevronRight
} from 'lucide-react'

const triggerHaptic = () => {
    if (typeof window !== 'undefined' && 'vibrate' in navigator) {
        navigator.vibrate(15)
    }
}

const NAV_ITEMS = [
    {
        id: 'budget',
        name: 'Budget Manager',
        description: 'Track monthly budget',
        icon: Sparkles,
        href: '/dashboard/budget',
        color: 'from-violet-500 to-purple-500',
        bgColor: 'bg-violet-50',
        iconBg: 'bg-violet-100',
        textColor: 'text-violet-700'
    },
    {
        id: 'debt',
        name: 'Debt Manager',
        description: 'Manage debts & loans',
        icon: CreditCard,
        href: '/dashboard/debt',
        color: 'from-red-500 to-pink-500',
        bgColor: 'bg-red-50',
        iconBg: 'bg-red-100',
        textColor: 'text-red-700'
    },
    {
        id: 'debt-calculator',
        name: 'Debt Calculator',
        description: 'Calculate payments',
        icon: Calculator,
        href: '/dashboard/debt-calculator',
        color: 'from-orange-500 to-amber-500',
        bgColor: 'bg-orange-50',
        iconBg: 'bg-orange-100',
        textColor: 'text-orange-700'
    },
    {
        id: 'profile',
        name: 'Profile',
        description: 'Manage account',
        icon: User,
        href: '/dashboard/profile',
        color: 'from-indigo-500 to-blue-500',
        bgColor: 'bg-indigo-50',
        iconBg: 'bg-indigo-100',
        textColor: 'text-indigo-700'
    },
    {
        id: 'settings',
        name: 'Settings',
        description: 'App preferences',
        icon: Settings,
        href: '/dashboard/settings',
        color: 'from-slate-500 to-gray-500',
        bgColor: 'bg-slate-50',
        iconBg: 'bg-slate-100',
        textColor: 'text-slate-700'
    },
    {
        id: 'help',
        name: 'Help & Support',
        description: 'Get assistance',
        icon: HelpCircle,
        href: '/dashboard/help',
        color: 'from-green-500 to-emerald-500',
        bgColor: 'bg-green-50',
        iconBg: 'bg-green-100',
        textColor: 'text-green-700'
    }
]

export default function MobileQuickNav() {
    const router = useRouter()
    const pathname = usePathname()

    const handleNavigation = (href) => {
        triggerHaptic()
        router.push(href)
    }

    return (
        <div className="lg:hidden">
            {/* Header */}
            <div className="mb-4">
                <h2 className="text-lg font-bold text-slate-800 mb-1 flex items-center gap-2">
                    <TrendingUp className="w-5 h-5 text-emerald-600" />
                    Quick Access
                </h2>
                <p className="text-sm text-slate-600">All features at your fingertips</p>
            </div>

            {/* Navigation Grid */}
            <div className="grid grid-cols-2 gap-3 sm:gap-4">
                {NAV_ITEMS.map((item) => {
                    const Icon = item.icon
                    const isActive = pathname === item.href

                    return (
                        <button
                            key={item.id}
                            onClick={() => handleNavigation(item.href)}
                            className={`
                relative overflow-hidden rounded-2xl p-4 
                tap-target touch-feedback
                transition-all duration-200
                ${isActive
                                    ? `${item.bgColor} ring-2 ring-offset-2 ring-${item.color.split('-')[1]}-400 shadow-lg scale-[0.98]`
                                    : `bg-white border-2 border-slate-100 hover:border-slate-200 active:scale-95 shadow-sm hover:shadow-md`
                                }
              `}
                        >
                            {/* Background Gradient (subtle) */}
                            <div className={`absolute inset-0 bg-gradient-to-br ${item.color} opacity-0 ${isActive ? 'opacity-5' : 'group-hover:opacity-5'} transition-opacity`}></div>

                            {/* Content */}
                            <div className="relative z-10">
                                {/* Icon */}
                                <div className={`
                  w-12 h-12 rounded-xl mb-3
                  flex items-center justify-center
                  ${isActive ? item.iconBg : 'bg-slate-100'}
                  transition-all duration-200
                `}>
                                    <Icon
                                        className={`w-6 h-6 ${isActive ? item.textColor : 'text-slate-600'}`}
                                        strokeWidth={2.5}
                                    />
                                </div>

                                {/* Text */}
                                <div className="text-left">
                                    <h3 className={`
                    font-bold text-sm mb-0.5 line-clamp-1
                    ${isActive ? item.textColor : 'text-slate-800'}
                  `}>
                                        {item.name}
                                    </h3>
                                    <p className="text-xs text-slate-500 line-clamp-1">
                                        {item.description}
                                    </p>
                                </div>

                                {/* Arrow indicator */}
                                <ChevronRight
                                    className={`
                    absolute top-3 right-3 w-4 h-4 
                    ${isActive ? item.textColor : 'text-slate-300'}
                    transition-all duration-200
                  `}
                                />

                                {/* Active indicator dot */}
                                {isActive && (
                                    <div className={`absolute top-2 left-2 w-2 h-2 rounded-full bg-gradient-to-r ${item.color}`}></div>
                                )}
                            </div>
                        </button>
                    )
                })}
            </div>

            {/* Helper text */}
            <div className="mt-4 p-3 bg-gradient-to-r from-emerald-50 to-blue-50 rounded-xl border border-emerald-100">
                <p className="text-xs text-slate-600 text-center">
                    💡 <span className="font-medium">Tip:</span> Tap any feature to access it instantly
                </p>
            </div>
        </div>
    )
}
