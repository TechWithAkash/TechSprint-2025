// components/notifications/NotificationCenter.js
'use client'

import { useState, useRef, useEffect } from 'react'
import { useNotifications } from '@/contexts/NotificationContext'
import { Bell, Check, CheckCheck, X, TrendingUp, AlertCircle, Info, Target, Wallet } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'

const PRIORITY_COLORS = {
    critical: {
        bg: 'bg-red-50',
        border: 'border-red-200',
        text: 'text-red-800',
        icon: 'text-red-600',
        badge: 'bg-red-600'
    },
    high: {
        bg: 'bg-orange-50',
        border: 'border-orange-200',
        text: 'text-orange-800',
        icon: 'text-orange-600',
        badge: 'bg-orange-600'
    },
    medium: {
        bg: 'bg-blue-50',
        border: 'border-blue-200',
        text: 'text-blue-800',
        icon: 'text-blue-600',
        badge: 'bg-blue-600'
    },
    low: {
        bg: 'bg-gray-50',
        border: 'border-gray-200',
        text: 'text-gray-800',
        icon: 'text-gray-600',
        badge: 'bg-gray-600'
    }
}

const CATEGORY_ICONS = {
    spending: Wallet,
    savings: TrendingUp,
    goals: Target,
    bills: AlertCircle,
    ai_insights: Info,
    system: Info
}

export default function NotificationCenter() {
    const { notifications, unreadCount, markAsRead, markAllAsRead, dismiss, loading } = useNotifications()
    const [isOpen, setIsOpen] = useState(false)
    const [filter, setFilter] = useState('all') // 'all', 'unread', 'critical'
    const [isMobile, setIsMobile] = useState(false)
    const dropdownRef = useRef(null)

    // Detect mobile viewport
    useEffect(() => {
        const checkMobile = () => setIsMobile(window.innerWidth < 640)
        checkMobile()
        window.addEventListener('resize', checkMobile)
        return () => window.removeEventListener('resize', checkMobile)
    }, [])

    // Close dropdown when clicking outside (desktop only)
    useEffect(() => {
        function handleClickOutside(event) {
            if (!isMobile && dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsOpen(false)
            }
        }

        if (isOpen && !isMobile) {
            document.addEventListener('mousedown', handleClickOutside)
            return () => document.removeEventListener('mousedown', handleClickOutside)
        }
    }, [isOpen, isMobile])

    // Prevent body scroll when mobile sheet is open
    useEffect(() => {
        if (isMobile && isOpen) {
            document.body.style.overflow = 'hidden'
            return () => {
                document.body.style.overflow = 'unset'
            }
        }
    }, [isOpen, isMobile])

    // Filter notifications
    const filteredNotifications = notifications.filter(notification => {
        if (filter === 'unread') return !notification.read
        if (filter === 'critical') return notification.priority === 'critical' || notification.priority === 'high'
        return true
    })

    const handleNotificationClick = (notification) => {
        if (!notification.read) {
            markAsRead(notification.id)
        }
    }

    const handleDismiss = (e, notificationId) => {
        e.stopPropagation()
        dismiss(notificationId)
    }

    const handleMarkAllRead = (e) => {
        e.stopPropagation()
        markAllAsRead()
    }

    return (
        <>
            {/* Bell Icon Button - Touch-friendly */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="relative tap-target p-2 text-gray-600 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors touch-feedback no-select"
                aria-label="Notifications"
            >
                <Bell className="h-5 w-5 sm:h-6 sm:w-6" />

                {/* Unread Badge */}
                {unreadCount > 0 && (
                    <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-bold text-white bg-red-500 rounded-full ring-2 ring-white">
                        {unreadCount > 9 ? '9+' : unreadCount}
                    </span>
                )}
            </button>

            {/* Mobile Bottom Sheet or Desktop Dropdown */}
            <AnimatePresence>
                {isOpen && (
                    <>
                        {/* Backdrop - Mobile Only */}
                        {isMobile && (
                            <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                onClick={() => setIsOpen(false)}
                                className="fixed inset-0 bg-black/50 z-[60] sm:hidden"
                            />
                        )}

                        {/* Notification Panel */}
                        <motion.div
                            ref={!isMobile ? dropdownRef : null}
                            initial={isMobile ? { y: '100%' } : { opacity: 0, scale: 0.95, y: -10 }}
                            animate={isMobile ? { y: 0 } : { opacity: 1, scale: 1, y: 0 }}
                            exit={isMobile ? { y: '100%' } : { opacity: 0, scale: 0.95, y: -10 }}
                            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
                            className={`
                                bg-white shadow-2xl border border-gray-200 z-[70] overflow-hidden
                                ${isMobile
                                    ? 'fixed bottom-0 left-0 right-0 rounded-t-3xl'
                                    : 'absolute right-0 top-full mt-2 w-96 max-w-[calc(100vw-2rem)] rounded-xl'
                                }
                            `}
                            style={isMobile ? {
                                maxHeight: 'calc(85vh - env(safe-area-inset-bottom))',
                                paddingBottom: 'env(safe-area-inset-bottom)'
                            } : {}}
                        >
                            {/* Handle Bar for Mobile */}
                            {isMobile && (
                                <div className="flex justify-center pt-3 pb-2">
                                    <div className="w-10 h-1 bg-gray-300 rounded-full" />
                                </div>
                            )}

                            {/* Header */}
                            <div className="bg-gradient-to-r from-emerald-600 to-teal-600 px-4 py-3.5 text-white">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <h3 className="text-base sm:text-lg font-bold">Notifications</h3>
                                        <p className="text-[11px] sm:text-xs text-emerald-100 mt-0.5">
                                            {unreadCount > 0 ? `${unreadCount} unread` : 'All caught up!'}
                                        </p>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {unreadCount > 0 && (
                                            <button
                                                onClick={handleMarkAllRead}
                                                className="tap-target flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 sm:py-2 text-[11px] sm:text-xs font-medium bg-white/20 hover:bg-white/30 active:bg-white/40 rounded-lg transition-colors touch-feedback"
                                            >
                                                <CheckCheck className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
                                                <span className="hidden sm:inline">Mark all read</span>
                                            </button>
                                        )}
                                        {isMobile && (
                                            <button
                                                onClick={() => setIsOpen(false)}
                                                className="tap-target p-1.5 hover:bg-white/20 rounded-lg transition-colors"
                                            >
                                                <X className="h-5 w-5" />
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {/* Filter Tabs - Touch-friendly */}
                                <div className="flex gap-1.5 sm:gap-2 mt-3 touch-spacing">
                                    <button
                                        onClick={() => setFilter('all')}
                                        className={`tap-target px-3 sm:px-4 py-1.5 sm:py-2 text-[11px] sm:text-xs font-medium rounded-lg transition-colors touch-feedback ${filter === 'all'
                                            ? 'bg-white text-emerald-600 shadow-sm'
                                            : 'bg-white/20 text-white hover:bg-white/30'
                                            }`}
                                    >
                                        All ({notifications.length})
                                    </button>
                                    <button
                                        onClick={() => setFilter('unread')}
                                        className={`tap-target px-3 sm:px-4 py-1.5 sm:py-2 text-[11px] sm:text-xs font-medium rounded-lg transition-colors touch-feedback ${filter === 'unread'
                                            ? 'bg-white text-emerald-600 shadow-sm'
                                            : 'bg-white/20 text-white hover:bg-white/30'
                                            }`}
                                    >
                                        Unread ({unreadCount})
                                    </button>
                                    <button
                                        onClick={() => setFilter('critical')}
                                        className={`tap-target px-3 sm:px-4 py-1.5 sm:py-2 text-[11px] sm:text-xs font-medium rounded-lg transition-colors touch-feedback ${filter === 'critical'
                                            ? 'bg-white text-emerald-600 shadow-sm'
                                            : 'bg-white/20 text-white hover:bg-white/30'
                                            }`}
                                    >
                                        Important
                                    </button>
                                </div>
                            </div>

                            {/* Notifications List - Touch-friendly scrolling */}
                            <div className={`overflow-y-auto smooth-scroll ${isMobile ? 'max-h-[50vh]' : 'max-h-96'}`}>
                                {loading ? (
                                    <div className="flex items-center justify-center py-12">
                                        <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-emerald-600"></div>
                                    </div>
                                ) : filteredNotifications.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center py-16 px-4">
                                        <Bell className="h-16 w-16 text-gray-300 mb-4" />
                                        <p className="text-gray-500 text-base font-medium">
                                            {filter === 'all' ? 'No notifications yet' :
                                                filter === 'unread' ? 'No unread notifications' :
                                                    'No important notifications'}
                                        </p>
                                        <p className="text-gray-400 text-sm mt-2">
                                            {filter === 'all' ? 'You\'ll see important updates here' : 'Check back later'}
                                        </p>
                                    </div>
                                ) : (
                                    <div className="divide-y divide-gray-100">
                                        {filteredNotifications.map((notification) => {
                                            const colors = PRIORITY_COLORS[notification.priority] || PRIORITY_COLORS.low
                                            const CategoryIcon = CATEGORY_ICONS[notification.category] || Info

                                            return (
                                                <div
                                                    key={notification.id}
                                                    className={`relative px-4 py-4 hover:bg-gray-50 active:bg-gray-100 transition-colors cursor-pointer mobile-card-spacing ${!notification.read ? 'bg-blue-50/30' : ''
                                                        }`}
                                                    onClick={() => handleNotificationClick(notification)}
                                                >
                                                    {/* Unread Indicator */}
                                                    {!notification.read && (
                                                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-emerald-600"></div>
                                                    )}

                                                    <div className="flex gap-3">
                                                        {/* Icon - Touch-friendly size */}
                                                        <div className={`flex-shrink-0 w-12 h-12 ${colors.bg} rounded-xl flex items-center justify-center border ${colors.border}`}>
                                                            <CategoryIcon className={`h-6 w-6 ${colors.icon}`} />
                                                        </div>

                                                        {/* Content */}
                                                        <div className="flex-1 min-w-0">
                                                            <div className="flex items-start justify-between gap-2">
                                                                <h4 className={`text-sm font-semibold ${colors.text} leading-tight`}>
                                                                    {notification.title}
                                                                </h4>

                                                                {/* Dismiss Button - Touch-friendly */}
                                                                <button
                                                                    onClick={(e) => handleDismiss(e, notification.id)}
                                                                    className="tap-target flex-shrink-0 p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-200 active:bg-gray-300 rounded-lg transition-colors"
                                                                    aria-label="Dismiss"
                                                                >
                                                                    <X className="h-4 w-4" />
                                                                </button>
                                                            </div>

                                                            <p className="text-sm text-gray-600 mt-1.5 line-clamp-2 leading-relaxed">
                                                                {notification.message}
                                                            </p>

                                                            <div className="flex items-center justify-between mt-3">
                                                                <span className="text-xs text-gray-500">
                                                                    {formatDistanceToNow(new Date(notification.timestamp), { addSuffix: true })}
                                                                </span>

                                                                {notification.actionUrl && (
                                                                    <Link
                                                                        href={notification.actionUrl}
                                                                        className="tap-target text-sm font-medium text-emerald-600 hover:text-emerald-700 active:text-emerald-800 px-2 py-1 rounded"
                                                                        onClick={() => setIsOpen(false)}
                                                                    >
                                                                        {notification.actionLabel || 'View'} →
                                                                    </Link>
                                                                )}
                                                            </div>

                                                            {/* Priority Badge */}
                                                            {(notification.priority === 'critical' || notification.priority === 'high') && (
                                                                <div className="mt-2">
                                                                    <span className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium text-white ${colors.badge}`}>
                                                                        {notification.priority === 'critical' ? '🚨 Critical' : '⚠️ Important'}
                                                                    </span>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            )
                                        })}
                                    </div>
                                )}
                            </div>

                            {/* Footer - Touch-friendly */}
                            {filteredNotifications.length > 0 && (
                                <div className="border-t border-gray-200 px-4 py-3 bg-gray-50">
                                    <Link
                                        href="/dashboard/notifications"
                                        className="tap-target block text-center text-sm font-medium text-emerald-600 hover:text-emerald-700 active:text-emerald-800 py-2 rounded-lg hover:bg-emerald-50 transition-colors"
                                        onClick={() => setIsOpen(false)}
                                    >
                                        View All Notifications →
                                    </Link>
                                </div>
                            )}
                        </motion.div>
                    </>
                )}
            </AnimatePresence>
        </>
    )
}
