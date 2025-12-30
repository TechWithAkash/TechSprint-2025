// app/dashboard/notifications/page.js
'use client'

import { useState } from 'react'
import { useNotifications } from '@/contexts/NotificationContext'
import { useRouter } from 'next/navigation'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
    Bell,
    CheckCheck,
    Filter,
    Trash2,
    TrendingUp,
    AlertCircle,
    Info,
    Target,
    Wallet,
    RefreshCw,
    ArrowLeft
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import Link from 'next/link'

const PRIORITY_COLORS = {
    critical: {
        bg: 'bg-red-50',
        border: 'border-l-red-500',
        text: 'text-red-800',
        icon: 'text-red-600',
        badge: 'bg-red-600'
    },
    high: {
        bg: 'bg-orange-50',
        border: 'border-l-orange-500',
        text: 'text-orange-800',
        icon: 'text-orange-600',
        badge: 'bg-orange-600'
    },
    medium: {
        bg: 'bg-blue-50',
        border: 'border-l-blue-500',
        text: 'text-blue-800',
        icon: 'text-blue-600',
        badge: 'bg-blue-600'
    },
    low: {
        bg: 'bg-gray-50',
        border: 'border-l-gray-500',
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

export default function NotificationsPage() {
    const { notifications, unreadCount, markAsRead, markAllAsRead, dismiss, refresh, loading } = useNotifications()
    const router = useRouter()
    const [filter, setFilter] = useState('all') // 'all', 'unread', 'critical', 'spending', etc.

    // Filter notifications
    const filteredNotifications = notifications.filter(notification => {
        if (filter === 'all') return true
        if (filter === 'unread') return !notification.read
        if (filter === 'critical') return notification.priority === 'critical' || notification.priority === 'high'
        return notification.category === filter
    })

    const handleNotificationClick = (notification) => {
        if (!notification.read) {
            markAsRead(notification.id)
        }
    }

    return (
        <DashboardLayout title="Notifications">
            <div className="space-y-6">
                {/* Back Button - Mobile */}
                <div className="lg:hidden">
                    <Button
                        onClick={() => router.back()}
                        variant="ghost"
                        size="sm"
                        className="gap-2 text-slate-600 hover:text-slate-900 hover:bg-slate-100 -ml-2"
                    >
                        <ArrowLeft className="h-4 w-4" />
                        Back
                    </Button>
                </div>

                {/* Header */}
                <Card>
                    <CardHeader>
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="flex items-center gap-2 text-2xl">
                                    <Bell className="h-6 w-6 text-emerald-600" />
                                    All Notifications
                                </CardTitle>
                                <CardDescription className="mt-1">
                                    {unreadCount > 0
                                        ? `You have ${unreadCount} unread notification${unreadCount > 1 ? 's' : ''}`
                                        : 'You\'re all caught up! 🎉'
                                    }
                                </CardDescription>
                            </div>

                            <div className="flex gap-2">
                                {/* Back Button - Desktop */}
                                <Button
                                    onClick={() => router.back()}
                                    variant="outline"
                                    size="sm"
                                    className="hidden lg:flex gap-2"
                                >
                                    <ArrowLeft className="h-4 w-4" />
                                    Back
                                </Button>

                                <Button
                                    onClick={refresh}
                                    variant="outline"
                                    size="sm"
                                    disabled={loading}
                                >
                                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                                    Refresh
                                </Button>

                                {unreadCount > 0 && (
                                    <Button
                                        onClick={markAllAsRead}
                                        variant="outline"
                                        size="sm"
                                        className="hidden sm:flex"
                                    >
                                        <CheckCheck className="h-4 w-4 mr-2" />
                                        Mark all read
                                    </Button>
                                )}
                            </div>
                        </div>
                    </CardHeader>
                </Card>

                {/* Filters */}
                <Card>
                    <CardContent className="pt-6">
                        <div className="flex items-center gap-2 mb-4">
                            <Filter className="h-4 w-4 text-gray-500" />
                            <span className="text-sm font-medium text-gray-700">Filter by:</span>
                        </div>

                        <div className="flex flex-wrap gap-2">
                            <Button
                                onClick={() => setFilter('all')}
                                variant={filter === 'all' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'all' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                All ({notifications.length})
                            </Button>

                            <Button
                                onClick={() => setFilter('unread')}
                                variant={filter === 'unread' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'unread' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                Unread ({unreadCount})
                            </Button>

                            <Button
                                onClick={() => setFilter('critical')}
                                variant={filter === 'critical' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'critical' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                Important
                            </Button>

                            <div className="w-px h-6 bg-gray-300 mx-1"></div>

                            <Button
                                onClick={() => setFilter('spending')}
                                variant={filter === 'spending' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'spending' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                <Wallet className="h-3 w-3 mr-1" />
                                Spending
                            </Button>

                            <Button
                                onClick={() => setFilter('savings')}
                                variant={filter === 'savings' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'savings' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                <TrendingUp className="h-3 w-3 mr-1" />
                                Savings
                            </Button>

                            <Button
                                onClick={() => setFilter('goals')}
                                variant={filter === 'goals' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'goals' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                <Target className="h-3 w-3 mr-1" />
                                Goals
                            </Button>

                            <Button
                                onClick={() => setFilter('ai_insights')}
                                variant={filter === 'ai_insights' ? 'default' : 'outline'}
                                size="sm"
                                className={filter === 'ai_insights' ? 'bg-emerald-600 hover:bg-emerald-700' : ''}
                            >
                                <Info className="h-3 w-3 mr-1" />
                                AI Insights
                            </Button>
                        </div>
                    </CardContent>
                </Card>

                {/* Notifications List */}
                <Card>
                    <CardContent className="p-0">
                        {loading ? (
                            <div className="flex items-center justify-center py-12">
                                <div className="text-center">
                                    <RefreshCw className="h-8 w-8 animate-spin text-emerald-600 mx-auto mb-2" />
                                    <p className="text-gray-500">Loading notifications...</p>
                                </div>
                            </div>
                        ) : filteredNotifications.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 px-4">
                                <Bell className="h-16 w-16 text-gray-300 mb-4" />
                                <h3 className="text-lg font-semibold text-gray-700 mb-2">
                                    {filter === 'all' ? 'No notifications yet' :
                                        filter === 'unread' ? 'No unread notifications' :
                                            `No ${filter} notifications`}
                                </h3>
                                <p className="text-gray-500 text-sm text-center max-w-md">
                                    {filter === 'all'
                                        ? 'You\'ll receive notifications about your spending, savings, goals, and AI insights here.'
                                        : 'Check back later for updates.'}
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
                                            className={`relative px-6 py-4 hover:bg-gray-50 transition-colors border-l-4 ${colors.border} ${!notification.read ? 'bg-blue-50/20' : ''
                                                }`}
                                        >
                                            <div className="flex gap-4">
                                                {/* Icon */}
                                                <div className={`flex-shrink-0 w-12 h-12 ${colors.bg} rounded-xl flex items-center justify-center`}>
                                                    <CategoryIcon className={`h-6 w-6 ${colors.icon}`} />
                                                </div>

                                                {/* Content */}
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-start justify-between gap-4">
                                                        <div className="flex-1">
                                                            <h3 className={`text-base font-semibold ${colors.text} mb-1`}>
                                                                {notification.title}
                                                            </h3>
                                                            <p className="text-sm text-gray-700 leading-relaxed">
                                                                {notification.message}
                                                            </p>
                                                        </div>

                                                        {/* Actions */}
                                                        <div className="flex items-center gap-2 flex-shrink-0">
                                                            {!notification.read && (
                                                                <Button
                                                                    onClick={() => markAsRead(notification.id)}
                                                                    variant="ghost"
                                                                    size="sm"
                                                                    className="text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50"
                                                                >
                                                                    <CheckCheck className="h-4 w-4" />
                                                                </Button>
                                                            )}

                                                            <Button
                                                                onClick={() => dismiss(notification.id)}
                                                                variant="ghost"
                                                                size="sm"
                                                                className="text-gray-400 hover:text-red-600 hover:bg-red-50"
                                                            >
                                                                <Trash2 className="h-4 w-4" />
                                                            </Button>
                                                        </div>
                                                    </div>

                                                    {/* Metadata */}
                                                    <div className="flex items-center justify-between mt-3">
                                                        <div className="flex items-center gap-3 text-xs text-gray-500">
                                                            <span>{format(new Date(notification.timestamp), 'MMM dd, yyyy • hh:mm a')}</span>
                                                            <span>•</span>
                                                            <span>{formatDistanceToNow(new Date(notification.timestamp), { addSuffix: true })}</span>
                                                        </div>

                                                        {notification.actionUrl && (
                                                            <Link
                                                                href={notification.actionUrl}
                                                                className="text-sm font-medium text-emerald-600 hover:text-emerald-700 hover:underline"
                                                                onClick={() => handleNotificationClick(notification)}
                                                            >
                                                                {notification.actionLabel || 'View Details'} →
                                                            </Link>
                                                        )}
                                                    </div>

                                                    {/* Priority Badge */}
                                                    {(notification.priority === 'critical' || notification.priority === 'high') && (
                                                        <div className="mt-3">
                                                            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold text-white ${colors.badge}`}>
                                                                {notification.priority === 'critical' ? '🚨 Critical' : '⚠️ Important'}
                                                            </span>
                                                        </div>
                                                    )}

                                                    {/* Unread Indicator */}
                                                    {!notification.read && (
                                                        <div className="absolute left-2 top-1/2 -translate-y-1/2 w-2 h-2 bg-emerald-600 rounded-full"></div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )
                                })}
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </DashboardLayout>
    )
}
