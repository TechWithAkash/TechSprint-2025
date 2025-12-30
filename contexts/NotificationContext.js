// contexts/NotificationContext.js
'use client'

import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { useSession } from 'next-auth/react'
import notificationService from '@/lib/notificationService'
import toast from 'react-hot-toast'

const NotificationContext = createContext()

export function useNotifications() {
    const context = useContext(NotificationContext)
    if (!context) {
        throw new Error('useNotifications must be used within NotificationProvider')
    }
    return context
}

export function NotificationProvider({ children }) {
    const { data: session } = useSession()
    const [notifications, setNotifications] = useState([])
    const [unreadCount, setUnreadCount] = useState(0)
    const [loading, setLoading] = useState(true)

    // Load notifications on mount
    useEffect(() => {
        if (session?.user?.id) {
            loadNotifications()
        }
    }, [session?.user?.id])

    // Subscribe to notification updates
    useEffect(() => {
        const unsubscribe = notificationService.subscribe((event, data) => {
            handleNotificationEvent(event, data)
        })

        return unsubscribe
    }, [session?.user?.id])

    /**
     * Load notifications from service
     */
    const loadNotifications = async () => {
        if (!session?.user?.id) return

        setLoading(true)
        try {
            await notificationService.loadFromDatabase(session.user.id)
            const userNotifications = notificationService.getForUser(session.user.id, {
                limit: 100,
                includeRead: true,
                includeDismissed: false
            })
            setNotifications(userNotifications)
            setUnreadCount(notificationService.getUnreadCount(session.user.id))
        } catch (error) {
            console.error('Failed to load notifications:', error)
        } finally {
            setLoading(false)
        }
    }

    /**
     * Handle notification events
     */
    const handleNotificationEvent = useCallback((event, data) => {
        if (!session?.user?.id) return

        switch (event) {
            case 'created':
                if (data.userId === session.user.id) {
                    setNotifications(prev => [data, ...prev])
                    setUnreadCount(prev => prev + 1)

                    // Show toast for high priority notifications
                    if (data.priority === 'critical' || data.priority === 'high') {
                        toast.custom((t) => (
                            <div
                                className={`${t.visible ? 'animate-enter' : 'animate-leave'
                                    } max-w-md w-full bg-white shadow-lg rounded-lg pointer-events-auto flex ring-1 ring-black ring-opacity-5`}
                            >
                                <div className="flex-1 w-0 p-4">
                                    <div className="flex items-start">
                                        <div className="flex-shrink-0 pt-0.5">
                                            {data.priority === 'critical' ? (
                                                <span className="text-2xl">🚨</span>
                                            ) : (
                                                <span className="text-2xl">⚠️</span>
                                            )}
                                        </div>
                                        <div className="ml-3 flex-1">
                                            <p className="text-sm font-medium text-gray-900">
                                                {data.title}
                                            </p>
                                            <p className="mt-1 text-sm text-gray-500">
                                                {data.message}
                                            </p>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex border-l border-gray-200">
                                    <button
                                        onClick={() => toast.dismiss(t.id)}
                                        className="w-full border border-transparent rounded-none rounded-r-lg p-4 flex items-center justify-center text-sm font-medium text-emerald-600 hover:text-emerald-500 focus:outline-none"
                                    >
                                        Close
                                    </button>
                                </div>
                            </div>
                        ), {
                            duration: 6000,
                            position: 'top-right'
                        })
                    }
                }
                break

            case 'read':
                if (data.userId === session.user.id) {
                    setNotifications(prev =>
                        prev.map(n => (n.id === data.id ? { ...n, read: true, readAt: data.readAt } : n))
                    )
                    setUnreadCount(prev => Math.max(0, prev - 1))
                }
                break

            case 'allRead':
                if (data.length > 0 && data[0].userId === session.user.id) {
                    setNotifications(prev =>
                        prev.map(n => ({ ...n, read: true, readAt: new Date().toISOString() }))
                    )
                    setUnreadCount(0)
                }
                break

            case 'dismissed':
                if (data.userId === session.user.id) {
                    setNotifications(prev => prev.filter(n => n.id !== data.id))
                }
                break

            case 'loaded':
                if (session?.user?.id) {
                    const userNotifications = notificationService.getForUser(session.user.id)
                    setNotifications(userNotifications)
                    setUnreadCount(notificationService.getUnreadCount(session.user.id))
                }
                break
        }
    }, [session?.user?.id])

    /**
     * Mark notification as read
     */
    const markAsRead = async (notificationId) => {
        if (!session?.user?.id) return

        try {
            await notificationService.markAsRead(notificationId, session.user.id)
        } catch (error) {
            console.error('Failed to mark notification as read:', error)
            toast.error('Failed to update notification')
        }
    }

    /**
     * Mark all notifications as read
     */
    const markAllAsRead = async () => {
        if (!session?.user?.id) return

        try {
            await notificationService.markAllAsRead(session.user.id)
            toast.success('All notifications marked as read')
        } catch (error) {
            console.error('Failed to mark all as read:', error)
            toast.error('Failed to update notifications')
        }
    }

    /**
     * Dismiss notification
     */
    const dismiss = async (notificationId) => {
        if (!session?.user?.id) return

        try {
            await notificationService.dismiss(notificationId, session.user.id)
        } catch (error) {
            console.error('Failed to dismiss notification:', error)
            toast.error('Failed to dismiss notification')
        }
    }

    /**
     * Refresh notifications
     */
    const refresh = async () => {
        await loadNotifications()
    }

    const value = {
        notifications,
        unreadCount,
        loading,
        markAsRead,
        markAllAsRead,
        dismiss,
        refresh
    }

    return (
        <NotificationContext.Provider value={value}>
            {children}
        </NotificationContext.Provider>
    )
}
