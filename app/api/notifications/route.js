// app/api/notifications/route.js
import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { connectToDatabase } from '@/lib/database'

/**
 * GET /api/notifications
 * Fetch all notifications for the authenticated user
 */
export async function GET(request) {
    try {
        const session = await auth()

        if (!session?.user) {
            return NextResponse.json(
                { success: false, error: 'Unauthorized' },
                { status: 401 }
            )
        }

        const { searchParams } = new URL(request.url)
        const limit = parseInt(searchParams.get('limit') || '50')
        const includeRead = searchParams.get('includeRead') !== 'false'
        const includeDismissed = searchParams.get('includeDismissed') === 'true'
        const category = searchParams.get('category')
        const priority = searchParams.get('priority')

        const db = await connectToDatabase()

        // Build query
        const query = {
            userId: session.user.id
        }

        if (!includeRead) {
            query.read = false
        }

        if (!includeDismissed) {
            query.dismissed = { $ne: true }
        }

        if (category) {
            query.category = category
        }

        if (priority) {
            query.priority = priority
        }

        // Fetch notifications
        const notifications = await db
            .collection('notifications')
            .find(query)
            .sort({ timestamp: -1 })
            .limit(limit)
            .toArray()

        // Format notifications
        const formattedNotifications = notifications.map(notif => ({
            ...notif,
            id: notif._id.toString(),
            _id: undefined
        }))

        return NextResponse.json({
            success: true,
            notifications: formattedNotifications,
            count: formattedNotifications.length
        })

    } catch (error) {
        console.error('Get notifications error:', error)
        return NextResponse.json(
            { success: false, error: 'Failed to fetch notifications' },
            { status: 500 }
        )
    }
}

/**
 * POST /api/notifications
 * Create a new notification
 */
export async function POST(request) {
    try {
        const session = await auth()

        if (!session?.user) {
            return NextResponse.json(
                { success: false, error: 'Unauthorized' },
                { status: 401 }
            )
        }

        const data = await request.json()

        const {
            userId,
            type,
            priority,
            category,
            title,
            message,
            actionLabel,
            actionUrl,
            metadata
        } = data

        // Validate required fields
        if (!type || !priority || !category || !title || !message) {
            return NextResponse.json(
                { success: false, error: 'Missing required fields' },
                { status: 400 }
            )
        }

        // Ensure userId matches session
        if (userId && userId !== session.user.id) {
            return NextResponse.json(
                { success: false, error: 'Invalid user ID' },
                { status: 403 }
            )
        }

        const db = await connectToDatabase()

        // Create notification
        const notification = {
            userId: session.user.id,
            type,
            priority,
            category,
            title,
            message,
            actionLabel: actionLabel || null,
            actionUrl: actionUrl || null,
            metadata: metadata || {},
            read: false,
            dismissed: false,
            timestamp: new Date(),
            createdAt: new Date()
        }

        const result = await db.collection('notifications').insertOne(notification)

        return NextResponse.json({
            success: true,
            notification: {
                ...notification,
                id: result.insertedId.toString()
            }
        })

    } catch (error) {
        console.error('Create notification error:', error)
        return NextResponse.json(
            { success: false, error: 'Failed to create notification' },
            { status: 500 }
        )
    }
}

/**
 * PATCH /api/notifications/bulk
 * Bulk update notifications (e.g., mark all as read)
 */
export async function PATCH(request) {
    try {
        const session = await auth()

        if (!session?.user) {
            return NextResponse.json(
                { success: false, error: 'Unauthorized' },
                { status: 401 }
            )
        }

        const { userId, updates } = await request.json()

        if (userId !== session.user.id) {
            return NextResponse.json(
                { success: false, error: 'Invalid user ID' },
                { status: 403 }
            )
        }

        const db = await connectToDatabase()

        const result = await db.collection('notifications').updateMany(
            { userId: session.user.id, dismissed: { $ne: true } },
            {
                $set: {
                    ...updates,
                    updatedAt: new Date()
                }
            }
        )

        return NextResponse.json({
            success: true,
            modifiedCount: result.modifiedCount
        })

    } catch (error) {
        console.error('Bulk update notifications error:', error)
        return NextResponse.json(
            { success: false, error: 'Failed to update notifications' },
            { status: 500 }
        )
    }
}
