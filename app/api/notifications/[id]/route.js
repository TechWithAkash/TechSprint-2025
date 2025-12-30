// app/api/notifications/[id]/route.js
import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { connectToDatabase } from '@/lib/database'
import { ObjectId } from 'mongodb'

/**
 * PATCH /api/notifications/[id]
 * Update a specific notification (mark as read, dismiss, etc.)
 */
export async function PATCH(request, { params }) {
    try {
        const session = await auth()

        if (!session?.user) {
            return NextResponse.json(
                { success: false, error: 'Unauthorized' },
                { status: 401 }
            )
        }

        const { id } = params
        const updates = await request.json()

        if (!ObjectId.isValid(id)) {
            return NextResponse.json(
                { success: false, error: 'Invalid notification ID' },
                { status: 400 }
            )
        }

        const db = await connectToDatabase()

        // First, verify the notification belongs to the user
        const notification = await db.collection('notifications').findOne({
            _id: new ObjectId(id),
            userId: session.user.id
        })

        if (!notification) {
            return NextResponse.json(
                { success: false, error: 'Notification not found' },
                { status: 404 }
            )
        }

        // Update the notification
        const result = await db.collection('notifications').updateOne(
            { _id: new ObjectId(id) },
            {
                $set: {
                    ...updates,
                    updatedAt: new Date()
                }
            }
        )

        if (result.modifiedCount === 0) {
            return NextResponse.json(
                { success: false, error: 'Failed to update notification' },
                { status: 500 }
            )
        }

        // Fetch updated notification
        const updatedNotification = await db.collection('notifications').findOne({
            _id: new ObjectId(id)
        })

        return NextResponse.json({
            success: true,
            notification: {
                ...updatedNotification,
                id: updatedNotification._id.toString()
            }
        })

    } catch (error) {
        console.error('Update notification error:', error)
        return NextResponse.json(
            { success: false, error: 'Failed to update notification' },
            { status: 500 }
        )
    }
}

/**
 * DELETE /api/notifications/[id]
 * Delete a specific notification
 */
export async function DELETE(request, { params }) {
    try {
        const session = await auth()

        if (!session?.user) {
            return NextResponse.json(
                { success: false, error: 'Unauthorized' },
                { status: 401 }
            )
        }

        const { id } = params

        if (!ObjectId.isValid(id)) {
            return NextResponse.json(
                { success: false, error: 'Invalid notification ID' },
                { status: 400 }
            )
        }

        const db = await connectToDatabase()

        // Delete the notification (only if it belongs to the user)
        const result = await db.collection('notifications').deleteOne({
            _id: new ObjectId(id),
            userId: session.user.id
        })

        if (result.deletedCount === 0) {
            return NextResponse.json(
                { success: false, error: 'Notification not found' },
                { status: 404 }
            )
        }

        return NextResponse.json({
            success: true,
            message: 'Notification deleted successfully'
        })

    } catch (error) {
        console.error('Delete notification error:', error)
        return NextResponse.json(
            { success: false, error: 'Failed to delete notification' },
            { status: 500 }
        )
    }
}
