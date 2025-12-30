import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import User from '@/models/User'
import mongoose from 'mongoose'

// GET - Fetch user profile
export async function GET() {
  try {
    const session = await auth()

    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    await dbConnect()

    // Get the User document to obtain the userId
    const user = await User.findOne({ email: session.user.email })

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // Query by userId first (unique field), fallback to email
    let userProfile = await UserProfile.findOne({ userId: user._id })

    if (!userProfile) {
      // Try finding by email as fallback
      userProfile = await UserProfile.findOne({ email: session.user.email })
    }

    // If no profile exists, create a default one with userId
    if (!userProfile) {
      try {
        userProfile = await UserProfile.create({
          userId: user._id,
          email: session.user.email,
          name: session.user.name || '',
          profileImage: session.user.image || '',
          createdAt: new Date(),
          updatedAt: new Date()
        })
      } catch (createError) {
        // If duplicate key error, profile was created by another request
        // Fetch it again
        if (createError.code === 11000) {
          userProfile = await UserProfile.findOne({ userId: user._id })
          if (!userProfile) {
            throw createError // If still not found, throw the original error
          }
        } else {
          throw createError
        }
      }
    }

    return NextResponse.json({
      success: true,
      profile: {
        name: userProfile.name || session.user.name || '',
        email: userProfile.email,
        phone: userProfile.phone || '',
        location: userProfile.city || '',
        bio: userProfile.bio || '',
        dateOfBirth: userProfile.dateOfBirth || '',
        occupation: userProfile.occupation || '',
        image: userProfile.profileImage || session.user.image || ''
      }
    })
  } catch (error) {
    console.error('Profile fetch error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch profile', details: error.message },
      { status: 500 }
    )
  }
}

// PUT - Update user profile
export async function PUT(request) {
  try {
    const session = await auth()

    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const { name, phone, location, bio, dateOfBirth, occupation, image } = body

    await dbConnect()

    // Get the User document to obtain the userId
    const user = await User.findOne({ email: session.user.email })

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // Query by userId first (unique field), fallback to email
    let profile = await UserProfile.findOne({ userId: user._id })

    if (!profile) {
      // Try finding by email as fallback
      profile = await UserProfile.findOne({ email: session.user.email })
    }

    if (profile) {
      // Update existing profile
      profile.name = name || session.user.name || profile.name
      profile.phone = phone || profile.phone || ''
      profile.city = location || profile.city || ''
      profile.bio = bio || profile.bio || ''
      profile.dateOfBirth = dateOfBirth || profile.dateOfBirth || null
      profile.occupation = occupation || profile.occupation || ''
      profile.profileImage = image || session.user.image || profile.profileImage
      profile.updatedAt = new Date()

      // Ensure userId is set correctly
      if (!profile.userId || profile.userId.toString() !== user._id.toString()) {
        profile.userId = user._id
      }

      await profile.save()
    } else {
      // Create profile with userId if it doesn't exist
      try {
        profile = await UserProfile.create({
          userId: user._id,
          email: session.user.email,
          name: name || session.user.name || '',
          phone: phone || '',
          city: location || '',
          bio: bio || '',
          dateOfBirth: dateOfBirth || null,
          occupation: occupation || '',
          profileImage: image || session.user.image || '',
          createdAt: new Date(),
          updatedAt: new Date()
        })
      } catch (createError) {
        // If duplicate key error, profile exists - fetch and update it
        if (createError.code === 11000) {
          profile = await UserProfile.findOne({ userId: user._id })
          if (profile) {
            // Update the found profile
            profile.name = name || session.user.name || profile.name
            profile.phone = phone || profile.phone || ''
            profile.city = location || profile.city || ''
            profile.bio = bio || profile.bio || ''
            profile.dateOfBirth = dateOfBirth || profile.dateOfBirth || null
            profile.occupation = occupation || profile.occupation || ''
            profile.profileImage = image || session.user.image || profile.profileImage
            profile.updatedAt = new Date()
            await profile.save()
          } else {
            throw createError
          }
        } else {
          throw createError
        }
      }
    }

    if (!profile) {
      return NextResponse.json(
        { error: 'Failed to update profile' },
        { status: 500 }
      )
    }

    return NextResponse.json({
      success: true,
      message: 'Profile updated successfully',
      profile: {
        name: profile.name,
        email: profile.email,
        phone: profile.phone || '',
        location: profile.city || '',
        bio: profile.bio || '',
        dateOfBirth: profile.dateOfBirth || '',
        occupation: profile.occupation || '',
        image: profile.profileImage
      }
    })
  } catch (error) {
    console.error('Profile update error:', error)

    // Handle duplicate key error specifically
    if (error.code === 11000) {
      return NextResponse.json(
        { error: 'Profile already exists or duplicate data conflict' },
        { status: 409 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update profile', details: error.message },
      { status: 500 }
    )
  }
}