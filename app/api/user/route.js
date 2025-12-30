import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"
import { connectToDatabase } from "@/lib/database"
import { encryptionService } from "@/lib/encryption"
import { updateProfileSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"
import { ObjectId } from "mongodb"

// GET /api/user - Get current user profile
async function getUserHandler(req) {
  const session = await auth()
  
  console.log('Get user - Session:', session)
  console.log('Get user - User ID:', session?.user?.id)
  
  if (!session?.user) {
    throw new AppError('Authentication required', 401, 'UNAUTHORIZED')
  }
  
  const db = await connectToDatabase()
  
  // Try to find user by ID first
  let userQuery
  const userId = session.user.id
  
  try {
    userQuery = { _id: new ObjectId(userId) }
  } catch (error) {
    console.log('Invalid ObjectId, trying string match:', error.message)
    userQuery = { _id: userId }
  }
  
  let user = await db.collection("users").findOne(
    userQuery,
    { 
      projection: { 
        password: 0, 
        passwordResetToken: 0, 
        passwordResetExpires: 0,
        emailVerificationToken: 0,
        emailVerificationExpires: 0
      } 
    }
  )
  
  // Fallback to email lookup if ID lookup fails
  if (!user && session.user.email) {
    console.log('User not found by ID, trying email:', session.user.email)
    user = await db.collection("users").findOne(
      { email: session.user.email },
      { 
        projection: { 
          password: 0, 
          passwordResetToken: 0, 
          passwordResetExpires: 0,
          emailVerificationToken: 0,
          emailVerificationExpires: 0
        } 
      }
    )
  }
  
  if (!user) {
    throw new AppError('User not found', 404, 'USER_NOT_FOUND')
  }
  
  console.log('Found user:', user._id)
  
  return NextResponse.json({
    success: true,
    data: { user }
  })
}

// PUT /api/user - Update user profile
async function updateUserHandler(req) {
  const session = await auth()
  
  console.log('Update user - Session:', session)
  console.log('Update user - User ID:', session?.user?.id)
  
  if (!session?.user) {
    throw new AppError('Authentication required', 401, 'UNAUTHORIZED')
  }
  
  const body = await req.json()
  console.log('Update user - Request body:', body)
  
  const validatedData = updateProfileSchema.parse(body)
  console.log('Update user - Validated data:', validatedData)
  
  const db = await connectToDatabase()
  
  // Debug: Check if user exists with the given ID
  const userId = session.user.id
  console.log('Looking for user with ID:', userId)
  console.log('ID type:', typeof userId)
  
  // Try to find the user first
  let userQuery
  try {
    userQuery = { _id: new ObjectId(userId) }
  } catch (error) {
    console.log('Invalid ObjectId, trying string match:', error.message)
    userQuery = { _id: userId }
  }
  
  console.log('User query:', userQuery)
  
  const existingUser = await db.collection("users").findOne(userQuery)
  console.log('Found user:', existingUser ? 'Yes' : 'No')
  
  if (!existingUser) {
    // Let's try to find by email as fallback
    console.log('Trying to find user by email:', session.user.email)
    const userByEmail = await db.collection("users").findOne({ 
      email: session.user.email 
    })
    console.log('Found user by email:', userByEmail ? 'Yes' : 'No')
    
    if (userByEmail) {
      console.log('User found by email, using that ID:', userByEmail._id)
      // Update session to use the correct ID
      session.user.id = userByEmail._id.toString()
      userQuery = { _id: userByEmail._id }
    } else {
      throw new AppError('User not found in database', 404, 'USER_NOT_FOUND')
    }
  }
  
  // Check if email is being changed and if it already exists
  if (validatedData.email) {
    const existingUser = await db.collection("users").findOne({
      email: validatedData.email.toLowerCase(),
      _id: { $ne: new ObjectId(session.user.id) }
    })
    
    if (existingUser) {
      throw new AppError('User with this email already exists', 409, 'DUPLICATE_EMAIL')
    }
  }
  
  // Prepare update data
  const updateData = {
    updatedAt: new Date()
  }
  
  if (validatedData.name) updateData.name = validatedData.name
  if (validatedData.avatar) updateData.avatar = validatedData.avatar
  if (validatedData.preferences) updateData.preferences = validatedData.preferences
  if (validatedData.profile) updateData.profile = validatedData.profile
  
  // If email is being changed, reset verification
  if (validatedData.email) {
    updateData.email = validatedData.email.toLowerCase()
    updateData.isEmailVerified = false
    
    const emailVerification = encryptionService.generateEmailVerificationToken()
    updateData.emailVerificationToken = emailVerification.token
    updateData.emailVerificationExpires = emailVerification.expiresAt
    
    // Send verification email for new email
    try {
      const { emailService } = await import('@/lib/emailService')
      await emailService.sendEmailVerification({
        email: validatedData.email,
        name: session.user.name || 'User'
      }, emailVerification.token)
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError)
    }
  }
  
  // Update user in database
  console.log('Updating user with query:', userQuery)
  console.log('Update data:', updateData)
  
  const result = await db.collection("users").findOneAndUpdate(
    userQuery,
    { $set: updateData },
    { 
      returnDocument: 'after',
      projection: { 
        password: 0, 
        passwordResetToken: 0, 
        passwordResetExpires: 0,
        emailVerificationToken: 0,
        emailVerificationExpires: 0
      }
    }
  )
  
  console.log('Update result:', result)
  
  if (!result) {
    throw new AppError('Failed to update user', 500, 'UPDATE_FAILED')
  }
  
  return NextResponse.json({
    success: true,
    message: validatedData.email ? "Profile updated. Please verify your new email address." : "Profile updated successfully",
    data: { user: result }
  })
}

export const GET = asyncHandler(getUserHandler)
export const PUT = asyncHandler(updateUserHandler)
