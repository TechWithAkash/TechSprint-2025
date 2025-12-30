import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { encryptionService } from "@/lib/encryption"
import { emailService } from "@/lib/emailService"
import { registerSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"
import { ObjectId } from "mongodb"

async function registerHandler(req) {
  const body = await req.json()
  
  // Validate input data
  const validatedData = registerSchema.parse(body)
  
  const db = await connectToDatabase()
  
  // Check if user already exists
  const existingUser = await db.collection("users").findOne({
    email: validatedData.email.toLowerCase()
  })
  
  if (existingUser) {
    throw new AppError('User with this email already exists', 409, 'DUPLICATE_EMAIL')
  }
  
  // Verify the OTP before proceeding with registration
  const otpRecord = await db.collection("otps").findOne({
    email: validatedData.email.toLowerCase(),
    type: 'registration',
    verified: true,
    verifiedAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) } // Within last 10 minutes
  }, { sort: { verifiedAt: -1 } })
  
  if (!otpRecord) {
    throw new AppError('OTP verification required. Please verify your email first.', 400, 'OTP_VERIFICATION_REQUIRED')
  }
  
  // Hash password
  const hashedPassword = await encryptionService.hashPassword(validatedData.password)
  
  // Create user object
  const newUser = {
    email: validatedData.email.toLowerCase(),
    password: hashedPassword,
    name: validatedData.name,
    avatar: null,
    isEmailVerified: true, // Since OTP was verified
    emailVerificationToken: null,
    emailVerificationExpires: null,
    passwordResetToken: null,
    passwordResetExpires: null,
    preferences: {
      currency: 'USD',
      language: 'en',
      timezone: 'UTC',
      notifications: {
        email: true,
        push: true,
        budgetAlerts: true,
        goalReminders: true
      },
      privacy: {
        shareData: false,
        analytics: true
      }
    },
    profile: {
      city: '',
      country: '',
      familySize: 1,
      ageRange: '',
      occupation: '',
      financialExperience: 'beginner'
    },
    subscription: {
      plan: 'free',
      status: 'active',
      startDate: new Date(),
      endDate: null
    },
    lastLogin: null,
    createdAt: new Date(),
    updatedAt: new Date()
  }
  
  // Insert user into database
  const result = await db.collection("users").insertOne(newUser)
  
  // Mark the OTP as used for registration
  await db.collection("otps").updateOne(
    { _id: otpRecord._id },
    { $set: { usedForRegistration: true, usedAt: new Date() } }
  )
  
  // Send welcome email
  try {
    await emailService.sendWelcomeEmail({
      email: newUser.email,
      name: newUser.name
    })
  } catch (emailError) {
    console.error('Failed to send welcome email:', emailError)
    // Continue with registration even if welcome email fails
  }
  
  // Return success response (don't include sensitive data)
  return NextResponse.json({
    success: true,
    message: "Registration successful! Welcome to WealthWise .",
    data: {
      user: {
        id: result.insertedId,
        email: newUser.email,
        name: newUser.name,
        isEmailVerified: newUser.isEmailVerified,
        createdAt: newUser.createdAt
      }
    }
  }, { status: 201 })
}

export const POST = asyncHandler(registerHandler)
