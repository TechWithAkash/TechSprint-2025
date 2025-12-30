import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { otpLoginSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"
import { signIn } from "@/lib/auth"

async function otpLoginHandler(req) {
  const body = await req.json()
  
  // Validate input data
  const validatedData = otpLoginSchema.parse(body)
  
  const db = await connectToDatabase()
  
  // Check if user exists
  const user = await db.collection("users").findOne({
    email: validatedData.email.toLowerCase()
  })
  
  if (!user) {
    throw new AppError('User with this email does not exist', 404, 'USER_NOT_FOUND')
  }
  
  // Verify the OTP
  const otpRecord = await db.collection("otps").findOne({
    email: validatedData.email.toLowerCase(),
    type: 'login',
    verified: true,
    verifiedAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) } // Within last 10 minutes
  }, { sort: { verifiedAt: -1 } })
  
  if (!otpRecord) {
    throw new AppError('OTP verification required. Please verify your OTP first.', 400, 'OTP_VERIFICATION_REQUIRED')
  }
  
  // Update last login
  await db.collection("users").updateOne(
    { _id: user._id },
    { 
      $set: { 
        lastLogin: new Date(),
        updatedAt: new Date()
      }
    }
  )
  
  // Mark the OTP as used for login
  await db.collection("otps").updateOne(
    { _id: otpRecord._id },
    { $set: { usedForLogin: true, usedAt: new Date() } }
  )
  
  // Create session data (compatible with NextAuth)
  const sessionUser = {
    id: user._id.toString(),
    email: user.email,
    name: user.name,
    image: user.avatar,
    isEmailVerified: user.isEmailVerified,
    preferences: user.preferences,
    profile: user.profile
  }
  
  return NextResponse.json({
    success: true,
    message: "Login successful!",
    data: {
      user: sessionUser,
      loginMethod: 'otp'
    }
  })
}

export const POST = asyncHandler(otpLoginHandler)
