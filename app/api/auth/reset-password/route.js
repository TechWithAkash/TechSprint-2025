import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { encryptionService } from "@/lib/encryption"
import { resetPasswordSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"
import { z } from 'zod'

// Updated schema for OTP-based password reset
const otpResetPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
  otp: z.string().length(6, 'OTP must be exactly 6 digits').regex(/^\d{6}$/, 'OTP must contain only numbers'),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password must be less than 128 characters'),
  confirmPassword: z.string()
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

async function resetPasswordHandler(req) {
  const body = await req.json()
  
  // Validate input data
  const validatedData = otpResetPasswordSchema.parse(body)
  
  const db = await connectToDatabase()
  
  // Find user by email
  const user = await db.collection("users").findOne({
    email: validatedData.email.toLowerCase()
  })
  
  if (!user) {
    throw new AppError("User not found", 404, "USER_NOT_FOUND")
  }
  
  // Verify the OTP for password reset
  const otpRecord = await db.collection("otps").findOne({
    email: validatedData.email.toLowerCase(),
    type: 'password_reset',
    verified: true,
    verifiedAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) } // Within last 10 minutes
  }, { sort: { verifiedAt: -1 } })
  
  if (!otpRecord) {
    throw new AppError("OTP verification required. Please verify your OTP first.", 400, "OTP_VERIFICATION_REQUIRED")
  }
  
  // Hash new password
  const hashedPassword = await encryptionService.hashPassword(validatedData.password)
  
  // Update user password
  await db.collection("users").updateOne(
    { _id: user._id },
    {
      $set: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
        updatedAt: new Date()
      }
    }
  )
  
  // Mark the OTP as used for password reset
  await db.collection("otps").updateOne(
    { _id: otpRecord._id },
    { $set: { usedForPasswordReset: true, usedAt: new Date() } }
  )
  
  return NextResponse.json({
    success: true,
    message: "Password reset successfully. You can now sign in with your new password.",
    data: null
  })
}

export const POST = asyncHandler(resetPasswordHandler)
