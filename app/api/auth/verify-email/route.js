import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { encryptionService } from "@/lib/encryption"
import { verifyEmailSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"

async function verifyEmailHandler(req) {
  const { searchParams } = new URL(req.url)
  const token = searchParams.get('token')
  
  // Validate token
  const validatedData = verifyEmailSchema.parse({ token })
  
  const db = await connectToDatabase()
  
  // Validate token format
  if (!encryptionService.isValidToken(validatedData.token)) {
    throw new AppError("Invalid token format", 400, "INVALID_TOKEN_FORMAT")
  }
  
  // Find user with matching verification token that hasn't expired
  const user = await db.collection("users").findOne({
    emailVerificationToken: validatedData.token,
    emailVerificationExpires: { $gt: new Date() }
  })
  
  if (!user) {
    throw new AppError("Invalid or expired verification token", 400, "INVALID_VERIFICATION_TOKEN")
  }
  
  // Check if already verified
  if (user.isEmailVerified) {
    return NextResponse.json({
      success: true,
      message: "Email is already verified.",
      data: null
    })
  }
  
  // Update user to verified status
  await db.collection("users").updateOne(
    { _id: user._id },
    {
      $set: {
        isEmailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
        updatedAt: new Date()
      }
    }
  )
  
  return NextResponse.json({
    success: true,
    message: "Email verified successfully. You can now sign in.",
    data: {
      user: {
        id: user._id,
        email: user.email,
        isEmailVerified: true
      }
    }
  })
}

export const GET = asyncHandler(verifyEmailHandler)
