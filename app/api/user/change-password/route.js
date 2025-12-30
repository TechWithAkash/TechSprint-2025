import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"
import { connectToDatabase } from "@/lib/database"
import { encryptionService } from "@/lib/encryption"
import { changePasswordSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"
import { ObjectId } from "mongodb"

async function changePasswordHandler(req) {
  const session = await auth()
  
  if (!session?.user) {
    throw new AppError('Authentication required', 401, 'UNAUTHORIZED')
  }
  
  const body = await req.json()
  const validatedData = changePasswordSchema.parse(body)
  
  const db = await connectToDatabase()
  
  // Get current user with password
  const user = await db.collection("users").findOne({
    _id: new ObjectId(session.user.id)
  })
  
  if (!user) {
    throw new AppError('User not found', 404, 'USER_NOT_FOUND')
  }
  
  // Verify current password
  const isValidPassword = await encryptionService.verifyPassword(
    validatedData.currentPassword,
    user.password
  )
  
  if (!isValidPassword) {
    throw new AppError("Current password is incorrect", 400, "INVALID_CURRENT_PASSWORD")
  }
  
  // Hash new password
  const hashedNewPassword = await encryptionService.hashPassword(validatedData.newPassword)
  
  // Update password in database
  await db.collection("users").updateOne(
    { _id: new ObjectId(session.user.id) },
    {
      $set: {
        password: hashedNewPassword,
        updatedAt: new Date()
      }
    }
  )
  
  return NextResponse.json({
    success: true,
    message: "Password changed successfully",
    data: null
  })
}

export const POST = asyncHandler(changePasswordHandler)
