import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { otpService } from "@/lib/otpService"
import { verifyOtpSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"

async function verifyOtpHandler(req) {
  const body = await req.json()
  const validatedData = verifyOtpSchema.parse(body)
  
  const { email, otp, type } = validatedData
  const db = await connectToDatabase()
  
  // Find the latest OTP for this email and type
  const storedOtp = await db.collection("otps").findOne(
    { 
      email: email.toLowerCase(), 
      type,
      verified: false,
      invalidated: { $ne: true }
    },
    { sort: { createdAt: -1 } }
  )
  
  if (!storedOtp) {
    throw new AppError('No valid OTP found. Please request a new one.', 404, 'OTP_NOT_FOUND')
  }
  
  // Validate OTP attempt
  const validation = await otpService.validateOTPAttempt(storedOtp, otp)
  
  // Update attempts count
  await db.collection("otps").updateOne(
    { _id: storedOtp._id },
    { $inc: { attempts: 1 } }
  )
  
  if (!validation.success) {
    // Return different messages based on error type
    const statusCodes = {
      'OTP_EXPIRED': 410,
      'OTP_ALREADY_USED': 410,
      'TOO_MANY_ATTEMPTS': 429,
      'INVALID_OTP': 400
    }
    
    const response = {
      success: false,
      message: validation.error,
      code: validation.code
    }
    
    if (validation.attemptsRemaining !== undefined) {
      response.attemptsRemaining = validation.attemptsRemaining
    }
    
    return NextResponse.json(response, { 
      status: statusCodes[validation.code] || 400 
    })
  }
  
  // Mark OTP as verified
  await db.collection("otps").updateOne(
    { _id: storedOtp._id },
    { 
      $set: { 
        verified: true,
        verifiedAt: new Date()
      }
    }
  )
  
  // Return success with appropriate message for each type
  const successMessages = {
    registration: 'Email verified successfully. You can now complete your registration.',
    login: 'OTP verified successfully. Logging you in...',
    password_reset: 'OTP verified successfully. You can now reset your password.'
  }
  
  return NextResponse.json({
    success: true,
    message: successMessages[type] || 'OTP verified successfully.',
    data: {
      email,
      type,
      verifiedAt: new Date(),
      // Include a verification token for subsequent requests
      verificationToken: storedOtp._id.toString()
    }
  })
}

export const POST = asyncHandler(verifyOtpHandler)
