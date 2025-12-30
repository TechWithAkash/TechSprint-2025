import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { otpService } from "@/lib/otpService"
import { emailService } from "@/lib/emailService"
import { forgotPasswordSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"

async function forgotPasswordHandler(req) {
  const body = await req.json()
  
  // Validate input data
  const validatedData = forgotPasswordSchema.parse(body)
  
  const db = await connectToDatabase()
  
  // Find user by email
  const user = await db.collection("users").findOne({
    email: validatedData.email.toLowerCase()
  })
  
  // Always return success for security (don't reveal if email exists)
  const successResponse = {
    success: true,
    message: "If an account with that email exists, we've sent an OTP for password reset.",
    data: null
  }
  
  if (!user) {
    return NextResponse.json(successResponse)
  }
  
  // Check rate limiting for password reset OTPs
  const rateLimitCheck = otpService.checkRateLimit(
    await db.collection("otps").find({
      email: user.email,
      type: 'password_reset',
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
    }).toArray()
  )
  
  if (!rateLimitCheck.allowed) {
    return NextResponse.json({
      success: false,
      message: rateLimitCheck.message,
      code: 'RATE_LIMITED'
    }, { status: 429 })
  }
  
  // Check resend cooldown
  const lastOtp = await db.collection("otps").findOne(
    { email: user.email, type: 'password_reset' },
    { sort: { createdAt: -1 } }
  )
  
  const cooldownCheck = otpService.checkResendCooldown(lastOtp?.createdAt)
  if (!cooldownCheck.allowed) {
    return NextResponse.json({
      success: false,
      message: cooldownCheck.message,
      code: 'COOLDOWN_ACTIVE'
    }, { status: 429 })
  }
  
  // Generate new OTP
  const { otp, otpData } = await otpService.createOTPData(user.email, 'password_reset')
  
  // Store OTP in database (invalidate previous password reset OTPs)
  await db.collection("otps").updateMany(
    { email: user.email, type: 'password_reset' },
    { $set: { verified: true, invalidated: true } }
  )
  
  await db.collection("otps").insertOne(otpData)
  
  // Send OTP via email (don't fail the request if email fails)
  try {
    const emailContent = otpService.generateEmailContent(otp, 'password_reset', user.name)
    
    await emailService.sendEmail({
      to: user.email,
      subject: emailContent.subject,
      html: emailContent.html
    })
  } catch (emailError) {
    console.error('Failed to send password reset OTP email:', emailError)
    // Log error but don't throw - we don't want to reveal if email exists
  }
  
  return NextResponse.json(successResponse)
}

export const POST = asyncHandler(forgotPasswordHandler)
