import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/database"
import { otpService } from "@/lib/otpService"
import { emailService } from "@/lib/emailService"
import { sendOtpSchema } from "@/lib/validations"
import { AppError, ValidationError, asyncHandler, formatErrorResponse } from "@/lib/errors"

async function sendOtpHandler(req) {
  const body = await req.json()
  const validatedData = sendOtpSchema.parse(body)

  const { email, type, name } = validatedData
  const db = await connectToDatabase()

  // Check if user exists based on type
  const existingUser = await db.collection("users").findOne({
    email: email.toLowerCase()
  })

  if (type === 'registration' && existingUser) {
    throw new AppError('User with this email already exists', 409, 'USER_EXISTS')
  }

  if ((type === 'login' || type === 'password_reset') && !existingUser) {
    throw new AppError('User with this email does not exist', 404, 'USER_NOT_FOUND')
  }

  // Get OTP history for rate limiting
  const rateLimitCheck = otpService.checkRateLimit(
    await db.collection("otps").find({
      email: email.toLowerCase(),
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
    }).toArray()
  )

  if (!rateLimitCheck.allowed) {
    throw new AppError(rateLimitCheck.message, 429, 'RATE_LIMITED')
  }

  // Check resend cooldown
  const lastOtp = await db.collection("otps").findOne(
    { email: email.toLowerCase(), type },
    { sort: { createdAt: -1 } }
  )

  const cooldownCheck = otpService.checkResendCooldown(lastOtp?.createdAt)
  if (!cooldownCheck.allowed) {
    throw new AppError(cooldownCheck.message, 429, 'COOLDOWN_ACTIVE')
  }

  // Generate new OTP
  const { otp, otpData } = await otpService.createOTPData(email, type)

  // Store OTP in database (invalidate previous OTPs of same type)
  await db.collection("otps").updateMany(
    { email: email.toLowerCase(), type },
    { $set: { verified: true, invalidated: true } }
  )

  await db.collection("otps").insertOne(otpData)

  // Send OTP via email
  try {
    // Use name from request body, or existing user name, or default to 'there'
    const userName = name || existingUser?.name || 'there'

    const emailContent = otpService.generateEmailContent(
      otp,
      type,
      userName
    )

    await emailService.sendEmail({
      to: email,
      subject: emailContent.subject,
      html: emailContent.html
    })
  } catch (emailError) {
    console.error('Failed to send OTP email:', emailError)
    throw new AppError('Failed to send OTP. Please try again.', 500, 'EMAIL_SEND_FAILED')
  }

  return NextResponse.json({
    success: true,
    message: `OTP sent to ${email}. Please check your inbox.`,
    data: {
      email,
      type,
      expiresIn: 600, // 10 minutes in seconds
      canResendAfter: 60 // 1 minute in seconds
    }
  })
}

export const POST = asyncHandler(sendOtpHandler)
