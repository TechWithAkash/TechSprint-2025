// Modern OTP service with rate limiting and security
import crypto from 'crypto'
import { encryptionService } from './encryption.js'
import config from './config.js'

export class OTPService {
  constructor() {
    this.otpLength = 6
    this.otpExpiry = 10 * 60 * 1000 // 10 minutes
    this.maxAttempts = 5
    this.resendCooldown = 60 * 1000 // 1 minute
    this.rateLimitWindow = 15 * 60 * 1000 // 15 minutes
    this.maxOtpPerWindow = 5
  }

  /**
   * Generate a secure 6-digit OTP
   */
  generateOTP() {
    // Generate cryptographically secure random 6-digit number
    const randomBytes = crypto.randomBytes(4)
    const randomNumber = randomBytes.readUInt32BE(0)
    const otp = String(randomNumber % 1000000).padStart(6, '0')

    return otp
  }

  /**
   * Hash OTP for secure storage
   */
  async hashOTP(otp) {
    return await encryptionService.hashPassword(otp)
  }

  /**
   * Verify OTP against hash
   */
  async verifyOTP(otp, hashedOtp) {
    return await encryptionService.verifyPassword(otp, hashedOtp)
  }

  /**
   * Create OTP data for database storage
   */
  async createOTPData(email, type) {
    const otp = this.generateOTP()
    const hashedOtp = await this.hashOTP(otp)
    const expiresAt = new Date(Date.now() + this.otpExpiry)

    return {
      otp, // Plain OTP for sending via email/SMS
      otpData: {
        email: email.toLowerCase(),
        hashedOtp,
        type,
        expiresAt,
        attempts: 0,
        createdAt: new Date(),
        verified: false
      }
    }
  }

  /**
   * Validate OTP attempt
   */
  async validateOTPAttempt(storedOtpData, providedOtp) {
    // Check if OTP has expired
    if (new Date() > storedOtpData.expiresAt) {
      return {
        success: false,
        error: 'OTP has expired',
        code: 'OTP_EXPIRED'
      }
    }

    // Check if already verified
    if (storedOtpData.verified) {
      return {
        success: false,
        error: 'OTP already used',
        code: 'OTP_ALREADY_USED'
      }
    }

    // Check attempts limit
    if (storedOtpData.attempts >= this.maxAttempts) {
      return {
        success: false,
        error: 'Too many invalid attempts',
        code: 'TOO_MANY_ATTEMPTS'
      }
    }

    // Verify OTP
    const isValid = await this.verifyOTP(providedOtp, storedOtpData.hashedOtp)

    if (!isValid) {
      return {
        success: false,
        error: 'Invalid OTP',
        code: 'INVALID_OTP',
        attemptsRemaining: this.maxAttempts - (storedOtpData.attempts + 1)
      }
    }

    return {
      success: true,
      message: 'OTP verified successfully'
    }
  }

  /**
   * Check rate limiting for OTP requests
   */
  checkRateLimit(otpHistory) {
    const now = new Date()
    const windowStart = new Date(now.getTime() - this.rateLimitWindow)

    const recentRequests = otpHistory.filter(request =>
      request.createdAt > windowStart
    )

    if (recentRequests.length >= this.maxOtpPerWindow) {
      const oldestRequest = recentRequests[0]
      const timeUntilReset = oldestRequest.createdAt.getTime() + this.rateLimitWindow - now.getTime()

      return {
        allowed: false,
        timeUntilReset: Math.ceil(timeUntilReset / 1000), // seconds
        message: `Too many OTP requests. Try again in ${Math.ceil(timeUntilReset / 1000 / 60)} minutes.`
      }
    }

    return { allowed: true }
  }

  /**
   * Check resend cooldown
   */
  checkResendCooldown(lastOtpTime) {
    if (!lastOtpTime) return { allowed: true }

    const now = new Date()
    const timeSinceLastOtp = now.getTime() - lastOtpTime.getTime()

    if (timeSinceLastOtp < this.resendCooldown) {
      const timeUntilResend = this.resendCooldown - timeSinceLastOtp

      return {
        allowed: false,
        timeUntilResend: Math.ceil(timeUntilResend / 1000), // seconds
        message: `Please wait ${Math.ceil(timeUntilResend / 1000)} seconds before requesting another OTP.`
      }
    }

    return { allowed: true }
  }

  /**
   * Generate email content for OTP
   */
  generateEmailContent(otp, type, userName = 'there') {
    const templates = {
      registration: {
        subject: 'Verify Your Account - WealthWise',
        html: `
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <title>Verify Your Account</title>
          </head>
          <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td align="center" style="padding: 40px 20px;">
                  <!-- Main Container -->
                  <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">
                    
                    <!-- Header -->
                    <tr>
                      <td style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 48px 40px; text-align: center;">
                        <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">🎉 Welcome to WealthWise</h1>
                      </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                      <td style="padding: 48px 40px;">
                        <p style="margin: 0 0 24px 0; font-size: 18px; line-height: 28px; color: #111827; font-weight: 500;">Hi ${userName},</p>
                        
                        <p style="margin: 0 0 32px 0; font-size: 16px; line-height: 26px; color: #6b7280;">Thank you for joining WealthWise! We're excited to help you take control of your finances. To get started, please verify your account with the code below:</p>
                        
                        <!-- OTP Box -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td align="center" style="padding: 32px 0;">
                              <div style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border: 2px solid #10b981; border-radius: 12px; padding: 32px; display: inline-block;">
                                <p style="margin: 0 0 12px 0; font-size: 14px; color: #059669; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Verification Code</p>
                                <p style="margin: 0; font-size: 40px; font-weight: 700; color: #065f46; letter-spacing: 12px; font-family: 'Courier New', monospace;">${otp}</p>
                              </div>
                            </td>
                          </tr>
                        </table>
                        
                        <!-- Expiry Notice -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px; padding: 16px; margin: 24px 0;">
                          <tr>
                            <td>
                              <p style="margin: 0; font-size: 14px; color: #92400e; line-height: 22px;">
                                <strong>⏱️ Time Sensitive:</strong> This code expires in <strong>10 minutes</strong> for your security.
                              </p>
                            </td>
                          </tr>
                        </table>
                        
                        <p style="margin: 24px 0 0 0; font-size: 14px; line-height: 22px; color: #9ca3af;">If you didn't create an account, please ignore this email or contact our support team if you have concerns.</p>
                      </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                      <td style="background-color: #f9fafb; padding: 32px 40px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280; text-align: center;">Sent with ❤️ by the WealthWise Team</p>
                        <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">© ${new Date().getFullYear()} WealthWise. All rights reserved.</p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `
      },
      login: {
        subject: 'Login Verification Code - WealthWise',
        html: `
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <title>Login Verification</title>
          </head>
          <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td align="center" style="padding: 40px 20px;">
                  <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">
                    
                    <!-- Header -->
                    <tr>
                      <td style="background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); padding: 48px 40px; text-align: center;">
                        <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">🔐 Secure Login</h1>
                      </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                      <td style="padding: 48px 40px;">
                        <p style="margin: 0 0 24px 0; font-size: 18px; line-height: 28px; color: #111827; font-weight: 500;">Hi ${userName},</p>
                        
                        <p style="margin: 0 0 32px 0; font-size: 16px; line-height: 26px; color: #6b7280;">A login attempt was made to your WealthWise account. Enter the verification code below to proceed:</p>
                        
                        <!-- OTP Box -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td align="center" style="padding: 32px 0;">
                              <div style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border: 2px solid #3b82f6; border-radius: 12px; padding: 32px; display: inline-block;">
                                <p style="margin: 0 0 12px 0; font-size: 14px; color: #2563eb; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Login Code</p>
                                <p style="margin: 0; font-size: 40px; font-weight: 700; color: #1e40af; letter-spacing: 12px; font-family: 'Courier New', monospace;">${otp}</p>
                              </div>
                            </td>
                          </tr>
                        </table>
                        
                        <!-- Security Notice -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px; padding: 16px; margin: 24px 0;">
                          <tr>
                            <td>
                              <p style="margin: 0; font-size: 14px; color: #92400e; line-height: 22px;">
                                <strong>⏱️ Valid for:</strong> 10 minutes only
                              </p>
                            </td>
                          </tr>
                        </table>
                        
                        <!-- Warning Box -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 8px; padding: 16px; margin: 24px 0;">
                          <tr>
                            <td>
                              <p style="margin: 0; font-size: 14px; color: #991b1b; line-height: 22px;">
                                <strong>⚠️ Security Alert:</strong> If you didn't attempt to log in, please secure your account immediately by changing your password.
                              </p>
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                      <td style="background-color: #f9fafb; padding: 32px 40px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280; text-align: center;">Sent with ❤️ by the WealthWise Team</p>
                        <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">© ${new Date().getFullYear()} WealthWise. All rights reserved.</p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `
      },
      password_reset: {
        subject: 'Password Reset Code - WealthWise',
        html: `
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <title>Password Reset</title>
          </head>
          <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td align="center" style="padding: 40px 20px;">
                  <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">
                    
                    <!-- Header -->
                    <tr>
                      <td style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); padding: 48px 40px; text-align: center;">
                        <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">🔑 Password Reset</h1>
                      </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                      <td style="padding: 48px 40px;">
                        <p style="margin: 0 0 24px 0; font-size: 18px; line-height: 28px; color: #111827; font-weight: 500;">Hi ${userName},</p>
                        
                        <p style="margin: 0 0 32px 0; font-size: 16px; line-height: 26px; color: #6b7280;">We received a request to reset your password. Use the verification code below to proceed with creating a new password:</p>
                        
                        <!-- OTP Box -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td align="center" style="padding: 32px 0;">
                              <div style="background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border: 2px solid #ef4444; border-radius: 12px; padding: 32px; display: inline-block;">
                                <p style="margin: 0 0 12px 0; font-size: 14px; color: #dc2626; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Reset Code</p>
                                <p style="margin: 0; font-size: 40px; font-weight: 700; color: #991b1b; letter-spacing: 12px; font-family: 'Courier New', monospace;">${otp}</p>
                              </div>
                            </td>
                          </tr>
                        </table>
                        
                        <!-- Expiry Notice -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px; padding: 16px; margin: 24px 0;">
                          <tr>
                            <td>
                              <p style="margin: 0; font-size: 14px; color: #92400e; line-height: 22px;">
                                <strong>⏱️ Time Sensitive:</strong> This code expires in <strong>10 minutes</strong>
                              </p>
                            </td>
                          </tr>
                        </table>
                        
                        <!-- Security Info -->
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 8px; padding: 16px; margin: 24px 0;">
                          <tr>
                            <td>
                              <p style="margin: 0 0 8px 0; font-size: 14px; color: #1e40af; line-height: 22px; font-weight: 600;">
                                🛡️ Security Tips:
                              </p>
                              <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #1e40af; line-height: 20px;">
                                <li>Never share this code with anyone</li>
                                <li>WealthWise will never ask for your code</li>
                                <li>Use a strong, unique password</li>
                              </ul>
                            </td>
                          </tr>
                        </table>
                        
                        <p style="margin: 24px 0 0 0; font-size: 14px; line-height: 22px; color: #9ca3af;">If you didn't request a password reset, please ignore this email or contact support if you have concerns about your account security.</p>
                      </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                      <td style="background-color: #f9fafb; padding: 32px 40px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280; text-align: center;">Sent with ❤️ by the WealthWise Team</p>
                        <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">© ${new Date().getFullYear()} WealthWise. All rights reserved.</p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `
      }
    }

    return templates[type] || templates.registration
  }
}

// Create singleton instance
export const otpService = new OTPService()
export default otpService
