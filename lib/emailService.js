import nodemailer from 'nodemailer'

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    })
  }

  async sendEmail({ to, subject, html, text }) {
    try {
      const mailOptions = {
        from: `"WealthWise " <${process.env.SMTP_USER}>`,
        to,
        subject,
        html,
        text
      }

      const result = await this.transporter.sendMail(mailOptions)
      console.log('Email sent successfully:', result.messageId)
      return { success: true, messageId: result.messageId }
    } catch (error) {
      console.error('Email sending failed:', error)
      return { success: false, error: error.message }
    }
  }

  async sendWelcomeEmail(user) {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>Welcome to WealthWise</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <!-- Main Container -->
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">
                
                <!-- Header with Gradient -->
                <tr>
                  <td style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 56px 40px; text-align: center;">
                    <div style="background-color: rgba(255, 255, 255, 0.2); width: 80px; height: 80px; margin: 0 auto 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                      <span style="font-size: 48px;">💚</span>
                    </div>
                    <h1 style="margin: 0 0 12px 0; color: #ffffff; font-size: 32px; font-weight: 700; letter-spacing: -0.5px;">Welcome to WealthWise!</h1>
                    <p style="margin: 0; color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 24px;">Your journey to financial wellness starts here</p>
                  </td>
                </tr>
                
                <!-- Content -->
                <tr>
                  <td style="padding: 48px 40px;">
                    <p style="margin: 0 0 24px 0; font-size: 18px; line-height: 28px; color: #111827; font-weight: 500;">Hi ${user.name || 'there'}! 👋</p>
                    
                    <p style="margin: 0 0 32px 0; font-size: 16px; line-height: 26px; color: #6b7280;">We're thrilled to have you on board! WealthWise is here to help you take control of your finances with smart budgeting, expense tracking, and AI-powered insights.</p>
                    
                    <!-- Features Grid -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin: 32px 0;">
                      <tr>
                        <td style="padding-bottom: 20px;">
                          <div style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-radius: 12px; padding: 20px; border-left: 4px solid #10b981;">
                            <p style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600; color: #065f46;">🎯 Smart Budgeting</p>
                            <p style="margin: 0; font-size: 14px; line-height: 22px; color: #6b7280;">Create personalized budgets that adapt to your spending habits</p>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding-bottom: 20px;">
                          <div style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-radius: 12px; padding: 20px; border-left: 4px solid #3b82f6;">
                            <p style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600; color: #1e40af;">📊 Expense Tracking</p>
                            <p style="margin: 0; font-size: 14px; line-height: 22px; color: #6b7280;">Monitor your spending with easy-to-use tracking tools</p>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding-bottom: 20px;">
                          <div style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-radius: 12px; padding: 20px; border-left: 4px solid #f59e0b;">
                            <p style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600; color: #92400e;">🤖 AI Insights</p>
                            <p style="margin: 0; font-size: 14px; line-height: 22px; color: #6b7280;">Get personalized recommendations from our AI agents</p>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style="background: linear-gradient(135deg, #fce7f3 0%, #fbcfe8 100%); border-radius: 12px; padding: 20px; border-left: 4px solid #ec4899;">
                            <p style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600; color: #9f1239;">🎁 Goal Setting</p>
                            <p style="margin: 0; font-size: 14px; line-height: 22px; color: #6b7280;">Set and achieve your financial goals with guided support</p>
                          </div>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- CTA Button -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin: 40px 0;">
                      <tr>
                        <td align="center">
                          <a href="${process.env.NEXTAUTH_URL}/dashboard" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 16px 48px; border-radius: 12px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);">
                            Get Started Now →
                          </a>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- Help Section -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f9fafb; border-radius: 12px; padding: 24px; margin: 32px 0;">
                      <tr>
                        <td>
                          <p style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #374151;">Need help getting started?</p>
                          <p style="margin: 0; font-size: 13px; line-height: 20px; color: #6b7280;">Check out our guides or reach out to our support team. We're here to help you succeed!</p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 32px 40px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280; text-align: center;">Happy budgeting! 💰</p>
                    <p style="margin: 0 0 16px 0; font-size: 14px; color: #6b7280; text-align: center; font-weight: 500;">The WealthWise Team</p>
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

    const text = `
      Welcome to WealthWise!
      
      Hi ${user.name || 'there'}!
      
      We're thrilled to have you on board! WealthWise is here to help you take control of your finances with smart budgeting, expense tracking, and AI-powered insights.
      
      What You Can Do:
      
      🎯 Smart Budgeting
      Create personalized budgets that adapt to your spending habits
      
      📊 Expense Tracking
      Monitor your spending with easy-to-use tracking tools
      
      🤖 AI Insights
      Get personalized recommendations from our AI agents
      
      🎁 Goal Setting
      Set and achieve your financial goals with guided support
      
      Get Started Now:
      ${process.env.NEXTAUTH_URL}/dashboard
      
      Need help? Check out our guides or reach out to our support team. We're here to help you succeed!
      
      Happy budgeting! 💰
      The WealthWise Team
      
      © ${new Date().getFullYear()} WealthWise. All rights reserved.
    `

    return await this.sendEmail({
      to: user.email,
      subject: '🎉 Welcome to WealthWise - Let\'s Get Started!',
      html,
      text
    })
  }

  async sendEmailVerification(user, token) {
    const verificationUrl = `${process.env.NEXTAUTH_URL}/auth/verify-email?token=${token}`

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email Address</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.name}!</h2>
            <p>Thank you for registering with WealthWise . To complete your registration, please verify your email address by clicking the button below.</p>
            
            <a href="${verificationUrl}" class="button">Verify Email Address</a>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
            
            <p><strong>This link will expire in 24 hours.</strong></p>
            
            <p>If you didn't create an account with WealthWise , you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>Best regards,<br>The WealthWise  Team</p>
          </div>
        </div>
      </body>
      </html>
    `

    const text = `
      Verify Your Email Address
      
      Hello ${user.name}!
      
      Thank you for registering with WealthWise . To complete your registration, please verify your email address by visiting this link:
      
      ${verificationUrl}
      
      This link will expire in 24 hours.
      
      If you didn't create an account with WealthWise , you can safely ignore this email.
      
      Best regards,
      The WealthWise  Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: 'Verify Your Email Address',
      html,
      text
    })
  }

  async sendPasswordReset(user, token) {
    const resetUrl = `${process.env.NEXTAUTH_URL}/auth/reset-password?token=${token}`

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Reset Your Password</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.name}!</h2>
            <p>You requested to reset your password for your WealthWise  account. Click the button below to create a new password.</p>
            
            <a href="${resetUrl}" class="button">Reset Password</a>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">${resetUrl}</p>
            
            <div class="warning">
              <strong>Security Notice:</strong>
              <ul>
                <li>This link will expire in 1 hour for your security</li>
                <li>If you didn't request this reset, please ignore this email</li>
                <li>Your password will remain unchanged until you create a new one</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>Stay secure,<br>The WealthWise  Team</p>
          </div>
        </div>
      </body>
      </html>
    `

    const text = `
      Reset Your Password
      
      Hello ${user.name}!
      
      You requested to reset your password for your WealthWise  account. Visit this link to create a new password:
      
      ${resetUrl}
      
      Security Notice:
      - This link will expire in 1 hour for your security
      - If you didn't request this reset, please ignore this email
      - Your password will remain unchanged until you create a new one
      
      Stay secure,
      The WealthWise  Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: 'Reset Your Password - WealthWise ',
      html,
      text
    })
  }
  // ============================================
  // Emergency Alert Email Templates
  // ============================================

  /**
   * Send low balance alert email
   */
  async sendLowBalanceAlert({ user, currentBalance, threshold, accountName }) {
    const dashboardUrl = `${process.env.NEXTAUTH_URL}/dashboard`
    const isCritical = currentBalance < threshold * 0.5

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Low Balance Alert</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">

                <!-- Header -->
                <tr>
                  <td style="background: ${isCritical ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)'}; padding: 40px; text-align: center;">
                    <div style="width: 64px; height: 64px; margin: 0 auto 16px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                      <span style="font-size: 32px;">${isCritical ? '🚨' : '⚠️'}</span>
                    </div>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">
                      ${isCritical ? 'Critical Balance Alert!' : 'Low Balance Warning'}
                    </h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <p style="margin: 0 0 20px 0; font-size: 18px; color: #111827;">Hi ${user.name || 'there'},</p>

                    <div style="background: ${isCritical ? '#fef2f2' : '#fffbeb'}; border-radius: 12px; padding: 24px; margin: 24px 0; border-left: 4px solid ${isCritical ? '#dc2626' : '#f59e0b'};">
                      <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280;">Current Balance</p>
                      <p style="margin: 0; font-size: 32px; font-weight: 700; color: ${isCritical ? '#dc2626' : '#d97706'};">
                        ₹${currentBalance.toLocaleString('en-IN')}
                      </p>
                      ${accountName ? `<p style="margin: 8px 0 0 0; font-size: 14px; color: #6b7280;">${accountName}</p>` : ''}
                    </div>

                    <p style="margin: 0 0 16px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      Your balance has dropped ${isCritical ? 'critically' : ''} below your set threshold of <strong>₹${threshold.toLocaleString('en-IN')}</strong>.
                    </p>

                    <p style="margin: 0 0 24px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      ${isCritical
                        ? 'This is a critical situation. Please review your finances immediately to avoid any payment failures or overdraft charges.'
                        : 'We recommend reviewing your upcoming expenses and ensuring you have sufficient funds for essential payments.'
                      }
                    </p>

                    <!-- Action Button -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 16px 0;">
                          <a href="${dashboardUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 10px; font-size: 16px; font-weight: 600;">
                            Review Your Finances
                          </a>
                        </td>
                      </tr>
                    </table>

                    <!-- Tips -->
                    <div style="background: #f9fafb; border-radius: 12px; padding: 20px; margin-top: 24px;">
                      <p style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #374151;">💡 Quick Tips:</p>
                      <ul style="margin: 0; padding-left: 20px; color: #6b7280; font-size: 14px; line-height: 24px;">
                        <li>Review and postpone non-essential expenses</li>
                        <li>Check for any upcoming automatic payments</li>
                        <li>Consider transferring from savings if available</li>
                      </ul>
                    </div>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 24px 40px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">
                      This alert was sent because you enabled emergency notifications in your WealthWise settings.
                      <br>© ${new Date().getFullYear()} WealthWise. All rights reserved.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `

    const text = `
      ${isCritical ? 'CRITICAL' : 'LOW'} BALANCE ALERT

      Hi ${user.name || 'there'},

      Your current balance is ₹${currentBalance.toLocaleString('en-IN')}${accountName ? ` (${accountName})` : ''}.

      This is ${isCritical ? 'critically' : ''} below your set threshold of ₹${threshold.toLocaleString('en-IN')}.

      ${isCritical
        ? 'This is a critical situation. Please review your finances immediately.'
        : 'Please review your upcoming expenses and ensure sufficient funds.'
      }

      Review your finances: ${dashboardUrl}

      - The WealthWise Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: `${isCritical ? '🚨 CRITICAL' : '⚠️'} Low Balance Alert - ₹${currentBalance.toLocaleString('en-IN')}`,
      html,
      text
    })
  }

  /**
   * Send budget exceeded alert email
   */
  async sendBudgetExceededAlert({ user, categoryName, budgetAmount, spentAmount, percentage }) {
    const dashboardUrl = `${process.env.NEXTAUTH_URL}/dashboard/budget`
    const overspent = spentAmount - budgetAmount

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Budget Exceeded Alert</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">

                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 40px; text-align: center;">
                    <div style="width: 64px; height: 64px; margin: 0 auto 16px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                      <span style="font-size: 32px;">📊</span>
                    </div>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">Budget Exceeded!</h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <p style="margin: 0 0 20px 0; font-size: 18px; color: #111827;">Hi ${user.name || 'there'},</p>

                    <p style="margin: 0 0 24px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      You've exceeded your budget for <strong>${categoryName}</strong> this month.
                    </p>

                    <!-- Budget Details -->
                    <div style="background: #fef2f2; border-radius: 12px; padding: 24px; margin: 24px 0; border: 1px solid #fecaca;">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Category</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #111827;">${categoryName}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Budget</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #059669;">₹${budgetAmount.toLocaleString('en-IN')}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Spent</p>
                            <p style="margin: 4px 0 0 0; font-size: 24px; font-weight: 700; color: #dc2626;">₹${spentAmount.toLocaleString('en-IN')}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Over Budget</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #dc2626;">₹${overspent.toLocaleString('en-IN')} (${percentage}%)</p>
                          </td>
                        </tr>
                      </table>
                    </div>

                    <!-- Action Button -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 16px 0;">
                          <a href="${dashboardUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 10px; font-size: 16px; font-weight: 600;">
                            Review Budget
                          </a>
                        </td>
                      </tr>
                    </table>

                    <!-- Tips -->
                    <div style="background: #f9fafb; border-radius: 12px; padding: 20px; margin-top: 24px;">
                      <p style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #374151;">💡 What you can do:</p>
                      <ul style="margin: 0; padding-left: 20px; color: #6b7280; font-size: 14px; line-height: 24px;">
                        <li>Review recent expenses in this category</li>
                        <li>Reduce spending for the rest of the month</li>
                        <li>Adjust budget allocation if this is a regular pattern</li>
                      </ul>
                    </div>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 24px 40px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">
                      © ${new Date().getFullYear()} WealthWise. All rights reserved.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `

    const text = `
      BUDGET EXCEEDED ALERT

      Hi ${user.name || 'there'},

      You've exceeded your budget for ${categoryName} this month.

      Budget: ₹${budgetAmount.toLocaleString('en-IN')}
      Spent: ₹${spentAmount.toLocaleString('en-IN')}
      Over Budget: ₹${overspent.toLocaleString('en-IN')} (${percentage}%)

      Review your budget: ${dashboardUrl}

      - The WealthWise Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: `📊 Budget Exceeded: ${categoryName} - ${percentage}% over`,
      html,
      text
    })
  }

  /**
   * Send unusual expense alert email
   */
  async sendUnusualExpenseAlert({ user, expenseAmount, categoryName, averageAmount, multiplier }) {
    const dashboardUrl = `${process.env.NEXTAUTH_URL}/dashboard/expenses`

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Unusual Expense Alert</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">

                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%); padding: 40px; text-align: center;">
                    <div style="width: 64px; height: 64px; margin: 0 auto 16px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                      <span style="font-size: 32px;">🔍</span>
                    </div>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">Unusual Expense Detected</h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <p style="margin: 0 0 20px 0; font-size: 18px; color: #111827;">Hi ${user.name || 'there'},</p>

                    <p style="margin: 0 0 24px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      We detected an expense that's significantly higher than your usual spending pattern.
                    </p>

                    <!-- Expense Details -->
                    <div style="background: #f5f3ff; border-radius: 12px; padding: 24px; margin: 24px 0; border: 1px solid #c4b5fd;">
                      <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280;">Recent Expense</p>
                      <p style="margin: 0 0 16px 0; font-size: 32px; font-weight: 700; color: #7c3aed;">
                        ₹${expenseAmount.toLocaleString('en-IN')}
                      </p>
                      <p style="margin: 0 0 8px 0; font-size: 14px; color: #6b7280;">
                        Category: <strong>${categoryName}</strong>
                      </p>
                      <p style="margin: 0; font-size: 14px; color: #6b7280;">
                        This is <strong>${multiplier}x</strong> your average (₹${averageAmount.toLocaleString('en-IN')})
                      </p>
                    </div>

                    <p style="margin: 0 0 24px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      If this expense was made by you and is expected, no action is needed. However, if you don't recognize this transaction, please review it immediately.
                    </p>

                    <!-- Action Button -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 16px 0;">
                          <a href="${dashboardUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 10px; font-size: 16px; font-weight: 600;">
                            Review Expense
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 24px 40px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">
                      © ${new Date().getFullYear()} WealthWise. All rights reserved.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `

    const text = `
      UNUSUAL EXPENSE DETECTED

      Hi ${user.name || 'there'},

      We detected an expense that's significantly higher than usual.

      Amount: ₹${expenseAmount.toLocaleString('en-IN')}
      Category: ${categoryName}
      This is ${multiplier}x your average (₹${averageAmount.toLocaleString('en-IN')})

      Review this expense: ${dashboardUrl}

      - The WealthWise Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: `🔍 Unusual Expense: ₹${expenseAmount.toLocaleString('en-IN')} in ${categoryName}`,
      html,
      text
    })
  }

  /**
   * Send EMI at risk alert email
   */
  async sendEMIRiskAlert({ user, emiAmount, emiName, dueDate, currentBalance }) {
    const dashboardUrl = `${process.env.NEXTAUTH_URL}/dashboard`
    const shortfall = emiAmount - currentBalance

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>EMI Payment At Risk</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); overflow: hidden;">

                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 40px; text-align: center;">
                    <div style="width: 64px; height: 64px; margin: 0 auto 16px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                      <span style="font-size: 32px;">🏦</span>
                    </div>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">EMI Payment At Risk!</h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <p style="margin: 0 0 20px 0; font-size: 18px; color: #111827;">Hi ${user.name || 'there'},</p>

                    <p style="margin: 0 0 24px 0; font-size: 16px; line-height: 24px; color: #4b5563;">
                      Your upcoming EMI payment may be at risk due to insufficient balance.
                    </p>

                    <!-- EMI Details -->
                    <div style="background: #fef2f2; border-radius: 12px; padding: 24px; margin: 24px 0; border: 1px solid #fecaca;">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">EMI</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #111827;">${emiName}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">EMI Amount</p>
                            <p style="margin: 4px 0 0 0; font-size: 24px; font-weight: 700; color: #dc2626;">₹${emiAmount.toLocaleString('en-IN')}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Due Date</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #111827;">${new Date(dueDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Current Balance</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #f59e0b;">₹${currentBalance.toLocaleString('en-IN')}</p>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 8px 0;">
                            <p style="margin: 0; font-size: 14px; color: #6b7280;">Shortfall</p>
                            <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 600; color: #dc2626;">₹${shortfall.toLocaleString('en-IN')}</p>
                          </td>
                        </tr>
                      </table>
                    </div>

                    <div style="background: #fffbeb; border-radius: 8px; padding: 16px; margin-bottom: 24px; border: 1px solid #fde68a;">
                      <p style="margin: 0; font-size: 14px; color: #92400e;">
                        <strong>⚠️ Important:</strong> Missing EMI payments can affect your credit score and result in late payment fees.
                      </p>
                    </div>

                    <!-- Action Button -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 16px 0;">
                          <a href="${dashboardUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 10px; font-size: 16px; font-weight: 600;">
                            Manage Your Finances
                          </a>
                        </td>
                      </tr>
                    </table>

                    <!-- Tips -->
                    <div style="background: #f9fafb; border-radius: 12px; padding: 20px; margin-top: 24px;">
                      <p style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #374151;">💡 Suggestions:</p>
                      <ul style="margin: 0; padding-left: 20px; color: #6b7280; font-size: 14px; line-height: 24px;">
                        <li>Transfer funds from savings to ensure EMI payment</li>
                        <li>Contact your bank if you need payment flexibility</li>
                        <li>Set up auto-pay to avoid future payment risks</li>
                      </ul>
                    </div>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 24px 40px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; font-size: 12px; color: #9ca3af; text-align: center;">
                      © ${new Date().getFullYear()} WealthWise. All rights reserved.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `

    const text = `
      EMI PAYMENT AT RISK!

      Hi ${user.name || 'there'},

      Your upcoming EMI payment may be at risk due to insufficient balance.

      EMI: ${emiName}
      Amount: ₹${emiAmount.toLocaleString('en-IN')}
      Due Date: ${new Date(dueDate).toLocaleDateString('en-IN')}
      Current Balance: ₹${currentBalance.toLocaleString('en-IN')}
      Shortfall: ₹${shortfall.toLocaleString('en-IN')}

      ⚠️ Missing EMI payments can affect your credit score.

      Manage your finances: ${dashboardUrl}

      - The WealthWise Team
    `

    return await this.sendEmail({
      to: user.email,
      subject: `🏦 URGENT: EMI Payment At Risk - ${emiName}`,
      html,
      text
    })
  }
}

export const emailService = new EmailService()
