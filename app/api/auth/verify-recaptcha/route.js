import { NextResponse } from 'next/server'

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY

export async function POST(request) {
  try {
    const { token } = await request.json()

    if (!token) {
      return NextResponse.json(
        { success: false, message: 'reCAPTCHA token is required' },
        { status: 400 }
      )
    }

    // Verify the reCAPTCHA token with Google
    const verificationResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: RECAPTCHA_SECRET_KEY,
        response: token,
      }),
    })

    const verificationResult = await verificationResponse.json()

    if (verificationResult.success) {
      return NextResponse.json(
        { success: true, message: 'reCAPTCHA verification successful' },
        { status: 200 }
      )
    } else {
      return NextResponse.json(
        { 
          success: false, 
          message: 'reCAPTCHA verification failed',
          errors: verificationResult['error-codes'] || []
        },
        { status: 400 }
      )
    }
  } catch (error) {
    console.error('reCAPTCHA verification error:', error)
    return NextResponse.json(
      { success: false, message: 'Internal server error during reCAPTCHA verification' },
      { status: 500 }
    )
  }
}