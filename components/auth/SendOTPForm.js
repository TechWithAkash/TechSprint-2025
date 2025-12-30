'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Mail, ArrowRight, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'

const sendOtpSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
})

export default function SendOTPForm({ type = 'registration', onOtpSent }) {
  const [isLoading, setIsLoading] = useState(false)
  const [countdown, setCountdown] = useState(0)
  const [otpSent, setOtpSent] = useState(false)
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    getValues
  } = useForm({
    resolver: zodResolver(sendOtpSchema)
  })

  const getTypeText = () => {
    switch (type) {
      case 'registration': return { title: 'Create Account', desc: 'Enter your email to get started' }
      case 'login': return { title: 'Sign In', desc: 'Enter your email to receive a login OTP' }
      case 'password_reset': return { title: 'Reset Password', desc: 'Enter your email to reset your password' }
      default: return { title: 'Verify Email', desc: 'Enter your email address' }
    }
  }

  const startCountdown = () => {
    setCountdown(60)
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }

  const onSubmit = async (data) => {
    setIsLoading(true)
    
    try {
      const response = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: data.email, type })
      })

      const result = await response.json()

      if (response.ok) {
        setOtpSent(true)
        startCountdown()
        toast.success(`OTP sent successfully! ${result.message}`)
        onOtpSent?.(data.email)
      } else {
        toast.error(`Failed to send OTP. ${result.message}`)
      }
    } catch (error) {
      toast.error('Network error. Please check your connection and try again')
    } finally {
      setIsLoading(false)
    }
  }

  const resendOtp = async () => {
    const email = getValues('email')
    if (!email) return
    
    setIsLoading(true)
    try {
      const response = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type })
      })

      const result = await response.json()

      if (response.ok) {
        startCountdown()
        toast.success(`OTP resent successfully! ${result.message}`)
      } else {
        toast.error(`Failed to resend OTP. ${result.message}`)
      }
    } catch (error) {
      toast.error('Network error. Please check your connection and try again')
    } finally {
      setIsLoading(false)
    }
  }

  const typeText = getTypeText()

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-blue-100 rounded-full">
          <Mail className="w-6 h-6 text-blue-600" />
        </div>
        <CardTitle className="text-2xl text-center">{typeText.title}</CardTitle>
        <CardDescription className="text-center">
          {typeText.desc}
        </CardDescription>
      </CardHeader>
      
      <form onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium">
              Email Address
            </label>
            <Input
              id="email"
              type="email"
              placeholder="Enter your email"
              disabled={isLoading || otpSent}
              {...register('email')}
            />
            {errors.email && (
              <p className="text-sm text-red-600">{errors.email.message}</p>
            )}
          </div>
          
          {otpSent && (
            <div className="p-4 bg-green-50 border border-green-200 rounded-md">
              <p className="text-sm text-green-800 font-medium">
                ✓ OTP sent successfully!
              </p>
              <p className="text-sm text-green-600 mt-1">
                Check your email and enter the 6-digit code below.
              </p>
            </div>
          )}
        </CardContent>

        <CardFooter className="flex flex-col space-y-4">
          {!otpSent ? (
            <Button 
              type="submit" 
              className="w-full" 
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Sending OTP...
                </>
              ) : (
                <>
                  Send OTP
                  <ArrowRight className="w-4 h-4 ml-2" />
                </>
              )}
            </Button>
          ) : (
            <Button 
              type="button"
              variant="outline" 
              className="w-full" 
              disabled={countdown > 0 || isLoading}
              onClick={resendOtp}
            >
              {countdown > 0 ? (
                `Resend OTP in ${countdown}s`
              ) : isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Resending...
                </>
              ) : (
                'Resend OTP'
              )}
            </Button>
          )}
        </CardFooter>
      </form>
    </Card>
  )
}
