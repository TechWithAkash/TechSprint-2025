'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import SendOTPForm from '@/components/auth/SendOTPForm'
import VerifyOTPForm from '@/components/auth/VerifyOTPForm'
import { KeyRound, Eye, EyeOff, ArrowLeft } from 'lucide-react'
import { toast } from 'sonner'
import Link from 'next/link'

const resetPasswordSchema = z.object({
  password: z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password must be less than 128 characters'),
  confirmPassword: z.string(),
  otp: z.string().length(6, 'OTP must be exactly 6 digits').regex(/^\d{6}$/, 'OTP must contain only numbers')
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

export default function ForgotPasswordPage() {
  const [step, setStep] = useState('email') // 'email', 'otp', 'reset'
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const router = useRouter()
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue
  } = useForm({
    resolver: zodResolver(resetPasswordSchema)
  })

  const handleOtpSent = (sentEmail) => {
    setEmail(sentEmail)
    setValue('email', sentEmail)
    setStep('otp')
  }

  const handleOtpVerified = (data) => {
    setStep('reset')
  }

  const handleBackToEmail = () => {
    setStep('email')
  }

  const handleBackToOtp = () => {
    setStep('otp')
  }

  const onSubmit = async (data) => {
    setIsLoading(true)
    
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          password: data.password,
          otp: data.otp
        })
      })

      const result = await response.json()

      if (response.ok) {
        toast.success('🎉 Password reset successfully!', {
          description: 'You can now sign in with your new password',
          duration: 5000
        })
        router.push('/auth/signin?message=password-reset-complete&email=' + encodeURIComponent(email))
      } else {
        toast.error('Password reset failed', {
          description: result.message
        })
        if (result.code === 'OTP_VERIFICATION_REQUIRED') {
          setStep('otp')
        }
      }
    } catch (error) {
      toast.error('Network error', {
        description: 'Please check your connection and try again'
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Step 1: Email verification
  if (step === 'email') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <SendOTPForm 
            type="password-reset" 
            onOtpSent={handleOtpSent}
          />
          
          <div className="text-center space-y-2">
            <Link
              href="/auth/signin"
              className="inline-flex items-center text-sm text-blue-600 hover:text-blue-500 hover:bg-blue-50 px-3 py-2 rounded-md transition-all duration-200"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back to sign in
            </Link>
          </div>
        </div>
      </div>
    )
  }

  // Step 2: OTP verification
  if (step === 'otp') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <VerifyOTPForm 
            email={email}
            type="password-reset"
            onVerified={handleOtpVerified}
            onBack={handleBackToEmail}
          />
        </div>
      </div>
    )
  }

  // Step 3: Reset password
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <Card className="w-full shadow-xl border-0 bg-white/80 backdrop-blur-sm">
          <CardHeader className="space-y-1 pb-8">
            <div className="flex items-center justify-center w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-orange-500 to-red-600 rounded-full shadow-lg">
              <KeyRound className="w-8 h-8 text-white" />
            </div>
            <CardTitle className="text-3xl text-center font-bold bg-gradient-to-r from-orange-600 to-red-600 bg-clip-text text-transparent">
              Reset Password
            </CardTitle>
            <CardDescription className="text-center text-lg text-gray-600">
              Create your new secure password
            </CardDescription>
          </CardHeader>
          
          <form onSubmit={handleSubmit(onSubmit)}>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="email-display" className="text-sm font-medium">
                  Email Address
                </label>
                <Input
                  id="email-display"
                  type="email"
                  value={email}
                  disabled
                  className="bg-gray-50"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium">
                  New Password
                </label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Create a secure password"
                    disabled={isLoading}
                    {...register('password')}
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4 text-gray-400" />
                    ) : (
                      <Eye className="h-4 w-4 text-gray-400" />
                    )}
                  </button>
                </div>
                {errors.password && (
                  <p className="text-sm text-red-600">{errors.password.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <label htmlFor="confirmPassword" className="text-sm font-medium">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm your new password"
                    disabled={isLoading}
                    {...register('confirmPassword')}
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? (
                      <EyeOff className="h-4 w-4 text-gray-400" />
                    ) : (
                      <Eye className="h-4 w-4 text-gray-400" />
                    )}
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="text-sm text-red-600">{errors.confirmPassword.message}</p>
                )}
              </div>

              <input type="hidden" {...register('otp')} value="verified" />
            </CardContent>

            <div className="px-6 pb-6 space-y-4">
              <Button 
                type="submit" 
                className="w-full h-12 text-lg font-semibold bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-[1.02]" 
                disabled={isLoading}
              >
                {isLoading ? (
                  <div className="flex items-center space-x-2">
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Resetting Password...</span>
                  </div>
                ) : (
                  'Reset Password'
                )}
              </Button>
              
              <Button 
                type="button"
                variant="outline" 
                className="w-full h-12 border-gray-300 hover:border-gray-400 hover:bg-gray-50 transition-all duration-200" 
                onClick={handleBackToOtp}
                disabled={isLoading}
              >
                Back to OTP Verification
              </Button>
            </div>
          </form>
        </Card>
        
        <div className="text-center">
          <Link
            href="/auth/signin"
            className="inline-flex items-center text-sm text-blue-600 hover:text-blue-500 hover:bg-blue-50 px-3 py-2 rounded-md transition-all duration-200"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Back to sign in
          </Link>
        </div>
      </div>
    </div>
  )
}
