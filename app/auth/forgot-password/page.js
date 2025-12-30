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
import toast from 'react-hot-toast'
import Link from 'next/link'

const resetPasswordSchema = z.object({
  password: z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password must be less than 128 characters'),
  confirmPassword: z.string()
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

const resetPasswordWithOtpSchema = z.object({
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
  const [verifiedOtp, setVerifiedOtp] = useState('')
  const [verificationToken, setVerificationToken] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const router = useRouter()
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    getValues
  } = useForm({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: '',
      confirmPassword: ''
    }
  })

  const handleOtpSent = (sentEmail) => {
    setEmail(sentEmail)
    setValue('email', sentEmail)
    setStep('otp')
  }

  const handleOtpVerified = (data) => {
    console.log('🎯 OTP verified successfully:', data)
    console.log('🎯 Full response data:', JSON.stringify(data, null, 2))
    
    // Store the actual OTP value that was verified
    setVerifiedOtp(data.otp || '')
    setVerificationToken(data.verificationToken || '')
    setStep('reset')
  }

  const handleBackToEmail = () => {
    setStep('email')
  }

  const handleBackToOtp = () => {
    setStep('otp')
  }

  const onSubmit = async (data) => {
    console.log('🔥 Form submitted with data:', data)
    console.log('🔑 Verified OTP:', verifiedOtp)
    console.log('🎫 Verification Token:', verificationToken)
    console.log('📧 Email:', email)
    
    if (!verifiedOtp) {
      console.error('❌ No verified OTP found!')
      toast.error('OTP verification required. Please verify your OTP first')
      setStep('otp')
      return
    }
    
    setIsLoading(true)
    
    try {
      const payload = {
        email: email,
        password: data.password,
        confirmPassword: data.confirmPassword,
        otp: verifiedOtp
      }
      
      console.log('📤 Sending payload:', payload)
      
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const result = await response.json()
      console.log('📥 Response status:', response.status)
      console.log('📥 Response:', result)

      if (response.ok) {
        toast.success('🎉 Password reset successfully! You can now sign in with your new password', {
          duration: 5000
        })
        router.push('/auth/signin?message=password-reset-complete&email=' + encodeURIComponent(email))
      } else {
        console.error('❌ Reset failed:', result)
        toast.error(`Password reset failed. ${result.message || 'Something went wrong'}`)
        if (result.code === 'OTP_VERIFICATION_REQUIRED') {
          toast.error('OTP Expired. Please verify your OTP again')
          setStep('otp')
        }
      }
    } catch (error) {
      console.error('💥 Network error:', error)
      toast.error('Network error. Please check your connection and try again')
    } finally {
      setIsLoading(false)
    }
  }

  const handleButtonClick = () => {
    console.log('🔘 Reset Password button clicked!')
    console.log('🔑 Current verified OTP:', verifiedOtp)
    console.log('🎫 Current verification token:', verificationToken)
    console.log('📧 Current email:', email)
    console.log('⚡ Form errors:', errors)
    console.log('📝 Current step:', step)
  }

  // Step 1: Email verification
  if (step === 'email') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-white to-indigo-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <SendOTPForm 
            type="password_reset" 
            onOtpSent={handleOtpSent}
          />
          
          <div className="text-center space-y-2">
            <Link
              href="/auth/signin"
              className="inline-flex items-center text-sm text-indigo-600 hover:text-indigo-500 hover:bg-indigo-50 px-3 py-2 rounded-md transition-all duration-200"
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
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-white to-indigo-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <VerifyOTPForm 
            email={email}
            type="password_reset"
            onVerified={handleOtpVerified}
            onBack={handleBackToEmail}
          />
        </div>
      </div>
    )
  }

  // Step 3: Reset password
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-white to-indigo-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <Card className="w-full shadow-2xl border-0 bg-white/90 backdrop-blur-md ring-1 ring-slate-200/50">
          <CardHeader className="space-y-1 pb-8">
            <div className="flex items-center justify-center w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-amber-500 to-rose-600 rounded-full shadow-xl">
              <KeyRound className="w-8 h-8 text-white" />
            </div>
            <CardTitle className="text-3xl text-center font-bold bg-gradient-to-r from-amber-600 to-rose-600 bg-clip-text text-transparent">
              Reset Password
            </CardTitle>
            <CardDescription className="text-center text-lg text-slate-600">
              Create your new secure password
            </CardDescription>
          </CardHeader>
          
          <form onSubmit={handleSubmit(onSubmit)}>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="email-display" className="text-sm font-medium text-slate-700">
                  Email Address
                </label>
                <Input
                  id="email-display"
                  type="email"
                  value={email}
                  disabled
                  className="bg-slate-50 border-slate-200"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium text-slate-700">
                  New Password
                </label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Create a secure password"
                    disabled={isLoading}
                    className="pr-10 border-2 border-slate-200 focus:border-emerald-500 focus:ring-emerald-500/20 focus:ring-4 transition-all duration-200 rounded-xl"
                    {...register('password')}
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4 text-slate-400 hover:text-slate-600 transition-colors" />
                    ) : (
                      <Eye className="h-4 w-4 text-slate-400 hover:text-slate-600 transition-colors" />
                    )}
                  </button>
                </div>
                {errors.password && (
                  <p className="text-sm text-rose-600 font-medium">{errors.password.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <label htmlFor="confirmPassword" className="text-sm font-medium text-slate-700">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm your new password"
                    disabled={isLoading}
                    className="pr-10 border-2 border-slate-200 focus:border-emerald-500 focus:ring-emerald-500/20 focus:ring-4 transition-all duration-200 rounded-xl"
                    {...register('confirmPassword')}
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? (
                      <EyeOff className="h-4 w-4 text-slate-400 hover:text-slate-600 transition-colors" />
                    ) : (
                      <Eye className="h-4 w-4 text-slate-400 hover:text-slate-600 transition-colors" />
                    )}
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="text-sm text-rose-600 font-medium">{errors.confirmPassword.message}</p>
                )}
              </div>
            </CardContent>

            <div className="px-6 pb-6 space-y-4">
              <Button 
                type="submit" 
                className="w-full h-12 text-lg font-semibold bg-gradient-to-r from-amber-600 to-rose-600 hover:from-amber-700 hover:to-rose-700 text-white shadow-xl hover:shadow-2xl transition-all duration-200 transform hover:scale-[1.02] focus:ring-4 focus:ring-amber-500/20 rounded-xl" 
                disabled={isLoading}
                onClick={handleButtonClick}
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
                className="w-full h-12 border-2 border-slate-300 hover:border-slate-400 hover:bg-slate-50 text-slate-600 hover:text-slate-800 transition-all duration-200 rounded-xl" 
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
            className="inline-flex items-center text-sm text-indigo-600 hover:text-indigo-500 hover:bg-indigo-50 px-3 py-2 rounded-md transition-all duration-200"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Back to sign in
          </Link>
        </div>
      </div>
    </div>
  )
}
