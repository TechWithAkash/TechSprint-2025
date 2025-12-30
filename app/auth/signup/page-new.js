'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import SendOTPForm from '@/components/auth/SendOTPForm'
import VerifyOTPForm from '@/components/auth/VerifyOTPForm'
import { UserPlus, Eye, EyeOff } from 'lucide-react'
import { toast } from 'sonner'
import Link from 'next/link'

const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(50, 'Name must be less than 50 characters'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password must be less than 128 characters'),
  confirmPassword: z.string(),
  otp: z.string().length(6, 'OTP must be exactly 6 digits').regex(/^\d{6}$/, 'OTP must contain only numbers')
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

export default function SignUpPage() {
  const [step, setStep] = useState('email') // 'email', 'otp', 'register'
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const router = useRouter()
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    watch
  } = useForm({
    resolver: zodResolver(registerSchema)
  })

  const handleOtpSent = (sentEmail) => {
    setEmail(sentEmail)
    setValue('email', sentEmail)
    setStep('otp')
  }

  const handleOtpVerified = (data) => {
    setStep('register')
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
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: data.name,
          email: data.email,
          password: data.password,
          otp: data.otp
        })
      })

      const result = await response.json()

      if (response.ok) {
        toast.success('Account created successfully!', {
          description: result.message
        })
        router.push('/auth/signin?message=registration-complete')
      } else {
        toast.error('Registration failed', {
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
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <SendOTPForm 
            type="registration" 
            onOtpSent={handleOtpSent}
          />
          
          <div className="text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <Link href="/auth/signin" className="font-medium text-blue-600 hover:text-blue-500">
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </div>
    )
  }

  // Step 2: OTP verification
  if (step === 'otp') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <VerifyOTPForm 
            email={email}
            type="registration"
            onVerified={handleOtpVerified}
            onBack={handleBackToEmail}
          />
        </div>
      </div>
    )
  }

  // Step 3: Complete registration
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <Card className="w-full">
          <CardHeader className="space-y-1">
            <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-blue-100 rounded-full">
              <UserPlus className="w-6 h-6 text-blue-600" />
            </div>
            <CardTitle className="text-2xl text-center">Complete Registration</CardTitle>
            <CardDescription className="text-center">
              Email verified! Now create your account
            </CardDescription>
          </CardHeader>
          
          <form onSubmit={handleSubmit(onSubmit)}>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="name" className="text-sm font-medium">
                  Full Name
                </label>
                <Input
                  id="name"
                  type="text"
                  placeholder="Enter your full name"
                  disabled={isLoading}
                  {...register('name')}
                />
                {errors.name && (
                  <p className="text-sm text-red-600">{errors.name.message}</p>
                )}
              </div>

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
                <input type="hidden" {...register('email')} value={email} />
              </div>

              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium">
                  Password
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
                  Confirm Password
                </label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm your password"
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

            <div className="px-6 pb-6 space-y-3">
              <Button 
                type="submit" 
                className="w-full" 
                disabled={isLoading}
              >
                {isLoading ? 'Creating Account...' : 'Create Account'}
              </Button>
              
              <Button 
                type="button"
                variant="outline" 
                className="w-full" 
                onClick={handleBackToOtp}
                disabled={isLoading}
              >
                Back to OTP Verification
              </Button>
            </div>
          </form>
        </Card>
        
        <div className="text-center">
          <p className="text-sm text-gray-600">
            Already have an account?{' '}
            <Link href="/auth/signin" className="font-medium text-blue-600 hover:text-blue-500">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
