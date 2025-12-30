'use client'

import { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { signIn } from 'next-auth/react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import SendOTPForm from '@/components/auth/SendOTPForm'
import VerifyOTPForm from '@/components/auth/VerifyOTPForm'
import { LogIn, Eye, EyeOff, Mail, KeyRound, ArrowLeft } from 'lucide-react'
import { toast } from 'sonner'
import Link from 'next/link'

const passwordLoginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional()
})

export default function SignInPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const callbackUrl = searchParams.get('callbackUrl') || '/dashboard'
  
  const [loginMethod, setLoginMethod] = useState('password') // 'password', 'otp-send', 'otp-verify'
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue
  } = useForm({
    resolver: zodResolver(passwordLoginSchema)
  })

  // Handle traditional password login
  const onPasswordLogin = async (data) => {
    setIsLoading(true)

    try {
      const result = await signIn('credentials', {
        email: data.email,
        password: data.password,
        redirect: false
      })

      if (result?.error) {
        toast.error('Sign in failed', {
          description: 'Invalid email or password'
        })
      } else {
        toast.success('Welcome back!', {
          description: 'You have been signed in successfully'
        })
        router.push(callbackUrl)
      }
    } catch (error) {
      toast.error('Network error', {
        description: 'Please check your connection and try again'
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Handle Google sign-in
  const handleGoogleSignIn = async () => {
    setIsLoading(true)
    try {
      await signIn('google', { callbackUrl })
    } catch (error) {
      toast.error('Google sign-in failed', {
        description: 'Please try again'
      })
      setIsLoading(false)
    }
  }

  // Handle OTP login flow
  const handleOtpSent = (sentEmail) => {
    setEmail(sentEmail)
    setLoginMethod('otp-verify')
  }

  const handleOtpVerified = (data) => {
    toast.success('Welcome back!', {
      description: 'You have been signed in successfully'
    })
    router.push(callbackUrl)
  }

  const handleBackToPassword = () => {
    setLoginMethod('password')
  }

  const handleBackToOtpSend = () => {
    setLoginMethod('otp-send')
  }

  // Password login form
  if (loginMethod === 'password') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <Card className="w-full">
            <CardHeader className="space-y-1">
              <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-blue-100 rounded-full">
                <LogIn className="w-6 h-6 text-blue-600" />
              </div>
              <CardTitle className="text-2xl text-center">Welcome back</CardTitle>
              <CardDescription className="text-center">
                Sign in to your account to continue
              </CardDescription>
            </CardHeader>
            
            <form onSubmit={handleSubmit(onPasswordLogin)}>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="email" className="text-sm font-medium">
                    Email Address
                  </label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="Enter your email"
                    autoComplete="email"
                    disabled={isLoading}
                    {...register('email')}
                  />
                  {errors.email && (
                    <p className="text-sm text-red-600">{errors.email.message}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <label htmlFor="password" className="text-sm font-medium">
                    Password
                  </label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="Enter your password"
                      autoComplete="current-password"
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

                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <input
                      id="rememberMe"
                      type="checkbox"
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                      {...register('rememberMe')}
                    />
                    <label htmlFor="rememberMe" className="ml-2 block text-sm text-gray-900">
                      Remember me
                    </label>
                  </div>
                  <Link
                    href="/auth/forgot-password"
                    className="text-sm text-blue-600 hover:text-blue-500"
                  >
                    Forgot password?
                  </Link>
                </div>
              </CardContent>

              <div className="px-6 pb-6 space-y-3">
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isLoading}
                >
                  {isLoading ? 'Signing in...' : 'Sign in'}
                </Button>
                
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-white px-2 text-muted-foreground">Or continue with</span>
                  </div>
                </div>
                
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={handleGoogleSignIn}
                  disabled={isLoading}
                >
                  <svg className="w-4 h-4 mr-2" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  Continue with Google
                </Button>

                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={() => setLoginMethod('otp-send')}
                  disabled={isLoading}
                >
                  <Mail className="w-4 h-4 mr-2" />
                  Sign in with OTP
                </Button>
              </div>
            </form>
          </Card>
          
          <div className="text-center">
            <p className="text-sm text-gray-600">
              Don&apos;t have an account?{' '}
              <Link href="/auth/signup" className="font-medium text-blue-600 hover:text-blue-500">
                Sign up
              </Link>
            </p>
          </div>
        </div>
      </div>
    )
  }

  // OTP send form
  if (loginMethod === 'otp-send') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <SendOTPForm 
            type="login" 
            onOtpSent={handleOtpSent}
          />
          
          <div className="text-center space-y-2">
            <Button
              variant="ghost"  
              onClick={handleBackToPassword}
              className="text-blue-600 hover:text-blue-500"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back to password login
            </Button>
            
            <p className="text-sm text-gray-600">
              Don&apos;t have an account?{' '}
              <Link href="/auth/signup" className="font-medium text-blue-600 hover:text-blue-500">
                Sign up
              </Link>
            </p>
          </div>
        </div>
      </div>
    )
  }

  // OTP verification form
  if (loginMethod === 'otp-verify') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <VerifyOTPForm 
            email={email}
            type="login"
            onVerified={handleOtpVerified}
            onBack={handleBackToOtpSend}
          />
        </div>
      </div>
    )
  }

  return null
}
