'use client'

import { useState, useRef, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, ArrowLeft } from 'lucide-react'
import toast from 'react-hot-toast'

export default function VerifyOTPForm({ email, type = 'registration', onVerified, onBack }) {
  const [otp, setOtp] = useState(['', '', '', '', '', ''])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const inputRefs = useRef([])

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus()
  }, [])

  const handleInputChange = (index, value) => {
    if (!/^\d*$/.test(value)) return // Only allow digits
    
    const newOtp = [...otp]
    newOtp[index] = value.slice(-1) // Only take the last digit
    setOtp(newOtp)
    setError('')

    // Auto-focus next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  const handlePaste = (e) => {
    e.preventDefault()
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    const newOtp = [...otp]
    
    for (let i = 0; i < 6; i++) {
      newOtp[i] = pastedData[i] || ''
    }
    
    setOtp(newOtp)
    setError('')
    
    // Focus the next empty input or the last input
    const nextEmptyIndex = newOtp.findIndex(digit => !digit)
    const focusIndex = nextEmptyIndex === -1 ? 5 : nextEmptyIndex
    inputRefs.current[focusIndex]?.focus()
  }

  const getTypeText = () => {
    switch (type) {
      case 'registration': return { title: 'Verify Your Email', desc: 'Enter the 6-digit code sent to your email' }
      case 'login': return { title: 'Verify Login', desc: 'Enter the 6-digit code to complete login' }
      case 'password_reset': return { title: 'Verify Reset Code', desc: 'Enter the 6-digit code to reset your password' }
      default: return { title: 'Verify OTP', desc: 'Enter the 6-digit verification code' }
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const otpValue = otp.join('')
    
    if (otpValue.length !== 6) {
      setError('Please enter all 6 digits')
      return
    }

    setIsLoading(true)
    setError('')

    try {
      const response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp: otpValue, type })
      })

      const result = await response.json()

      if (response.ok) {
        toast.success(`OTP verified successfully! ${result.message}`)
        // Pass both the API response data and the OTP value that was verified
        onVerified?.({
          ...result.data,
          otp: otpValue // Include the actual OTP that was verified
        })
      } else {
        setError(result.message)
        if (result.attemptsRemaining !== undefined) {
          setError(`${result.message}. ${result.attemptsRemaining} attempts remaining.`)
        }
        
        // Clear OTP on error
        setOtp(['', '', '', '', '', ''])
        inputRefs.current[0]?.focus()
      }
    } catch (error) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const typeText = getTypeText()

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-green-100 rounded-full">
          <Shield className="w-6 h-6 text-green-600" />
        </div>
        <CardTitle className="text-2xl text-center">{typeText.title}</CardTitle>
        <CardDescription className="text-center">
          {typeText.desc}
          <br />
          <span className="font-medium text-gray-900">{email}</span>
        </CardDescription>
      </CardHeader>
      
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-6">
          <div className="flex justify-center space-x-2">
            {otp.map((digit, index) => (
              <input
                key={index}
                ref={el => inputRefs.current[index] = el}
                type="text"
                inputMode="numeric"
                maxLength={1}
                value={digit}
                onChange={(e) => handleInputChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                onPaste={handlePaste}
                className="w-12 h-12 text-center text-xl font-semibold border border-gray-300 rounded-md focus:border-blue-500 focus:ring-2 focus:ring-blue-200 focus:outline-none transition-colors"
                disabled={isLoading}
              />
            ))}
          </div>
          
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-md">
              <p className="text-sm text-red-600 text-center">{error}</p>
            </div>
          )}
          
          <div className="text-center text-sm text-gray-600">
            <p>Didn&apos;t receive the code?</p>
            <button
              type="button"
              onClick={onBack}
              className="text-blue-600 hover:text-blue-500 font-medium"
              disabled={isLoading}
            >
              Try a different email
            </button>
          </div>
        </CardContent>

        <div className="px-6 pb-6 space-y-3">
          <Button 
            type="submit" 
            className="w-full" 
            disabled={isLoading || otp.join('').length !== 6}
          >
            {isLoading ? 'Verifying...' : 'Verify OTP'}
          </Button>
          
          <Button 
            type="button"
            variant="outline" 
            className="w-full" 
            onClick={onBack}
            disabled={isLoading}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
        </div>
      </form>
    </Card>
  )
}
