// components/ui/MobileInput.js
'use client'

import { forwardRef, useState } from 'react'
import { Eye, EyeOff, AlertCircle, Check } from 'lucide-react'

/**
 * Mobile-optimized input component
 * - 16px font size to prevent iOS zoom
 * - Touch-friendly design
 * - Built-in validation states
 * - Optional icon support
 * - Password toggle
 */

const MobileInput = forwardRef(({
    type = 'text',
    label,
    placeholder,
    error,
    success,
    helpText,
    icon: Icon,
    value,
    onChange,
    className = '',
    inputClassName = '',
    disabled = false,
    required = false,
    ...props
}, ref) => {
    const [showPassword, setShowPassword] = useState(false)
    const [isFocused, setIsFocused] = useState(false)

    const isPassword = type === 'password'
    const inputType = isPassword && showPassword ? 'text' : type

    const hasError = Boolean(error)
    const hasSuccess = Boolean(success)

    return (
        <div className={`w-full ${className}`}>
            {/* Label */}
            {label && (
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                    {label}
                    {required && <span className="text-red-500 ml-1">*</span>}
                </label>
            )}

            {/* Input Container */}
            <div className="relative">
                {/* Left Icon */}
                {Icon && (
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none">
                        <Icon className="h-5 w-5" />
                    </div>
                )}

                {/* Input Field */}
                <input
                    ref={ref}
                    type={inputType}
                    value={value}
                    onChange={onChange}
                    disabled={disabled}
                    placeholder={placeholder}
                    onFocus={() => setIsFocused(true)}
                    onBlur={() => setIsFocused(false)}
                    className={`
            w-full px-4 py-3 text-base
            bg-white border-2 rounded-xl
            transition-all duration-200
            placeholder:text-gray-400
            disabled:bg-gray-100 disabled:cursor-not-allowed disabled:text-gray-500
            focus:outline-none
            ${Icon ? 'pl-12' : 'pl-4'}
            ${isPassword ? 'pr-12' : 'pr-4'}
            ${hasError
                            ? 'border-red-500 focus:border-red-600 focus:ring-4 focus:ring-red-100'
                            : hasSuccess
                                ? 'border-green-500 focus:border-green-600 focus:ring-4 focus:ring-green-100'
                                : 'border-gray-300 focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100'
                        }
            ${isFocused && !hasError && !hasSuccess ? 'shadow-lg' : 'shadow-sm'}
            ${inputClassName}
          `}
                    {...props}
                />

                {/* Password Toggle */}
                {isPassword && (
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="tap-target absolute right-2 top-1/2 -translate-y-1/2 p-2 text-gray-400 hover:text-gray-600 rounded-lg transition-colors"
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                        {showPassword ? (
                            <EyeOff className="h-5 w-5" />
                        ) : (
                            <Eye className="h-5 w-5" />
                        )}
                    </button>
                )}

                {/* Validation Icons */}
                {!isPassword && (hasError || hasSuccess) && (
                    <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none">
                        {hasError && <AlertCircle className="h-5 w-5 text-red-500" />}
                        {hasSuccess && <Check className="h-5 w-5 text-green-500" />}
                    </div>
                )}
            </div>

            {/* Error Message */}
            {hasError && (
                <p className="mt-2 text-sm font-medium text-red-600 flex items-center gap-1">
                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    {error}
                </p>
            )}

            {/* Success Message */}
            {hasSuccess && (
                <p className="mt-2 text-sm font-medium text-green-600 flex items-center gap-1">
                    <Check className="h-4 w-4 flex-shrink-0" />
                    {success}
                </p>
            )}

            {/* Help Text */}
            {helpText && !hasError && !hasSuccess && (
                <p className="mt-2 text-sm text-gray-500">
                    {helpText}
                </p>
            )}
        </div>
    )
})

MobileInput.displayName = 'MobileInput'

export default MobileInput


// Example Usage:
/*
import MobileInput from '@/components/ui/MobileInput'
import { Mail, Lock, User, Phone, DollarSign } from 'lucide-react'

// Basic input
<MobileInput
  label="Email Address"
  type="email"
  placeholder="your@email.com"
  icon={Mail}
  required
/>

// With validation error
<MobileInput
  label="Password"
  type="password"
  placeholder="Enter password"
  icon={Lock}
  error="Password must be at least 8 characters"
/>

// With success state
<MobileInput
  label="Username"
  type="text"
  placeholder="Choose a username"
  icon={User}
  success="Username is available!"
/>

// Number input for amounts
<MobileInput
  label="Amount"
  type="number"
  placeholder="0.00"
  icon={DollarSign}
  inputMode="decimal"
  helpText="Enter the transaction amount"
/>

// Phone input
<MobileInput
  label="Phone Number"
  type="tel"
  placeholder="+1 (555) 000-0000"
  icon={Phone}
  inputMode="tel"
/>

// Disabled input
<MobileInput
  label="Account ID"
  type="text"
  value="ACC-12345"
  disabled
/>
*/
