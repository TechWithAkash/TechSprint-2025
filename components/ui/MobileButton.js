// components/ui/MobileButton.js
'use client'

import { forwardRef } from 'react'
import { Loader2 } from 'lucide-react'

/**
 * Mobile-optimized button component
 * - Minimum 44px tap target
 * - Touch feedback
 * - Loading states
 * - Haptic feedback
 * - Accessible
 */

const MobileButton = forwardRef(({
    children,
    variant = 'primary',
    size = 'default',
    fullWidth = false,
    loading = false,
    disabled = false,
    icon: Icon,
    iconPosition = 'left',
    className = '',
    onClick,
    ...props
}, ref) => {

    const baseStyles = `
    tap-target touch-feedback no-select
    inline-flex items-center justify-center
    font-semibold rounded-xl
    transition-all duration-200
    focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed
    active:scale-[0.98]
    ${fullWidth ? 'w-full' : ''}
  `

    const variants = {
        primary: `
      bg-gradient-to-r from-emerald-600 to-teal-600
      text-white shadow-lg shadow-emerald-500/30
      hover:shadow-xl hover:shadow-emerald-500/40
      active:shadow-md
    `,
        secondary: `
      bg-white border-2 border-emerald-600
      text-emerald-600
      hover:bg-emerald-50
      active:bg-emerald-100
    `,
        outline: `
      bg-transparent border-2 border-gray-300
      text-gray-700
      hover:border-emerald-500 hover:text-emerald-600 hover:bg-emerald-50
      active:bg-emerald-100
    `,
        ghost: `
      bg-transparent
      text-gray-700
      hover:bg-gray-100
      active:bg-gray-200
    `,
        danger: `
      bg-gradient-to-r from-red-600 to-rose-600
      text-white shadow-lg shadow-red-500/30
      hover:shadow-xl hover:shadow-red-500/40
      active:shadow-md
    `,
        success: `
      bg-gradient-to-r from-green-600 to-emerald-600
      text-white shadow-lg shadow-green-500/30
      hover:shadow-xl hover:shadow-green-500/40
      active:shadow-md
    `
    }

    const sizes = {
        sm: 'px-3 py-2 text-sm min-h-[40px]',
        default: 'px-4 py-3 text-base min-h-[44px]',
        lg: 'px-6 py-4 text-lg min-h-[52px] tap-target-lg',
        xl: 'px-8 py-5 text-xl min-h-[60px] tap-target-lg'
    }

    const handleClick = (e) => {
        if (disabled || loading) return

        // Haptic feedback on mobile
        if (navigator.vibrate) {
            navigator.vibrate(10)
        }

        onClick?.(e)
    }

    return (
        <button
            ref={ref}
            disabled={disabled || loading}
            onClick={handleClick}
            className={`
        ${baseStyles}
        ${variants[variant]}
        ${sizes[size]}
        ${className}
      `}
            {...props}
        >
            {loading && (
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
            )}

            {!loading && Icon && iconPosition === 'left' && (
                <Icon className="h-5 w-5 mr-2 flex-shrink-0" />
            )}

            <span className="flex-1">{children}</span>

            {!loading && Icon && iconPosition === 'right' && (
                <Icon className="h-5 w-5 ml-2 flex-shrink-0" />
            )}
        </button>
    )
})

MobileButton.displayName = 'MobileButton'

export default MobileButton


// Example Usage:
/*
import MobileButton from '@/components/ui/MobileButton'
import { ArrowRight, Plus, Check } from 'lucide-react'

// Primary button
<MobileButton variant="primary" size="lg" fullWidth>
  Continue
</MobileButton>

// With icon
<MobileButton 
  variant="secondary" 
  icon={Plus}
  iconPosition="left"
>
  Add Expense
</MobileButton>

// Loading state
<MobileButton 
  variant="primary" 
  loading={isLoading}
  disabled={isLoading}
>
  Processing...
</MobileButton>

// Danger action
<MobileButton 
  variant="danger"
  onClick={handleDelete}
>
  Delete Account
</MobileButton>

// Success action
<MobileButton 
  variant="success"
  icon={Check}
  iconPosition="right"
>
  Confirm
</MobileButton>
*/
