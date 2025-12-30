// components/ui/MobileCard.js
'use client'

import { forwardRef } from 'react'
import { ChevronRight } from 'lucide-react'
import Link from 'next/link'

/**
 * Mobile-optimized card component
 * - Touch-friendly padding
 * - Tap feedback
 * - Optional link/click behavior
 * - Responsive variants
 */

const MobileCard = forwardRef(({
    children,
    title,
    subtitle,
    icon: Icon,
    action,
    actionLabel = 'View',
    href,
    onClick,
    variant = 'default',
    interactive = Boolean(href || onClick),
    className = '',
    ...props
}, ref) => {

    const baseStyles = `
    block w-full
    bg-white rounded-2xl shadow-sm
    border border-gray-200
    transition-all duration-200
    ${interactive
            ? 'touch-feedback active:scale-[0.98] hover:shadow-md hover:border-emerald-300 cursor-pointer'
            : ''
        }
  `

    const variants = {
        default: 'p-4 sm:p-5',
        compact: 'p-3 sm:p-4',
        spacious: 'p-5 sm:p-6',
        feature: `
      p-5 sm:p-6
      bg-gradient-to-br from-emerald-50 to-teal-50
      border-emerald-200
    `
    }

    const CardContent = () => (
        <>
            {/* Header Section */}
            {(title || Icon) && (
                <div className="flex items-start gap-3 mb-3">
                    {Icon && (
                        <div className="flex-shrink-0">
                            <div className="w-12 h-12 rounded-xl bg-emerald-100 flex items-center justify-center">
                                <Icon className="h-6 w-6 text-emerald-600" />
                            </div>
                        </div>
                    )}

                    <div className="flex-1 min-w-0">
                        {title && (
                            <h3 className="text-base sm:text-lg font-bold text-gray-900 leading-tight">
                                {title}
                            </h3>
                        )}
                        {subtitle && (
                            <p className="text-sm text-gray-500 mt-1">
                                {subtitle}
                            </p>
                        )}
                    </div>

                    {interactive && (
                        <ChevronRight className="h-5 w-5 text-gray-400 flex-shrink-0" />
                    )}
                </div>
            )}

            {/* Content */}
            <div className="mobile-card-content">
                {children}
            </div>

            {/* Action Footer */}
            {action && (
                <div className="mt-4 pt-4 border-t border-gray-100">
                    {action}
                </div>
            )}
        </>
    )

    const cardClasses = `
    ${baseStyles}
    ${variants[variant]}
    ${className}
  `

    // Render as Link if href provided
    if (href) {
        return (
            <Link
                ref={ref}
                href={href}
                className={cardClasses}
                {...props}
            >
                <CardContent />
            </Link>
        )
    }

    // Render as button if onClick provided
    if (onClick) {
        return (
            <button
                ref={ref}
                onClick={onClick}
                className={`${cardClasses} text-left`}
                {...props}
            >
                <CardContent />
            </button>
        )
    }

    // Render as div (non-interactive)
    return (
        <div
            ref={ref}
            className={cardClasses}
            {...props}
        >
            <CardContent />
        </div>
    )
})

MobileCard.displayName = 'MobileCard'

export default MobileCard


// Example Usage:
/*
import MobileCard from '@/components/ui/MobileCard'
import { Wallet, TrendingUp, Target, PieChart } from 'lucide-react'
import MobileButton from '@/components/ui/MobileButton'

// Basic card
<MobileCard title="Total Balance">
  <div className="text-3xl font-bold text-gray-900">₹45,280</div>
  <p className="text-sm text-green-600 mt-1">+12% from last month</p>
</MobileCard>

// Interactive card with link
<MobileCard
  title="Recent Expenses"
  subtitle="Last 7 days"
  icon={Wallet}
  href="/dashboard/expenses"
  interactive
>
  <div className="space-y-2">
    <div className="flex justify-between text-sm">
      <span>Food & Dining</span>
      <span className="font-semibold">₹2,450</span>
    </div>
    <div className="flex justify-between text-sm">
      <span>Transportation</span>
      <span className="font-semibold">₹1,200</span>
    </div>
  </div>
</MobileCard>

// Feature card (highlighted)
<MobileCard
  variant="feature"
  title="Savings Goal"
  subtitle="New Phone"
  icon={Target}
>
  <div className="space-y-3">
    <div className="flex justify-between items-center">
      <span className="text-sm text-gray-600">Progress</span>
      <span className="text-lg font-bold text-emerald-600">75%</span>
    </div>
    <div className="w-full bg-gray-200 rounded-full h-3">
      <div className="bg-gradient-to-r from-emerald-500 to-teal-500 h-3 rounded-full" style={{width: '75%'}}></div>
    </div>
    <div className="flex justify-between text-sm">
      <span className="text-gray-600">₹7,500 saved</span>
      <span className="text-gray-600">₹2,500 remaining</span>
    </div>
  </div>
</MobileCard>

// Card with action button
<MobileCard
  title="Budget Analysis"
  icon={PieChart}
  action={
    <MobileButton 
      variant="secondary" 
      size="sm" 
      fullWidth
    >
      View Details
    </MobileButton>
  }
>
  <p className="text-sm text-gray-600">
    You've spent 82% of your monthly budget. Consider reducing expenses in Food & Dining.
  </p>
</MobileCard>

// Compact card
<MobileCard variant="compact">
  <div className="flex items-center justify-between">
    <span className="text-sm font-medium">Monthly Income</span>
    <span className="text-lg font-bold text-green-600">₹50,000</span>
  </div>
</MobileCard>

// Spacious card
<MobileCard variant="spacious" title="Account Summary">
  <div className="space-y-4">
    <div className="flex justify-between">
      <span>Total Income</span>
      <span className="font-semibold">₹50,000</span>
    </div>
    <div className="flex justify-between">
      <span>Total Expenses</span>
      <span className="font-semibold">₹32,450</span>
    </div>
    <div className="flex justify-between pt-4 border-t">
      <span className="font-bold">Savings</span>
      <span className="font-bold text-green-600">₹17,550</span>
    </div>
  </div>
</MobileCard>

// Grid of cards
<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
  <MobileCard title="Card 1">Content</MobileCard>
  <MobileCard title="Card 2">Content</MobileCard>
  <MobileCard title="Card 3">Content</MobileCard>
</div>

// Horizontal scroll on mobile
<div className="mobile-scroll-x gap-4 pb-4 sm:grid sm:grid-cols-2">
  <MobileCard className="w-72 sm:w-auto" title="Card 1">Content</MobileCard>
  <MobileCard className="w-72 sm:w-auto" title="Card 2">Content</MobileCard>
  <MobileCard className="w-72 sm:w-auto" title="Card 3">Content</MobileCard>
</div>
*/
