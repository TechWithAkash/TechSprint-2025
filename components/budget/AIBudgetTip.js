'use client'

import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import {
    Sparkles,
    Info,
    X,
    TrendingUp,
    Shield,
    Edit3
} from 'lucide-react'
import { Button } from '@/components/ui/button'

export default function AIBudgetTip({ onCustomize }) {
    const [isExpanded, setIsExpanded] = useState(true)
    const [isDismissed, setIsDismissed] = useState(false)

    if (isDismissed) {
        return null
    }

    return (
        <Card className="border-0 bg-gradient-to-br from-violet-50 via-purple-50 to-fuchsia-50 shadow-lg overflow-hidden relative">
            {/* Decorative background pattern */}
            <div className="absolute inset-0 opacity-[0.03]">
                <svg className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                            <circle cx="10" cy="10" r="1" fill="currentColor" />
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#grid)" />
                </svg>
            </div>

            <CardContent className="p-6 relative">
                {/* Close button */}
                <button
                    onClick={() => setIsDismissed(true)}
                    className="absolute top-4 right-4 text-purple-400 hover:text-purple-600 transition-colors"
                    aria-label="Dismiss tip"
                >
                    <X className="h-4 w-4" />
                </button>

                {/* Header with icon */}
                <div className="flex items-start gap-4 mb-4">
                    <div className="flex-shrink-0">
                        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-violet-500 via-purple-500 to-fuchsia-500 flex items-center justify-center shadow-lg">
                            <Sparkles className="h-6 w-6 text-white" />
                        </div>
                    </div>

                    <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                            <h3 className="text-lg font-bold text-purple-900">
                                AI Budget Tip
                            </h3>
                            <span className="px-2 py-0.5 text-xs font-semibold bg-purple-100 text-purple-700 rounded-full">
                                Smart
                            </span>
                        </div>
                        <p className="text-sm text-purple-700 leading-relaxed">
                            Your budget was intelligently generated using the <span className="font-semibold">50-30-20 Rule</span> to help you manage finances smarter.
                        </p>
                    </div>
                </div>

                {/* Expandable content */}
                {isExpanded && (
                    <div className="space-y-4 mt-6 animate-fade-in">
                        {/* Info cards */}
                        <div className="grid gap-3">
                            {/* 50-30-20 Rule Explanation */}
                            <div className="flex items-start gap-3 p-4 bg-white/60 backdrop-blur-sm rounded-xl border border-purple-100">
                                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-violet-100 flex items-center justify-center">
                                    <TrendingUp className="h-4 w-4 text-violet-600" />
                                </div>
                                <div className="flex-1">
                                    <h4 className="font-semibold text-purple-900 text-sm mb-1">
                                        What&apos;s the 50-30-20 Rule?
                                    </h4>
                                    <p className="text-xs text-purple-700 leading-relaxed">
                                        <span className="font-medium">50%</span> for needs • <span className="font-medium">30%</span> for wants • <span className="font-medium">20%</span> for savings & goals
                                    </p>
                                </div>
                            </div>

                            {/* Customization tip */}
                            <div className="flex items-start gap-3 p-4 bg-white/60 backdrop-blur-sm rounded-xl border border-purple-100">
                                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-fuchsia-100 flex items-center justify-center">
                                    <Edit3 className="h-4 w-4 text-fuchsia-600" />
                                </div>
                                <div className="flex-1">
                                    <h4 className="font-semibold text-purple-900 text-sm mb-1">
                                        Customize Anytime
                                    </h4>
                                    <p className="text-xs text-purple-700 leading-relaxed">
                                        Every financial situation is unique. Feel free to adjust allocations to better match your goals and lifestyle.
                                    </p>
                                </div>
                            </div>

                            {/* Disclaimer */}
                            <div className="flex items-start gap-3 p-4 bg-amber-50/80 backdrop-blur-sm rounded-xl border border-amber-100">
                                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-amber-100 flex items-center justify-center">
                                    <Shield className="h-4 w-4 text-amber-600" />
                                </div>
                                <div className="flex-1">
                                    <h4 className="font-semibold text-amber-900 text-sm mb-1">
                                        Review & Adjust
                                    </h4>
                                    <p className="text-xs text-amber-700 leading-relaxed">
                                        AI suggestions are starting points, not perfect solutions. Please review and adjust allocations before finalizing.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Action buttons */}
                        {onCustomize && (
                            <div className="flex gap-2 pt-2">
                                <Button
                                    onClick={onCustomize}
                                    className="flex-1 bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-700 hover:to-fuchsia-700 text-white shadow-md"
                                >
                                    <Edit3 className="h-4 w-4 mr-2" />
                                    Customize Budget
                                </Button>
                                <Button
                                    onClick={() => setIsExpanded(false)}
                                    variant="outline"
                                    className="border-purple-200 text-purple-700 hover:bg-purple-50"
                                >
                                    Got it
                                </Button>
                            </div>
                        )}
                    </div>
                )}

                {/* Toggle button when collapsed */}
                {!isExpanded && (
                    <button
                        onClick={() => setIsExpanded(true)}
                        className="flex items-center gap-2 text-sm font-medium text-purple-700 hover:text-purple-900 transition-colors mt-2"
                    >
                        <Info className="h-4 w-4" />
                        Learn more about your AI budget
                    </button>
                )}
            </CardContent>
        </Card>
    )
}
