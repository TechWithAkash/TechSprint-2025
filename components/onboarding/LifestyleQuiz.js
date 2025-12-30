'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import {
    ChevronRight,
    ChevronLeft,
    Sparkles,
    Home,
    Utensils,
    ShoppingBag,
    Film,
    Heart,
    GraduationCap,
    Target,
    TrendingUp,
    CheckCircle,
    Info,
    Award
} from 'lucide-react'

// Quiz questions organized by category (20 questions total)
const QUIZ_CATEGORIES = [
    {
        id: 'basic',
        title: 'Basic Financial Profile',
        icon: TrendingUp,
        color: 'blue',
        questions: [
            {
                id: 'additional_income',
                question: 'Do you have any additional income sources?',
                emoji: '➕',
                type: 'single',
                options: [
                    { value: 'none', label: 'None' },
                    { value: 'freelance', label: 'Freelance / Side gigs' },
                    { value: 'rent', label: 'Rent or Property Income' },
                    { value: 'investment', label: 'Investment Returns / Dividends' },
                    { value: 'business', label: 'Family Business Income' }
                ]
            },
            {
                id: 'dependents',
                question: 'How many dependents do you support financially?',
                emoji: '👨‍👩‍👧',
                type: 'single',
                options: [
                    { value: '0', label: '0' },
                    { value: '1', label: '1' },
                    { value: '2', label: '2' },
                    { value: '3+', label: '3 or more' }
                ]
            },
            {
                id: 'living_situation',
                question: 'Living situation',
                emoji: '🏠',
                type: 'single',
                options: [
                    { value: 'family', label: 'Living with family (no rent)' },
                    { value: 'renting_alone', label: 'Renting alone' },
                    { value: 'sharing', label: 'Sharing rent with roommates' },
                    { value: 'emi', label: 'Paying home loan EMI' }
                ]
            }
        ]
    },
    {
        id: 'home',
        title: 'Home & Utilities',
        icon: Home,
        color: 'emerald',
        questions: [
            {
                id: 'rent_emi',
                question: 'What is your monthly rent or EMI?',
                emoji: '💡',
                type: 'single',
                options: [
                    { value: '0-10k', label: '₹0 – ₹10,000' },
                    { value: '10k-20k', label: '₹10,001 – ₹20,000' },
                    { value: '20k-30k', label: '₹20,001 – ₹30,000' },
                    { value: '30k-50k', label: '₹30,001 – ₹50,000' },
                    { value: '50k+', label: '₹50,000+' }
                ]
            },
            {
                id: 'utilities',
                question: 'Monthly cost for utilities (electricity, water, internet, etc.)',
                emoji: '🔌',
                type: 'single',
                options: [
                    { value: '0-2k', label: '₹0 – ₹2,000' },
                    { value: '2k-5k', label: '₹2,001 – ₹5,000' },
                    { value: '5k-8k', label: '₹5,001 – ₹8,000' },
                    { value: '8k+', label: '₹8,001+' }
                ]
            },
            {
                id: 'vehicle',
                question: 'Do you own a vehicle?',
                emoji: '🚗',
                type: 'single',
                options: [
                    { value: 'no', label: 'No' },
                    { value: '2wheeler', label: 'Yes, 2-wheeler' },
                    { value: '4wheeler', label: 'Yes, 4-wheeler' },
                    { value: 'both', label: 'Yes, both' }
                ]
            }
        ]
    },
    {
        id: 'food',
        title: 'Food & Dining',
        icon: Utensils,
        color: 'orange',
        questions: [
            {
                id: 'eating_out',
                question: 'How often do you eat out or order food online?',
                emoji: '🍽',
                type: 'single',
                options: [
                    { value: 'rarely', label: 'Rarely (1–2 times/month)' },
                    { value: 'sometimes', label: 'Sometimes (1–2 times/week)' },
                    { value: 'frequently', label: 'Frequently (3–5 times/week)' },
                    { value: 'daily', label: 'Almost daily' }
                ]
            },
            {
                id: 'groceries',
                question: 'Monthly grocery spending',
                emoji: '🛒',
                type: 'single',
                options: [
                    { value: '0-3k', label: '₹0 – ₹3,000' },
                    { value: '3k-6k', label: '₹3,001 – ₹6,000' },
                    { value: '6k-10k', label: '₹6,001 – ₹10,000' },
                    { value: '10k-15k', label: '₹10,001 – ₹15,000' },
                    { value: '15k+', label: '₹15,000+' }
                ]
            },
            {
                id: 'meal_preference',
                question: 'Meal preference',
                emoji: '👩‍🍳',
                type: 'single',
                options: [
                    { value: 'home_cooked', label: 'Mostly home-cooked' },
                    { value: 'mixed', label: 'Mixed (home + outside)' },
                    { value: 'outside', label: 'Mostly outside food' }
                ]
            }
        ]
    },
    {
        id: 'shopping',
        title: 'Shopping & Personal Care',
        icon: ShoppingBag,
        color: 'purple',
        questions: [
            {
                id: 'shopping_frequency',
                question: 'Shopping frequency (clothes, gadgets, etc.)',
                emoji: '🧢',
                type: 'single',
                options: [
                    { value: 'rarely', label: 'Rarely (once every few months)' },
                    { value: 'monthly', label: 'Monthly' },
                    { value: 'weekly', label: 'Weekly' }
                ]
            },
            {
                id: 'shopping_budget',
                question: 'Average monthly shopping budget',
                emoji: '💳',
                type: 'single',
                options: [
                    { value: '0-2k', label: '₹0 – ₹2,000' },
                    { value: '2k-5k', label: '₹2,001 – ₹5,000' },
                    { value: '5k-10k', label: '₹5,001 – ₹10,000' },
                    { value: '10k+', label: '₹10,001+' }
                ]
            },
            {
                id: 'personal_care',
                question: 'Spending on personal care or grooming',
                emoji: '🧴',
                type: 'single',
                options: [
                    { value: 'minimal', label: 'Minimal (< ₹1,000)' },
                    { value: 'moderate', label: 'Moderate (₹1,000 – ₹3,000)' },
                    { value: 'high', label: 'High (₹3,001 – ₹6,000)' },
                    { value: 'very_high', label: 'Very high (₹6,000+)' }
                ]
            }
        ]
    },
    {
        id: 'entertainment',
        title: 'Entertainment & Subscriptions',
        icon: Film,
        color: 'pink',
        questions: [
            {
                id: 'subscriptions',
                question: 'Do you have active entertainment subscriptions?',
                emoji: '📺',
                type: 'single',
                options: [
                    { value: 'none', label: 'None' },
                    { value: '1-2', label: '1–2 (Netflix, Spotify, etc.)' },
                    { value: '3-5', label: '3–5' },
                    { value: '5+', label: '5+' }
                ]
            },
            {
                id: 'entertainment_spend',
                question: 'Monthly spend on movies, hobbies, or outings',
                emoji: '🎭',
                type: 'single',
                options: [
                    { value: '0-1k', label: '₹0 – ₹1,000' },
                    { value: '1k-3k', label: '₹1,001 – ₹3,000' },
                    { value: '3k-6k', label: '₹3,001 – ₹6,000' },
                    { value: '6k+', label: '₹6,001+' }
                ]
            },
            {
                id: 'travel',
                question: 'How often do you travel or go on weekend trips?',
                emoji: '✈',
                type: 'single',
                options: [
                    { value: 'rarely', label: 'Rarely (once a year)' },
                    { value: 'occasionally', label: 'Occasionally (2–3 times a year)' },
                    { value: 'regularly', label: 'Regularly (monthly or quarterly)' }
                ]
            }
        ]
    },
    {
        id: 'health',
        title: 'Health & Insurance',
        icon: Heart,
        color: 'red',
        questions: [
            {
                id: 'health_insurance',
                question: 'Do you have health insurance?',
                emoji: '🩺',
                type: 'single',
                options: [
                    { value: 'no', label: 'No' },
                    { value: 'individual', label: 'Yes – individual policy' },
                    { value: 'family', label: 'Yes – family policy' }
                ]
            },
            {
                id: 'fitness_spend',
                question: 'Monthly fitness or health spending',
                emoji: '💪',
                type: 'single',
                options: [
                    { value: '0-1k', label: '₹0 – ₹1,000' },
                    { value: '1k-3k', label: '₹1,001 – ₹3,000' },
                    { value: '3k-5k', label: '₹3,001 – ₹5,000' },
                    { value: '5k+', label: '₹5,000+' }
                ]
            }
        ]
    },
    {
        id: 'education',
        title: 'Education & Self-Improvement',
        icon: GraduationCap,
        color: 'indigo',
        questions: [
            {
                id: 'learning_invest',
                question: 'Do you invest in online courses, books, or learning?',
                emoji: '📚',
                type: 'single',
                options: [
                    { value: 'no', label: 'No' },
                    { value: 'occasionally', label: 'Occasionally' },
                    { value: 'regularly', label: 'Regularly' }
                ]
            },
            {
                id: 'learning_spend',
                question: 'Monthly spend on learning/self-improvement',
                emoji: '🧠',
                type: 'single',
                options: [
                    { value: '0-1k', label: '₹0 – ₹1,000' },
                    { value: '1k-3k', label: '₹1,001 – ₹3,000' },
                    { value: '3k-5k', label: '₹3,001 – ₹5,000' },
                    { value: '5k+', label: '₹5,000+' }
                ]
            }
        ]
    },
    {
        id: 'goals',
        title: 'Goals & Priorities',
        icon: Target,
        color: 'teal',
        questions: [
            {
                id: 'financial_goal',
                question: 'Main financial goal right now',
                emoji: '🎯',
                type: 'single',
                options: [
                    { value: 'savings', label: 'Build savings' },
                    { value: 'debt', label: 'Repay debt' },
                    { value: 'travel', label: 'Save for travel' },
                    { value: 'house', label: 'Buy a house' },
                    { value: 'investment', label: 'Increase investments' }
                ]
            },
            {
                id: 'money_mindset',
                question: 'Money mindset',
                emoji: '⚖',
                type: 'single',
                options: [
                    { value: 'save_first', label: 'Save-first (prefer saving over spending)' },
                    { value: 'balanced', label: 'Balanced (moderate spend and save)' },
                    { value: 'spend_first', label: 'Spend-first (enjoy now, save later)' }
                ]
            },
            {
                id: 'upcoming_expenses',
                question: 'Any major upcoming expenses?',
                emoji: '🧳',
                type: 'single',
                options: [
                    { value: 'none', label: 'None' },
                    { value: 'travel', label: 'Travel' },
                    { value: 'wedding', label: 'Wedding or event' },
                    { value: 'gadget', label: 'Gadget or vehicle purchase' },
                    { value: 'renovation', label: 'Home renovation' }
                ]
            }
        ]
    }
]

// Flatten all questions for progress tracking
const ALL_QUESTIONS = QUIZ_CATEGORIES.flatMap(cat =>
    cat.questions.map(q => ({ ...q, category: cat.id, categoryTitle: cat.title }))
)

export default function LifestyleQuiz({ onComplete, onSkip, initialAnswers = {} }) {
    const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0)
    const [answers, setAnswers] = useState(initialAnswers)
    const [isCompleting, setIsCompleting] = useState(false)

    const currentQuestion = ALL_QUESTIONS[currentQuestionIndex]
    const progress = ((currentQuestionIndex + 1) / ALL_QUESTIONS.length) * 100
    const isLastQuestion = currentQuestionIndex === ALL_QUESTIONS.length - 1
    const answeredCount = Object.keys(answers).length

    const handleAnswer = (value) => {
        const newAnswers = {
            ...answers,
            [currentQuestion.id]: value
        }
        setAnswers(newAnswers)

        // Auto-advance to next question after a brief delay
        setTimeout(() => {
            if (!isLastQuestion) {
                setCurrentQuestionIndex(currentQuestionIndex + 1)
            }
        }, 300)
    }

    const handlePrevious = () => {
        if (currentQuestionIndex > 0) {
            setCurrentQuestionIndex(currentQuestionIndex - 1)
        }
    }

    const handleNext = () => {
        if (currentQuestionIndex < ALL_QUESTIONS.length - 1) {
            setCurrentQuestionIndex(currentQuestionIndex + 1)
        }
    }

    const handleComplete = () => {
        if (isLastQuestion && answers[currentQuestion.id]) {
            setIsCompleting(true)
            // Call onComplete with all answers
            setTimeout(() => {
                onComplete(answers)
            }, 100)
        }
    }

    const handleSkipQuiz = () => {
        onSkip()
    }

    const getCategoryColor = (color) => {
        const colors = {
            blue: 'from-blue-500 to-blue-600',
            emerald: 'from-emerald-500 to-emerald-600',
            orange: 'from-orange-500 to-orange-600',
            purple: 'from-purple-500 to-purple-600',
            pink: 'from-pink-500 to-pink-600',
            red: 'from-red-500 to-red-600',
            indigo: 'from-indigo-500 to-indigo-600',
            teal: 'from-teal-500 to-teal-600'
        }
        return colors[color] || colors.blue
    }

    const getBgColor = (color) => {
        const colors = {
            blue: 'bg-blue-50 border-blue-200',
            emerald: 'bg-emerald-50 border-emerald-200',
            orange: 'bg-orange-50 border-orange-200',
            purple: 'bg-purple-50 border-purple-200',
            pink: 'bg-pink-50 border-pink-200',
            red: 'bg-red-50 border-red-200',
            indigo: 'bg-indigo-50 border-indigo-200',
            teal: 'bg-teal-50 border-teal-200'
        }
        return colors[color] || colors.blue
    }

    const getCurrentCategory = () => {
        return QUIZ_CATEGORIES.find(cat => cat.id === currentQuestion.category)
    }

    const category = getCurrentCategory()
    const CategoryIcon = category.icon

    return (
        <div className="w-full max-w-4xl mx-auto px-2 sm:px-4">
            <div className="space-y-4 sm:space-y-6">
                {/* Header */}
                <div className="text-center space-y-2 sm:space-y-3">
                    <div className="flex items-center justify-center gap-2 mb-1 sm:mb-2">
                        <Sparkles className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-600" />
                        <h2 className="text-xl sm:text-2xl lg:text-3xl font-bold text-slate-900">
                            Lifestyle Insights
                        </h2>
                        <Sparkles className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-600" />
                    </div>
                    <p className="text-xs sm:text-sm text-slate-600 max-w-2xl mx-auto px-4">
                        Answer 20 quick questions for better recommendations
                    </p>
                    <Badge variant="outline" className="text-[10px] sm:text-xs border-emerald-200 text-emerald-700">
                        ✨ Optional - Skip anytime
                    </Badge>
                </div>

                {/* Progress Bar with Stats */}
                <div className="space-y-2 sm:space-y-3">
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 text-xs sm:text-sm text-slate-600">
                        <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-900">
                                Question {currentQuestionIndex + 1}
                            </span>
                            <span className="text-slate-400">/</span>
                            <span className="text-slate-500">{ALL_QUESTIONS.length}</span>
                        </div>
                        <div className="flex items-center gap-3 sm:gap-4">
                            <div className="flex items-center gap-1.5">
                                <Award className="w-3 h-3 sm:w-4 sm:h-4 text-emerald-600" />
                                <span className="text-[10px] sm:text-xs font-medium">
                                    {answeredCount} answered
                                </span>
                            </div>
                            <span className="font-semibold text-emerald-600">
                                {Math.round(progress)}%
                            </span>
                        </div>
                    </div>
                    <div className="relative">
                        <Progress value={progress} className="h-2 sm:h-3" />
                        <div
                            className="absolute top-0 left-0 h-full bg-gradient-to-r from-emerald-400 to-teal-500 rounded-full transition-all duration-500 ease-out"
                            style={{ width: `${progress}%` }}
                        />
                    </div>
                </div>

                {/* Category Badge */}
                <div className="flex items-center justify-center">
                    <div className={`flex items-center gap-2 px-3 sm:px-4 py-1.5 sm:py-2 rounded-full bg-gradient-to-r ${getCategoryColor(category.color)} text-white shadow-lg transform hover:scale-105 transition-transform`}>
                        <CategoryIcon className="w-3 h-3 sm:w-4 sm:h-4" />
                        <span className="text-xs sm:text-sm font-semibold">{category.title}</span>
                    </div>
                </div>

                {/* Question Card - Redesigned */}
                <div className={`rounded-2xl border-2 ${getBgColor(category.color)} shadow-xl transition-all duration-300 overflow-hidden`}>
                    {/* Question Header */}
                    <div className="p-4 sm:p-6 pb-3 sm:pb-4">
                        <div className="flex flex-col items-center gap-3 sm:gap-4">
                            <div className="text-4xl sm:text-5xl lg:text-6xl animate-bounce-subtle">
                                {currentQuestion.emoji}
                            </div>
                            <h3 className="text-base sm:text-lg lg:text-xl font-bold text-slate-900 text-center leading-snug px-2">
                                {currentQuestion.question}
                            </h3>
                        </div>
                    </div>

                    {/* Options Grid */}
                    <div className="p-4 sm:p-6 pt-2 sm:pt-3 space-y-2 sm:space-y-3">
                        {currentQuestion.options.map((option, index) => {
                            const isSelected = answers[currentQuestion.id] === option.value
                            return (
                                <button
                                    key={option.value}
                                    onClick={() => handleAnswer(option.value)}
                                    className={`group w-full text-left p-3 sm:p-4 rounded-xl border-2 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] ${isSelected
                                            ? 'border-emerald-500 bg-white shadow-lg ring-2 ring-emerald-200'
                                            : 'border-slate-200 bg-white hover:border-emerald-400 hover:shadow-md'
                                        }`}
                                    style={{
                                        animationDelay: `${index * 50}ms`
                                    }}
                                >
                                    <div className="flex items-center justify-between gap-3">
                                        <span className={`text-sm sm:text-base font-medium transition-colors ${isSelected ? 'text-emerald-900' : 'text-slate-700 group-hover:text-slate-900'
                                            }`}>
                                            {option.label}
                                        </span>
                                        {isSelected && (
                                            <CheckCircle className="w-5 h-5 sm:w-6 sm:h-6 text-emerald-600 animate-scale-in" />
                                        )}
                                    </div>
                                </button>
                            )
                        })}
                    </div>
                </div>

                {/* Navigation Buttons - Mobile Optimized */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 sm:gap-3 pt-2">
                    <Button
                        variant="outline"
                        onClick={handlePrevious}
                        disabled={currentQuestionIndex === 0}
                        className="flex items-center justify-center gap-2 h-11 sm:h-10 text-sm sm:text-base order-1 sm:order-1 border-2 hover:border-slate-400 transition-all"
                    >
                        <ChevronLeft className="w-4 h-4" />
                        Previous
                    </Button>

                    <Button
                        variant="ghost"
                        onClick={handleSkipQuiz}
                        className="text-slate-600 hover:text-slate-900 hover:bg-slate-100 h-11 sm:h-10 text-sm sm:text-base order-3 sm:order-2 transition-all"
                    >
                        Skip Quiz
                    </Button>

                    {isLastQuestion && answers[currentQuestion.id] ? (
                        <Button
                            onClick={handleComplete}
                            disabled={isCompleting}
                            className="flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white h-11 sm:h-10 text-sm sm:text-base order-2 sm:order-3 shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
                        >
                            {isCompleting ? (
                                <>
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                                    Completing...
                                </>
                            ) : (
                                <>
                                    <CheckCircle className="w-4 h-4" />
                                    Complete Quiz
                                </>
                            )}
                        </Button>
                    ) : answers[currentQuestion.id] ? (
                        <Button
                            onClick={handleNext}
                            className="flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white h-11 sm:h-10 text-sm sm:text-base order-2 sm:order-3 transition-all"
                        >
                            Next
                            <ChevronRight className="w-4 h-4" />
                        </Button>
                    ) : (
                        <div className="h-11 sm:h-10 order-2 sm:order-3" />
                    )}
                </div>

                {/* Help Text - Enhanced */}
                <div className="flex items-start gap-2 sm:gap-3 p-3 sm:p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border-2 border-blue-200 shadow-sm">
                    <Info className="w-4 h-4 sm:w-5 sm:h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <div className="space-y-1">
                        <p className="text-xs sm:text-sm text-blue-900 font-medium">
                            Your answers help our AI create hyper-personalized recommendations
                        </p>
                        <p className="text-[10px] sm:text-xs text-blue-700">
                            🔒 All information is encrypted and private. Never shared with anyone.
                        </p>
                    </div>
                </div>
            </div>

            {/* Add custom animations */}
            <style jsx>{`
                @keyframes bounce-subtle {
                    0%, 100% { transform: translateY(0); }
                    50% { transform: translateY(-5px); }
                }
                @keyframes scale-in {
                    0% { transform: scale(0); }
                    50% { transform: scale(1.2); }
                    100% { transform: scale(1); }
                }
                .animate-bounce-subtle {
                    animation: bounce-subtle 2s ease-in-out infinite;
                }
                .animate-scale-in {
                    animation: scale-in 0.3s ease-out;
                }
            `}</style>
        </div>
    )
}
