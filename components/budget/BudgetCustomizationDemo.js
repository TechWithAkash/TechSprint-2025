'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { 
  Settings,
  TrendingUp,
  TrendingDown,
  DollarSign,
  Target,
  CheckCircle,
  ArrowRight,
  Sparkles
} from 'lucide-react'

export default function BudgetCustomizationDemo() {
  const [currentStep, setCurrentStep] = useState(0)
  const [demoData, setDemoData] = useState({
    original: {
      food: { amount: 15000, percentage: 30 },
      entertainment: { amount: 5000, percentage: 10 },
      savings: { amount: 10000, percentage: 20 }
    },
    customized: {
      food: { amount: 18000, percentage: 36 },
      entertainment: { amount: 8000, percentage: 16 },
      savings: { amount: 7000, percentage: 14 }
    }
  })

  const demoSteps = [
    {
      title: "Original AI Budget",
      description: "Start with AI recommendations",
      data: demoData.original,
      highlight: "AI optimized for financial health"
    },
    {
      title: "Identify Preferences", 
      description: "You prefer dining out more",
      data: demoData.original,
      highlight: "Consider your lifestyle needs"
    },
    {
      title: "Adjust Categories",
      description: "Increase food & entertainment",
      data: demoData.customized,
      highlight: "Budget now matches your priorities"
    },
    {
      title: "Balanced & Saved!",
      description: "Your personalized budget is ready",
      data: demoData.customized,
      highlight: "✅ Customization complete"
    }
  ]

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStep((prev) => (prev + 1) % demoSteps.length)
    }, 3000)

    return () => clearInterval(timer)
  }, [demoSteps.length])

  const currentStepData = demoSteps[currentStep]

  return (
    <Card className="bg-gradient-to-br from-purple-50 via-blue-50 to-emerald-50 border-2 border-purple-200 shadow-xl">
      <CardHeader className="text-center pb-4">
        <div className="w-12 h-12 bg-gradient-to-r from-purple-600 to-blue-600 rounded-xl flex items-center justify-center mx-auto mb-3">
          <Sparkles className="w-6 h-6 text-white" />
        </div>
        <CardTitle className="text-xl font-bold text-gray-900">
          Live Budget Customization Demo
        </CardTitle>
        <CardDescription>
          See how easy it is to personalize your budget
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Step Indicator */}
        <div className="flex justify-center space-x-2 mb-4">
          {demoSteps.map((_, index) => (
            <div
              key={index}
              className={`w-3 h-3 rounded-full transition-all duration-300 ${
                index === currentStep ? 'bg-purple-600 w-8' : 'bg-gray-300'
              }`}
            />
          ))}
        </div>

        {/* Current Step */}
        <div className="text-center mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Step {currentStep + 1}: {currentStepData.title}
          </h3>
          <p className="text-gray-600 mb-2">{currentStepData.description}</p>
          <Badge className="bg-purple-100 text-purple-800 px-3 py-1">
            {currentStepData.highlight}
          </Badge>
        </div>

        {/* Demo Categories */}
        <div className="space-y-4">
          {Object.entries(currentStepData.data).map(([category, data]) => {
            const isChanged = currentStep >= 2 && (
              (category === 'food' && data.amount > 15000) ||
              (category === 'entertainment' && data.amount > 5000) ||
              (category === 'savings' && data.amount < 10000)
            )

            return (
              <div key={category} className="bg-white/70 backdrop-blur-sm rounded-lg p-4 border border-white/50">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">
                      {category === 'food' && '🍽️'}
                      {category === 'entertainment' && '🎬'}
                      {category === 'savings' && '💰'}
                    </span>
                    <div>
                      <h4 className="font-medium text-gray-900 capitalize">{category}</h4>
                      {isChanged && (
                        <div className="flex items-center gap-1 text-sm">
                          {data.amount > demoData.original[category].amount ? (
                            <>
                              <TrendingUp className="w-3 h-3 text-green-600" />
                              <span className="text-green-600">Increased</span>
                            </>
                          ) : (
                            <>
                              <TrendingDown className="w-3 h-3 text-red-600" />
                              <span className="text-red-600">Decreased</span>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-bold text-gray-900">
                      ₹{data.amount.toLocaleString('en-IN')}
                    </p>
                    <p className="text-sm text-gray-500">{data.percentage}%</p>
                  </div>
                </div>
                <Progress 
                  value={data.percentage} 
                  className={`h-2 transition-all duration-1000 ${
                    isChanged ? 'bg-purple-100' : 'bg-gray-100'
                  }`}
                />
                {isChanged && (
                  <div className="mt-2 text-xs text-gray-500">
                    Original: ₹{demoData.original[category].amount.toLocaleString('en-IN')} 
                    ({demoData.original[category].percentage}%)
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Action Buttons */}
        <div className="text-center pt-4 border-t border-white/50">
          <p className="text-sm text-gray-600 mb-3">
            Ready to customize your own budget?
          </p>
          <Button className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white px-6 py-2">
            <Settings className="w-4 h-4 mr-2" />
            Start Customizing
            <ArrowRight className="w-4 h-4 ml-2" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
