'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { 
  Settings,
  Target,
  TrendingUp,
  PiggyBank,
  Lightbulb,
  CheckCircle,
  ArrowRight,
  Users,
  DollarSign
} from 'lucide-react'

export default function BudgetCustomizationGuide({ onStartCustomization }) {
  const [currentStep, setCurrentStep] = useState(0)

  const features = [
    {
      icon: <Settings className="w-6 h-6 text-blue-600" />,
      title: "Easy Customization",
      description: "Adjust budget categories with simple sliders and input fields",
      benefit: "Perfect your budget in minutes, not hours"
    },
    {
      icon: <Target className="w-6 h-6 text-green-600" />,
      title: "Real-time Balancing",
      description: "Automatic validation ensures your budget adds up correctly",
      benefit: "Never worry about math errors again"
    },
    {
      icon: <TrendingUp className="w-6 h-6 text-purple-600" />,
      title: "Smart Recommendations",
      description: "Get health score feedback as you make changes",
      benefit: "Make informed decisions with AI guidance"
    },
    {
      icon: <PiggyBank className="w-6 h-6 text-emerald-600" />,
      title: "Flexible Priorities",
      description: "Adjust spending based on your lifestyle and goals",
      benefit: "Budget that actually fits your life"
    }
  ]

  const steps = [
    {
      title: "Review Your AI Budget",
      description: "Start with the AI-generated budget as your foundation",
      action: "Check category allocations and amounts"
    },
    {
      title: "Identify Your Priorities",
      description: "Think about what matters most in your financial life",
      action: "Consider savings goals, lifestyle preferences"
    },
    {
      title: "Customize Categories",
      description: "Adjust amounts using sliders or direct input",
      action: "Increase/decrease based on your needs"
    },
    {
      title: "Balance Your Budget",
      description: "Ensure total allocations match your income",
      action: "Use auto-balance or manual adjustments"
    },
    {
      title: "Save & Track",
      description: "Save your custom budget and start tracking expenses",
      action: "Monitor progress against your goals"
    }
  ]

  const useCases = [
    {
      scenario: "Young Professional",
      description: "Increase entertainment & dining, reduce family expenses",
      icon: "👨‍💼",
      adjustments: ["↑ Entertainment: 15%", "↑ Dining: 20%", "↓ Family: 5%"]
    },
    {
      scenario: "Growing Family",
      description: "Prioritize healthcare, education, and family needs",
      icon: "👨‍👩‍👧‍👦",
      adjustments: ["↑ Healthcare: 12%", "↑ Family: 25%", "↓ Entertainment: 8%"]
    },
    {
      scenario: "Aggressive Saver",
      description: "Maximize savings and investments, minimize discretionary spending",
      icon: "💰",
      adjustments: ["↑ Savings: 40%", "↑ Investments: 20%", "↓ Shopping: 5%"]
    }
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <Card className="bg-gradient-to-br from-blue-600 via-purple-600 to-emerald-600 text-white border-0 shadow-xl">
        <CardContent className="p-8 text-center">
          <div className="w-16 h-16 bg-white/20 backdrop-blur-xl rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Settings className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold mb-3">Budget Customization Guide</h1>
          <p className="text-blue-100 text-lg mb-6">
            Learn how to personalize your AI-generated budget to perfectly match your lifestyle and financial goals
          </p>
          <Button
            onClick={onStartCustomization}
            className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-3 text-lg font-medium"
          >
            Start Customizing Now
            <ArrowRight className="w-5 h-5 ml-2" />
          </Button>
        </CardContent>
      </Card>

      {/* Key Features */}
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-gray-900">
            🚀 Key Features
          </CardTitle>
          <CardDescription>
            Powerful tools to create your perfect budget
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {features.map((feature, index) => (
              <div key={index} className="flex items-start space-x-4 p-4 border border-gray-200 rounded-lg hover:shadow-md transition-shadow">
                <div className="flex-shrink-0 p-2 bg-gray-50 rounded-lg">
                  {feature.icon}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-gray-900 mb-1">{feature.title}</h3>
                  <p className="text-sm text-gray-600 mb-2">{feature.description}</p>
                  <Badge variant="outline" className="text-xs">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    {feature.benefit}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Step-by-Step Process */}
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-gray-900">
            📋 How It Works
          </CardTitle>
          <CardDescription>
            Simple 5-step process to customize your budget
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {steps.map((step, index) => (
              <div key={index} className="flex items-start space-x-4 p-4 border border-gray-200 rounded-lg">
                <div className="flex-shrink-0 w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm">
                  {index + 1}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-gray-900 mb-1">{step.title}</h3>
                  <p className="text-sm text-gray-600 mb-2">{step.description}</p>
                  <p className="text-xs text-blue-600 font-medium">→ {step.action}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Common Use Cases */}
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-gray-900">
            💡 Common Customization Examples
          </CardTitle>
          <CardDescription>
            See how different users adapt their budgets
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {useCases.map((useCase, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                <div className="text-center mb-4">
                  <div className="text-4xl mb-2">{useCase.icon}</div>
                  <h3 className="font-semibold text-gray-900 mb-1">{useCase.scenario}</h3>
                  <p className="text-sm text-gray-600">{useCase.description}</p>
                </div>
                <div className="space-y-2">
                  {useCase.adjustments.map((adjustment, adjIndex) => (
                    <div key={adjIndex} className="text-xs bg-gray-50 px-2 py-1 rounded flex items-center">
                      <span className="font-mono">{adjustment}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Benefits */}
      <Card className="bg-gradient-to-r from-emerald-50 to-blue-50 border-emerald-200">
        <CardContent className="p-8">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-3">
              🎯 Why Customize Your Budget?
            </h2>
            <p className="text-gray-600">
              Make your budget work for YOU, not against you
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="text-center p-4">
              <DollarSign className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
              <h3 className="font-semibold text-gray-900 mb-1">Better Control</h3>
              <p className="text-sm text-gray-600">Take charge of every rupee</p>
            </div>
            <div className="text-center p-4">
              <Target className="w-8 h-8 text-blue-600 mx-auto mb-2" />
              <h3 className="font-semibold text-gray-900 mb-1">Goal Alignment</h3>
              <p className="text-sm text-gray-600">Match your priorities</p>
            </div>
            <div className="text-center p-4">
              <TrendingUp className="w-8 h-8 text-purple-600 mx-auto mb-2" />
              <h3 className="font-semibold text-gray-900 mb-1">Better Results</h3>
              <p className="text-sm text-gray-600">Achieve financial success</p>
            </div>
            <div className="text-center p-4">
              <Users className="w-8 h-8 text-orange-600 mx-auto mb-2" />
              <h3 className="font-semibold text-gray-900 mb-1">Family Fit</h3>
              <p className="text-sm text-gray-600">Works for your situation</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Call to Action */}
      <Card className="bg-gradient-to-r from-blue-600 to-purple-600 text-white border-0">
        <CardContent className="p-8 text-center">
          <h2 className="text-2xl font-bold mb-3">Ready to Create Your Perfect Budget?</h2>
          <p className="text-blue-100 mb-6">
            Start with AI recommendations, then customize to match your unique needs and goals
          </p>
          <Button
            onClick={onStartCustomization}
            className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-3 text-lg font-medium"
          >
            <Settings className="w-5 h-5 mr-2" />
            Customize My Budget Now
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
