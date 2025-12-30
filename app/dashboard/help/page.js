'use client'

import { useState } from 'react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  HelpCircle,
  Search,
  MessageCircle,
  Mail,
  Phone,
  BookOpen,
  Lightbulb,
  Target,
  IndianRupee,
  Mic,
  Calendar,
  PieChart,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Sparkles
} from 'lucide-react'

const faqs = [
  {
    category: 'Getting Started',
    icon: BookOpen,
    questions: [
      {
        q: 'How do I set up my budget?',
        a: 'Go to Dashboard → Budget section. Click "Generate Budget" to create an AI-powered budget based on your income, city, and lifestyle preferences. You can customize categories and amounts after generation.'
      },
      {
        q: 'How accurate is the AI-generated budget?',
        a: 'Our AI uses real cost-of-living data for 50+ Indian cities, your income sources, family size, and lifestyle preferences to create personalized budgets. You can always adjust the suggestions to match your actual needs.'
      },
      {
        q: 'Can I have multiple income sources?',
        a: 'Yes! WealthWise supports multiple income streams including salary, freelance, rental income, investments, and more. Add them during onboarding or from your Profile page.'
      }
    ]
  },
  {
    category: 'Voice Entry',
    icon: Mic,
    questions: [
      {
        q: 'How do I add expenses by voice?',
        a: 'Click the microphone button on the dashboard or expenses page. Speak naturally like "I spent 500 rupees on lunch at Dominos" or "Metro pass for 200 rupees". The AI will automatically categorize your expense.'
      },
      {
        q: 'What languages does voice entry support?',
        a: 'Voice entry supports English, Hindi, and Hinglish (mixed). You can say "Maine 500 rupay khana pe kharch kiye" or mix languages naturally.'
      },
      {
        q: 'Why isn\'t voice entry recognizing my expense?',
        a: 'Ensure you mention the amount clearly. Speak in a quiet environment and include keywords like "spent", "paid", "bought" along with the amount. If it fails, you can always add manually.'
      }
    ]
  },
  {
    category: 'Budget & Expenses',
    icon: IndianRupee,
    questions: [
      {
        q: 'How do I track my expenses?',
        a: 'Add expenses via voice or manual entry. View all expenses in Dashboard → Expenses. Filter by category, date, or search by description. The app automatically calculates totals and compares against your budget.'
      },
      {
        q: 'What happens when I exceed my budget?',
        a: 'You\'ll receive notifications at 80% and 95% of your budget. The dashboard highlights overspent categories in red. You can adjust your budget or reduce spending in other areas to compensate.'
      },
      {
        q: 'Can I edit or delete expenses?',
        a: 'Yes! Go to Dashboard → Expenses, find the expense, and click the edit or delete icon. All changes are saved immediately.'
      }
    ]
  },
  {
    category: 'Savings Goals',
    icon: Target,
    questions: [
      {
        q: 'How do I create a savings goal?',
        a: 'Go to Dashboard → Goals → Add Goal. Enter a name (e.g., "Vacation Fund"), target amount, and deadline. The AI will suggest monthly savings needed to reach your goal.'
      },
      {
        q: 'How does auto-allocation work?',
        a: 'When you add income or have surplus budget, WealthWise can automatically allocate funds to your goals based on priority. Enable this in Settings → Goals.'
      },
      {
        q: 'Can I track progress toward my goals?',
        a: 'Yes! The Goals page shows visual progress bars, estimated completion dates, and suggestions to accelerate savings. You\'ll receive milestone notifications too.'
      }
    ]
  },
  {
    category: 'Seasonal Planning',
    icon: Calendar,
    questions: [
      {
        q: 'What is seasonal planning?',
        a: 'WealthWise knows Indian festivals, tax deadlines, and seasonal expenses. It helps you prepare for Diwali shopping, tax-saving investments (before March 31), school fees, and more.'
      },
      {
        q: 'How do I prepare for upcoming festivals?',
        a: 'Check Dashboard → Seasonal Events. The AI recommends how much to save and when to start. You can create dedicated savings goals for festivals.'
      },
      {
        q: 'Does it track tax-saving deadlines?',
        a: 'Yes! You\'ll receive reminders for 80C investments, advance tax payments, and ITR filing deadlines. The app suggests tax-saving options based on your income.'
      }
    ]
  },
  {
    category: 'Analytics & Insights',
    icon: PieChart,
    questions: [
      {
        q: 'Where can I see my spending analytics?',
        a: 'Dashboard → Analytics shows interactive charts including spending by category, monthly trends, budget vs actual comparison, and savings progress.'
      },
      {
        q: 'What are AI Insights?',
        a: 'Our AI analyzes your spending patterns to provide personalized tips like "You spent 40% more on food this week" or "Great job! You\'re ahead on your vacation goal".'
      },
      {
        q: 'Can I export my financial data?',
        a: 'Yes! Go to Settings → Privacy & Data → Export. Download your complete financial history as JSON for your records or to use with other tools.'
      }
    ]
  }
]

const quickTips = [
  {
    icon: Sparkles,
    title: 'Use Voice for Quick Entry',
    description: 'Say "I spent 200 on chai" - it\'s faster than typing!'
  },
  {
    icon: Target,
    title: 'Set Realistic Goals',
    description: 'Start with small, achievable goals to build savings habit'
  },
  {
    icon: Calendar,
    title: 'Plan for Festivals Early',
    description: 'Start saving 2-3 months before Diwali or weddings'
  },
  {
    icon: IndianRupee,
    title: 'Review Weekly',
    description: 'Check your budget every Sunday to stay on track'
  }
]

function FAQItem({ question, answer }) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className="border-b border-slate-100 last:border-0">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full py-4 flex items-center justify-between text-left hover:bg-slate-50 px-2 rounded-lg transition-colors"
      >
        <span className="font-medium text-slate-800 pr-4">{question}</span>
        {isOpen ? (
          <ChevronUp className="h-5 w-5 text-slate-400 flex-shrink-0" />
        ) : (
          <ChevronDown className="h-5 w-5 text-slate-400 flex-shrink-0" />
        )}
      </button>
      {isOpen && (
        <div className="pb-4 px-2 text-slate-600 text-sm leading-relaxed">
          {answer}
        </div>
      )}
    </div>
  )
}

function HelpContent() {
  const { t } = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState(null)

  // Filter FAQs based on search
  const filteredFaqs = searchQuery
    ? faqs.map(category => ({
        ...category,
        questions: category.questions.filter(
          q =>
            q.q.toLowerCase().includes(searchQuery.toLowerCase()) ||
            q.a.toLowerCase().includes(searchQuery.toLowerCase())
        )
      })).filter(category => category.questions.length > 0)
    : faqs

  return (
    <DashboardLayout title="Help & Support">
      <div className="space-y-6 max-w-4xl">
        {/* Header */}
        <div className="text-center py-6">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-emerald-100 rounded-full mb-4">
            <HelpCircle className="h-8 w-8 text-emerald-600" />
          </div>
          <h1 className="text-2xl font-bold text-slate-800">How can we help you?</h1>
          <p className="text-slate-600 mt-2">Search our help center or browse topics below</p>
        </div>

        {/* Search */}
        <div className="relative max-w-xl mx-auto">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
          <Input
            placeholder="Search for help..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 py-6 text-lg"
          />
        </div>

        {/* Quick Tips */}
        <Card className="bg-gradient-to-r from-emerald-50 to-teal-50 border-emerald-200">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-800">
              <Lightbulb className="h-5 w-5" />
              Quick Tips
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              {quickTips.map((tip, index) => (
                <div key={index} className="flex items-start gap-3 bg-white/60 rounded-lg p-3">
                  <div className="p-2 bg-emerald-100 rounded-lg">
                    <tip.icon className="h-4 w-4 text-emerald-600" />
                  </div>
                  <div>
                    <h4 className="font-medium text-slate-800 text-sm">{tip.title}</h4>
                    <p className="text-slate-600 text-xs mt-0.5">{tip.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* FAQ Sections */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-slate-800">Frequently Asked Questions</h2>

          {filteredFaqs.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center">
                <Search className="h-12 w-12 text-slate-300 mx-auto mb-3" />
                <p className="text-slate-600">No results found for &ldquo;{searchQuery}&rdquo;</p>
                <p className="text-slate-500 text-sm mt-1">Try different keywords or browse categories below</p>
                <Button
                  variant="outline"
                  className="mt-4"
                  onClick={() => setSearchQuery('')}
                >
                  Clear Search
                </Button>
              </CardContent>
            </Card>
          ) : (
            filteredFaqs.map((category, index) => (
              <Card key={index}>
                <CardHeader
                  className="cursor-pointer hover:bg-slate-50 transition-colors"
                  onClick={() => setActiveCategory(activeCategory === index ? null : index)}
                >
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-slate-100 rounded-lg">
                        <category.icon className="h-5 w-5 text-slate-600" />
                      </div>
                      <span className="text-base">{category.category}</span>
                    </div>
                    <span className="text-sm text-slate-500">
                      {category.questions.length} questions
                    </span>
                  </CardTitle>
                </CardHeader>
                {(activeCategory === index || searchQuery) && (
                  <CardContent className="pt-0">
                    {category.questions.map((faq, faqIndex) => (
                      <FAQItem key={faqIndex} question={faq.q} answer={faq.a} />
                    ))}
                  </CardContent>
                )}
              </Card>
            ))
          )}
        </div>

        {/* Contact Support */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MessageCircle className="h-5 w-5 text-blue-600" />
              Still need help?
            </CardTitle>
            <CardDescription>Our support team is here to assist you</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <a
                href="mailto:support@wealthwise.in"
                className="flex items-center gap-3 p-4 border rounded-lg hover:bg-slate-50 transition-colors"
              >
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Mail className="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <h4 className="font-medium text-slate-800">Email Support</h4>
                  <p className="text-slate-600 text-sm">support@wealthwise.in</p>
                </div>
                <ExternalLink className="h-4 w-4 text-slate-400 ml-auto" />
              </a>

              <a
                href="tel:+911234567890"
                className="flex items-center gap-3 p-4 border rounded-lg hover:bg-slate-50 transition-colors"
              >
                <div className="p-2 bg-green-100 rounded-lg">
                  <Phone className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <h4 className="font-medium text-slate-800">Phone Support</h4>
                  <p className="text-slate-600 text-sm">+91 12345 67890</p>
                </div>
                <ExternalLink className="h-4 w-4 text-slate-400 ml-auto" />
              </a>
            </div>
          </CardContent>
        </Card>

        {/* App Info */}
        <Card className="bg-slate-50">
          <CardContent className="pt-6">
            <div className="text-center space-y-2">
              <h3 className="font-semibold text-slate-800">WealthWise</h3>
              <p className="text-sm text-slate-600">AI-Powered Personal Finance for India</p>
              <p className="text-xs text-slate-500">Version 2.0.0</p>
              <div className="flex items-center justify-center gap-4 mt-4 text-xs text-slate-500">
                <a href="#" className="hover:text-emerald-600">Privacy Policy</a>
                <span>•</span>
                <a href="#" className="hover:text-emerald-600">Terms of Service</a>
                <span>•</span>
                <a href="#" className="hover:text-emerald-600">About Us</a>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}

export default function HelpPage() {
  return (
    <OnboardingGuard>
      <HelpContent />
    </OnboardingGuard>
  )
}
