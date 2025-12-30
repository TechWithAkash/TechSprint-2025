'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useSession } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import LanguageSelector from '@/components/ui/LanguageSelector'
import {
  TrendingUp,
  Shield,
  Zap,
  ArrowRight,
  BarChart3,
  PieChart,
  Target,
  Menu,
  X,
  CheckCircle,
  Brain,
  Wallet,
  Calculator
} from 'lucide-react'

export default function Home() {
  const { data: session } = useSession()
  const { t } = useTranslation()
  const [isScrolled, setIsScrolled] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const features = [
    {
      icon: Brain,
      title: t('features.ai.title'),
      description: t('features.ai.description'),
      color: 'text-purple-600',
      bg: 'bg-purple-50'
    },
    {
      icon: PieChart,
      title: t('features.budgeting.title'),
      description: t('features.budgeting.description'),
      color: 'text-blue-600',
      bg: 'bg-blue-50'
    },
    {
      icon: Target,
      title: t('features.goals.title'),
      description: t('features.goals.description'),
      color: 'text-emerald-600',
      bg: 'bg-emerald-50'
    },
    {
      icon: Calculator,
      title: t('features.investment.title'),
      description: t('features.investment.description'),
      color: 'text-amber-600',
      bg: 'bg-amber-50'
    },
    {
      icon: Shield,
      title: t('features.security.title'),
      description: t('features.security.description'),
      color: 'text-slate-600',
      bg: 'bg-slate-50'
    },
    {
      icon: Zap,
      title: t('features.automation.title'),
      description: t('features.automation.description'),
      color: 'text-orange-600',
      bg: 'bg-orange-50'
    }
  ]

  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className={`fixed w-full z-50 transition-all duration-200 ${
        isScrolled ? 'bg-white/95 backdrop-blur-sm shadow-sm' : 'bg-transparent'
      }`}>
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <Link href="/" className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-lg flex items-center justify-center">
                <TrendingUp className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold text-slate-800">
                Wealth<span className="text-emerald-600">Wise</span>
              </span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-6">
              <a href="#features" className="text-sm text-slate-600 hover:text-slate-900 transition-colors">
                {t('nav.features')}
              </a>
              <a href="#benefits" className="text-sm text-slate-600 hover:text-slate-900 transition-colors">
                {t('nav.about')}
              </a>
              <LanguageSelector variant="nav" />

              {session ? (
                <Link href="/dashboard">
                  <button className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                    {t('nav.dashboard')}
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </Link>
              ) : (
                <div className="flex items-center gap-3">
                  <Link href="/auth/signin">
                    <button className="text-sm text-slate-600 hover:text-slate-900 font-medium transition-colors">
                      {t('nav.signin')}
                    </button>
                  </Link>
                  <Link href="/auth/signup">
                    <button className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                      {t('nav.signup')}
                    </button>
                  </Link>
                </div>
              )}
            </div>

            {/* Mobile Menu Button */}
            <button
              className="md:hidden p-2 text-slate-600"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden absolute top-16 left-0 right-0 bg-white border-t border-slate-100 shadow-lg">
              <div className="flex flex-col p-4 gap-3">
                <a
                  href="#features"
                  className="text-slate-600 py-2"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  {t('nav.features')}
                </a>
                <a
                  href="#benefits"
                  className="text-slate-600 py-2"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  {t('nav.about')}
                </a>
                <div className="py-2">
                  <LanguageSelector variant="mobile" />
                </div>
                <hr className="border-slate-100" />
                {session ? (
                  <Link href="/dashboard" onClick={() => setMobileMenuOpen(false)}>
                    <button className="w-full bg-emerald-600 text-white py-3 rounded-lg font-medium">
                      {t('nav.dashboard')}
                    </button>
                  </Link>
                ) : (
                  <div className="flex flex-col gap-2">
                    <Link href="/auth/signin" onClick={() => setMobileMenuOpen(false)}>
                      <button className="w-full border border-slate-200 text-slate-700 py-3 rounded-lg font-medium">
                        {t('nav.signin')}
                      </button>
                    </Link>
                    <Link href="/auth/signup" onClick={() => setMobileMenuOpen(false)}>
                      <button className="w-full bg-emerald-600 text-white py-3 rounded-lg font-medium">
                        {t('nav.signup')}
                      </button>
                    </Link>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-24 pb-16 px-4 sm:px-6">
        <div className="max-w-4xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 bg-emerald-50 border border-emerald-100 rounded-full px-4 py-1.5 mb-6">
            <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-sm text-emerald-700 font-medium">{t('hero.badge')}</span>
          </div>

          {/* Headline */}
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-slate-900 leading-tight mb-4">
            {t('hero.title.part1')}{' '}
            <span className="text-emerald-600">{t('hero.title.part2')}</span>
          </h1>

          {/* Subtitle */}
          <p className="text-lg text-slate-600 max-w-2xl mx-auto mb-8">
            {t('hero.subtitle')}
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-12">
            {session ? (
              <Link href="/dashboard">
                <button className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
                  {t('hero.cta.dashboard')}
                  <ArrowRight className="w-4 h-4" />
                </button>
              </Link>
            ) : (
              <>
                <Link href="/auth/signup">
                  <button className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
                    {t('hero.cta.start')}
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </Link>
                <Link href="/auth/signin">
                  <button className="w-full sm:w-auto border border-slate-200 hover:border-slate-300 text-slate-700 px-6 py-3 rounded-lg font-medium transition-colors">
                    {t('nav.signin')}
                  </button>
                </Link>
              </>
            )}
          </div>

          {/* Trust Indicators */}
          <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-slate-500">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-600" />
              <span>{t('trust.bankLevel')}</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-600" />
              <span>{t('trust.noFees')}</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-600" />
              <span>{t('trust.fastSetup')}</span>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-16 px-4 sm:px-6 bg-slate-50">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-3">
              {t('features.title')}
            </h2>
            <p className="text-slate-600 max-w-2xl mx-auto">
              {t('features.subtitle')}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div
                  key={index}
                  className="bg-white rounded-xl p-6 border border-slate-100 hover:shadow-md transition-shadow"
                >
                  <div className={`w-10 h-10 ${feature.bg} rounded-lg flex items-center justify-center mb-4`}>
                    <Icon className={`w-5 h-5 ${feature.color}`} />
                  </div>
                  <h3 className="font-semibold text-slate-900 mb-2">{feature.title}</h3>
                  <p className="text-sm text-slate-600 leading-relaxed">{feature.description}</p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Benefits Section */}
      <section id="benefits" className="py-16 px-4 sm:px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-3">
              {t('benefits.title')}
            </h2>
            <p className="text-slate-600 max-w-xl mx-auto">
              {t('benefits.subtitle')}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-14 h-14 bg-emerald-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Shield className="w-7 h-7 text-emerald-600" />
              </div>
              <h3 className="font-semibold text-slate-900 mb-2">{t('benefits.secure.title')}</h3>
              <p className="text-sm text-slate-600">{t('benefits.secure.description')}</p>
            </div>

            <div className="text-center">
              <div className="w-14 h-14 bg-blue-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Brain className="w-7 h-7 text-blue-600" />
              </div>
              <h3 className="font-semibold text-slate-900 mb-2">{t('benefits.ai.title')}</h3>
              <p className="text-sm text-slate-600">{t('benefits.ai.description')}</p>
            </div>

            <div className="text-center">
              <div className="w-14 h-14 bg-purple-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <BarChart3 className="w-7 h-7 text-purple-600" />
              </div>
              <h3 className="font-semibold text-slate-900 mb-2">{t('benefits.realtime.title')}</h3>
              <p className="text-sm text-slate-600">{t('benefits.realtime.description')}</p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 px-4 sm:px-6 bg-slate-900">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4">
            {t('cta.title.part1')} <span className="text-emerald-400">{t('cta.title.part2')}</span>
          </h2>
          <p className="text-slate-400 mb-8 max-w-xl mx-auto">
            {t('cta.subtitle')}
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            {session ? (
              <Link href="/dashboard">
                <button className="w-full sm:w-auto bg-white hover:bg-slate-100 text-slate-900 px-6 py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
                  {t('cta.openDashboard')}
                  <ArrowRight className="w-4 h-4" />
                </button>
              </Link>
            ) : (
              <>
                <Link href="/auth/signup">
                  <button className="w-full sm:w-auto bg-emerald-500 hover:bg-emerald-600 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
                    {t('cta.startJourney')}
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </Link>
                <Link href="/auth/signin">
                  <button className="w-full sm:w-auto border border-slate-700 hover:border-slate-600 text-white px-6 py-3 rounded-lg font-medium transition-colors">
                    {t('cta.signIn')}
                  </button>
                </Link>
              </>
            )}
          </div>

          {/* Trust elements */}
          <div className="flex flex-wrap items-center justify-center gap-6 mt-8 text-sm text-slate-500">
            <span className="flex items-center gap-1">
              <Shield className="w-4 h-4" />
              {t('cta.trust.secure')}
            </span>
            <span className="flex items-center gap-1">
              <Zap className="w-4 h-4" />
              {t('cta.trust.fast')}
            </span>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-4 sm:px-6 border-t border-slate-100">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {/* Logo & Description */}
            <div className="md:col-span-2">
              <Link href="/" className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-lg flex items-center justify-center">
                  <TrendingUp className="w-5 h-5 text-white" />
                </div>
                <span className="text-xl font-bold text-slate-800">
                  Wealth<span className="text-emerald-600">Wise</span>
                </span>
              </Link>
              <p className="text-sm text-slate-600 max-w-xs">
                {t('footer.description')}
              </p>
            </div>

            {/* Product Links */}
            <div>
              <h4 className="font-semibold text-slate-900 mb-3">{t('footer.product')}</h4>
              <ul className="space-y-2 text-sm text-slate-600">
                <li><a href="#features" className="hover:text-slate-900 transition-colors">{t('footer.links.features')}</a></li>
                <li><a href="#" className="hover:text-slate-900 transition-colors">{t('footer.links.pricing')}</a></li>
                <li><a href="#" className="hover:text-slate-900 transition-colors">{t('footer.links.security')}</a></li>
              </ul>
            </div>

            {/* Support Links */}
            <div>
              <h4 className="font-semibold text-slate-900 mb-3">{t('footer.support')}</h4>
              <ul className="space-y-2 text-sm text-slate-600">
                <li><a href="#" className="hover:text-slate-900 transition-colors">{t('footer.links.helpCenter')}</a></li>
                <li><a href="#" className="hover:text-slate-900 transition-colors">{t('footer.links.contact')}</a></li>
                <li><Link href="/privacy-policy" className="hover:text-slate-900 transition-colors">{t('footer.links.privacy')}</Link></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-slate-100 mt-8 pt-8 text-center text-sm text-slate-500">
            {t('footer.copyright')}
          </div>
        </div>
      </footer>
    </div>
  )
}
