'use client'

import { useState, useRef, useEffect } from 'react'
import { Globe, ChevronDown, Check } from 'lucide-react'
import { useLanguage, SUPPORTED_LANGUAGES } from '@/components/providers/LanguageProvider'

// Custom language selector dropdown
export default function LanguageSelector({ variant = 'nav' }) {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef(null)
  const { currentLanguage, changeLanguage, isLoaded } = useLanguage()

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const currentLangData = SUPPORTED_LANGUAGES.find(l => l.code === currentLanguage) || SUPPORTED_LANGUAGES[0]

  const handleLanguageChange = (langCode) => {
    setIsOpen(false)
    if (langCode !== currentLanguage) {
      changeLanguage(langCode)
    }
  }

  // Don't render until loaded
  if (!isLoaded) return null

  // Onboarding variant - Grid of language cards
  if (variant === 'onboarding') {
    return (
      <div className="space-y-4">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-500 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Globe className="w-8 h-8 text-white" />
          </div>
          <h2 className="text-2xl font-bold text-slate-800 mb-2">Choose Your Language</h2>
          <p className="text-slate-600 mb-4">Select your preferred language</p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {SUPPORTED_LANGUAGES.map((lang) => (
            <button
              key={lang.code}
              onClick={() => handleLanguageChange(lang.code)}
              className={`p-4 rounded-xl border-2 transition-all text-left ${
                currentLanguage === lang.code
                  ? 'border-emerald-500 bg-emerald-50'
                  : 'border-slate-200 hover:border-emerald-300 hover:bg-slate-50'
              }`}
            >
              <p className="font-semibold text-slate-800">{lang.nativeName}</p>
              <p className="text-sm text-slate-500">{lang.name}</p>
            </button>
          ))}
        </div>
      </div>
    )
  }

  // Mobile variant - Simple select
  if (variant === 'mobile') {
    return (
      <div className="space-y-2">
        <p className="text-sm font-medium text-slate-600 mb-2">Language</p>
        <select
          value={currentLanguage}
          onChange={(e) => handleLanguageChange(e.target.value)}
          className="w-full p-3 border border-slate-200 rounded-lg bg-white text-slate-700"
        >
          {SUPPORTED_LANGUAGES.map((lang) => (
            <option key={lang.code} value={lang.code}>
              {lang.nativeName} ({lang.name})
            </option>
          ))}
        </select>
      </div>
    )
  }

  // Dashboard/Nav variant - Dropdown button
  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 h-10 px-3 bg-white border border-slate-200 rounded-xl hover:border-emerald-400 hover:bg-slate-50 transition-all"
        title="Change Language"
      >
        <Globe className="w-4 h-4 text-emerald-600" />
        <span className="text-sm font-medium text-slate-700 hidden sm:block max-w-[60px] truncate">
          {currentLangData.code.toUpperCase()}
        </span>
        <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-52 bg-white rounded-xl shadow-lg border border-slate-200 py-1 z-[100] max-h-72 overflow-y-auto">
          <div className="px-3 py-2 border-b border-slate-100">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Language</p>
          </div>
          {SUPPORTED_LANGUAGES.map((lang) => (
            <button
              key={lang.code}
              onClick={() => handleLanguageChange(lang.code)}
              className={`w-full flex items-center justify-between px-3 py-2.5 hover:bg-slate-50 transition-colors ${
                currentLanguage === lang.code ? 'bg-emerald-50' : ''
              }`}
            >
              <div className="text-left">
                <p className={`text-sm font-medium ${currentLanguage === lang.code ? 'text-emerald-700' : 'text-slate-700'}`}>
                  {lang.nativeName}
                </p>
                <p className="text-xs text-slate-400">{lang.name}</p>
              </div>
              {currentLanguage === lang.code && (
                <Check className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
