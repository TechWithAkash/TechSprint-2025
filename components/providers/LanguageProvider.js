'use client'

import React, { createContext, useContext, useEffect, useState } from 'react'

const LanguageContext = createContext()

export const useLanguage = () => {
  const context = useContext(LanguageContext)
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider')
  }
  return context
}

// Supported languages
export const SUPPORTED_LANGUAGES = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'hi', name: 'Hindi', nativeName: 'हिंदी' },
  { code: 'ta', name: 'Tamil', nativeName: 'தமிழ்' },
  { code: 'te', name: 'Telugu', nativeName: 'తెలుగు' },
  { code: 'bn', name: 'Bengali', nativeName: 'বাংলা' },
  { code: 'mr', name: 'Marathi', nativeName: 'मराठी' },
  { code: 'gu', name: 'Gujarati', nativeName: 'ગુજરાતી' },
  { code: 'kn', name: 'Kannada', nativeName: 'ಕನ್ನಡ' },
  { code: 'ml', name: 'Malayalam', nativeName: 'മലയാളം' },
  { code: 'pa', name: 'Punjabi', nativeName: 'ਪੰਜਾਬੀ' }
]

// Clear all Google Translate cookies
const clearGoogleTranslateCookies = () => {
  if (typeof document === 'undefined') return

  const domains = ['', window.location.hostname, '.' + window.location.hostname]
  domains.forEach(domain => {
    document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;${domain ? ` domain=${domain};` : ''}`
  })
}

export const LanguageProvider = ({ children }) => {
  const [currentLanguage, setCurrentLanguage] = useState('en')
  const [isLoaded, setIsLoaded] = useState(false)

  // Initialize - clear cookies and set English as default on first load
  useEffect(() => {
    const saved = localStorage.getItem('wealthwise-language')
    if (saved && saved !== 'en') {
      setCurrentLanguage(saved)
    } else {
      // Default to English - clear any existing translation cookies
      clearGoogleTranslateCookies()
      localStorage.setItem('wealthwise-language', 'en')
    }
    setIsLoaded(true)
  }, [])

  // Load Google Translate script only when needed (not English)
  useEffect(() => {
    if (!isLoaded || currentLanguage === 'en') return

    // Don't reload if already loaded
    if (document.getElementById('gt-script')) return

    const script = document.createElement('script')
    script.id = 'gt-script'
    script.src = 'https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit'
    script.async = true

    window.googleTranslateElementInit = () => {
      if (window.google?.translate) {
        new window.google.translate.TranslateElement({
          pageLanguage: 'en',
          includedLanguages: 'hi,ta,te,bn,mr,gu,kn,ml,pa',
          autoDisplay: false
        }, 'gt-element')
      }
    }

    document.body.appendChild(script)
  }, [isLoaded, currentLanguage])

  // Function to change language
  const changeLanguage = (langCode) => {
    if (langCode === currentLanguage) return

    localStorage.setItem('wealthwise-language', langCode)

    if (langCode === 'en') {
      clearGoogleTranslateCookies()
    } else {
      document.cookie = `googtrans=/en/${langCode}; path=/`
    }

    window.location.reload()
  }

  const value = {
    currentLanguage,
    changeLanguage,
    isLoaded,
    languages: SUPPORTED_LANGUAGES
  }

  return (
    <LanguageContext.Provider value={value}>
      {/* Hidden container for Google Translate - DO NOT REMOVE */}
      <div id="gt-element" style={{ display: 'none', position: 'absolute', left: '-9999px' }} />

      {children}

      {/* CSS to hide ALL Google Translate UI */}
      <style jsx global>{`
        /* HIDE EVERYTHING FROM GOOGLE TRANSLATE */
        #google_translate_element,
        .goog-te-banner-frame,
        .goog-te-balloon-frame,
        .goog-te-menu-frame,
        .goog-te-spinner-pos,
        .goog-te-gadget,
        .goog-te-gadget-simple,
        .goog-te-combo,
        #goog-gt-tt,
        .goog-tooltip,
        .skiptranslate,
        .VIpgJd-ZVi9od-ORHb-OEVmcd,
        .VIpgJd-ZVi9od-l4eHX-hSRGPd,
        .VIpgJd-ZVi9od-aZ2wEe-wOHMyf,
        .VIpgJd-ZVi9od-SmfZ-OEVmcd,
        .VIpgJd-suEOdc,
        [id^="goog-"],
        [class^="goog-"],
        [class*="skiptranslate"],
        iframe.goog-te-banner-frame,
        iframe.skiptranslate {
          display: none !important;
          visibility: hidden !important;
          height: 0 !important;
          width: 0 !important;
          opacity: 0 !important;
          position: absolute !important;
          top: -9999px !important;
          left: -9999px !important;
          pointer-events: none !important;
        }

        /* Fix body positioning */
        body {
          top: 0 !important;
          position: static !important;
          margin-top: 0 !important;
        }

        /* Fix translated text styling */
        font[style], font {
          background-color: transparent !important;
          box-shadow: none !important;
        }
      `}</style>
    </LanguageContext.Provider>
  )
}
