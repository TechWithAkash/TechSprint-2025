'use client'

import { createContext, useContext, useEffect, useState } from 'react'
import Script from 'next/script'

const GoogleTranslateContext = createContext()

export const useGoogleTranslate = () => {
  const context = useContext(GoogleTranslateContext)
  if (!context) {
    throw new Error('useGoogleTranslate must be used within GoogleTranslateProvider')
  }
  return context
}

export default function GoogleTranslateProvider({ children }) {
  const [isReady, setIsReady] = useState(false)
  const [currentLanguage, setCurrentLanguage] = useState('en')

  useEffect(() => {
    // Load saved language preference
    const saved = localStorage.getItem('preferred-language')
    if (saved) {
      setCurrentLanguage(saved)
    }
  }, [])

  // Initialize Google Translate
  useEffect(() => {
    window.googleTranslateElementInit = () => {
      if (window.google && window.google.translate) {
        new window.google.translate.TranslateElement(
          {
            pageLanguage: 'en',
            includedLanguages: 'en,hi,ta,te,bn,mr,gu,kn,ml,pa', // Indian languages
            layout: window.google.translate.TranslateElement.InlineLayout.SIMPLE,
            autoDisplay: false,
          },
          'google_translate_element'
        )
        setIsReady(true)
      }
    }

    // Clean up any existing translate elements
    return () => {
      const element = document.getElementById('google_translate_element')
      if (element) {
        element.innerHTML = ''
      }
    }
  }, [])

  const changeLanguage = (langCode) => {
    setCurrentLanguage(langCode)
    localStorage.setItem('preferred-language', langCode)

    // Trigger Google Translate
    const select = document.querySelector('.goog-te-combo')
    if (select) {
      select.value = langCode
      select.dispatchEvent(new Event('change'))
    }
  }

  const value = {
    isReady,
    currentLanguage,
    changeLanguage,
    isHindi: currentLanguage === 'hi',
    isEnglish: currentLanguage === 'en'
  }

  return (
    <GoogleTranslateContext.Provider value={value}>
      {/* Hidden Google Translate Element */}
      <div id="google_translate_element" className="hidden" />

      {/* Google Translate Script */}
      <Script
        src="//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"
        strategy="afterInteractive"
      />

      {/* Hide Google Translate banner/toolbar */}
      <style jsx global>{`
        .goog-te-banner-frame,
        .goog-te-balloon-frame,
        #goog-gt-tt,
        .goog-te-balloon-frame {
          display: none !important;
        }

        body {
          top: 0 !important;
        }

        .goog-te-gadget {
          font-size: 0 !important;
        }

        .goog-te-combo {
          display: none !important;
        }

        .skiptranslate {
          display: none !important;
        }

        body > .skiptranslate {
          display: none !important;
        }

        .goog-logo-link {
          display: none !important;
        }

        .goog-te-gadget span {
          display: none !important;
        }
      `}</style>

      {children}
    </GoogleTranslateContext.Provider>
  )
}
