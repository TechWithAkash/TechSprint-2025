// Enhanced Language Detection Utility
// Supports browser locale, geolocation, and user preference detection

export class LanguageDetector {
  constructor() {
    this.supportedLanguages = ['en', 'hi', 'es', 'fr', 'de', 'ja', 'zh', 'ar', 'he']
    
    // Country to language mapping for geolocation-based detection
    this.countryLanguageMap = {
      'US': 'en', 'GB': 'en', 'AU': 'en', 'CA': 'en', 'NZ': 'en',
      'IN': 'hi',
      'ES': 'es', 'MX': 'es', 'AR': 'es', 'CO': 'es', 'PE': 'es', 'VE': 'es',
      'FR': 'fr', 'BE': 'fr', 'CH': 'fr', 'CA': 'fr',
      'DE': 'de', 'AT': 'de', 'CH': 'de',
      'JP': 'ja',
      'CN': 'zh', 'TW': 'zh', 'HK': 'zh', 'SG': 'zh',
      'SA': 'ar', 'AE': 'ar', 'EG': 'ar', 'JO': 'ar', 'LB': 'ar', 'SY': 'ar',
      'IQ': 'ar', 'KW': 'ar', 'QA': 'ar', 'BH': 'ar', 'OM': 'ar', 'YE': 'ar',
      'MA': 'ar', 'TN': 'ar', 'DZ': 'ar', 'LY': 'ar', 'SD': 'ar',
      'IL': 'he'
    }
    
    // Browser language to supported language mapping
    this.browserLanguageMap = {
      'en': 'en', 'en-US': 'en', 'en-GB': 'en', 'en-AU': 'en', 'en-CA': 'en',
      'hi': 'hi', 'hi-IN': 'hi',
      'es': 'es', 'es-ES': 'es', 'es-MX': 'es', 'es-AR': 'es',
      'fr': 'fr', 'fr-FR': 'fr', 'fr-CA': 'fr', 'fr-BE': 'fr',
      'de': 'de', 'de-DE': 'de', 'de-AT': 'de', 'de-CH': 'de',
      'ja': 'ja', 'ja-JP': 'ja',
      'zh': 'zh', 'zh-CN': 'zh', 'zh-TW': 'zh', 'zh-HK': 'zh',
      'ar': 'ar', 'ar-SA': 'ar', 'ar-AE': 'ar', 'ar-EG': 'ar',
      'he': 'he', 'he-IL': 'he'
    }
  }

  // Get browser language preference
  getBrowserLanguage() {
    try {
      const browserLang = navigator.language || navigator.languages?.[0]
      if (!browserLang) return null
      
      // Check exact match first
      if (this.browserLanguageMap[browserLang]) {
        return this.browserLanguageMap[browserLang]
      }
      
      // Check language code only (e.g., 'en' from 'en-US')
      const langCode = browserLang.split('-')[0]
      if (this.browserLanguageMap[langCode]) {
        return this.browserLanguageMap[langCode]
      }
      
      return null
    } catch (error) {
      console.warn('Failed to detect browser language:', error)
      return null
    }
  }

  // Get user's country using geolocation API
  async getCountryFromGeolocation() {
    return new Promise((resolve) => {
      if (!navigator.geolocation) {
        resolve(null)
        return
      }

      const timeout = setTimeout(() => {
        resolve(null)
      }, 5000) // 5 second timeout

      navigator.geolocation.getCurrentPosition(
        async (position) => {
          clearTimeout(timeout)
          try {
            const { latitude, longitude } = position.coords
            const country = await this.getCountryFromCoordinates(latitude, longitude)
            resolve(country)
          } catch (error) {
            console.warn('Failed to get country from coordinates:', error)
            resolve(null)
          }
        },
        (error) => {
          clearTimeout(timeout)
          console.warn('Geolocation error:', error)
          resolve(null)
        },
        {
          timeout: 5000,
          enableHighAccuracy: false,
          maximumAge: 300000 // 5 minutes cache
        }
      )
    })
  }

  // Get country from coordinates using reverse geocoding
  async getCountryFromCoordinates(latitude, longitude) {
    try {
      // Using a free geocoding service (you might want to use a more reliable one)
      const response = await fetch(
        `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${latitude}&longitude=${longitude}&localityLanguage=en`
      )
      
      if (!response.ok) {
        throw new Error('Geocoding API failed')
      }
      
      const data = await response.json()
      return data.countryCode || null
    } catch (error) {
      console.warn('Failed to get country from coordinates:', error)
      return null
    }
  }

  // Get language from IP-based geolocation (fallback)
  async getLanguageFromIP() {
    try {
      const response = await fetch('https://ipapi.co/json/')
      if (!response.ok) {
        throw new Error('IP geolocation API failed')
      }
      
      const data = await response.json()
      const countryCode = data.country_code
      
      if (countryCode && this.countryLanguageMap[countryCode]) {
        return this.countryLanguageMap[countryCode]
      }
      
      return null
    } catch (error) {
      console.warn('Failed to get language from IP:', error)
      return null
    }
  }

  // Get stored user preference
  getStoredLanguage() {
    try {
      const stored = localStorage.getItem('preferred-language')
      if (stored && this.supportedLanguages.includes(stored)) {
        return stored
      }
      return null
    } catch (error) {
      console.warn('Failed to get stored language:', error)
      return null
    }
  }

  // Detect best language with priority order
  async detectLanguage() {
    const detectionMethods = [
      // 1. User's stored preference (highest priority)
      () => this.getStoredLanguage(),
      
      // 2. Browser language preference
      () => this.getBrowserLanguage(),
      
      // 3. Geolocation-based detection
      async () => {
        const country = await this.getCountryFromGeolocation()
        return country && this.countryLanguageMap[country] ? this.countryLanguageMap[country] : null
      },
      
      // 4. IP-based geolocation (fallback)
      () => this.getLanguageFromIP()
    ]

    for (const method of detectionMethods) {
      try {
        const result = await method()
        if (result && this.supportedLanguages.includes(result)) {
          return {
            language: result,
            confidence: this.getConfidenceScore(result),
            source: this.getDetectionSource(method)
          }
        }
      } catch (error) {
        console.warn('Language detection method failed:', error)
        continue
      }
    }

    // Default fallback
    return {
      language: 'en',
      confidence: 0.1,
      source: 'default'
    }
  }

  // Get confidence score based on detection method
  getConfidenceScore(language) {
    // This could be enhanced with more sophisticated scoring
    const scores = {
      'en': 0.9, // English is widely understood
      'hi': 0.8, // Hindi for Indian users
      'es': 0.7, // Spanish
      'fr': 0.7, // French
      'de': 0.7, // German
      'ja': 0.6, // Japanese
      'zh': 0.6, // Chinese
      'ar': 0.7, // Arabic
      'he': 0.6  // Hebrew
    }
    return scores[language] || 0.5
  }

  // Get detection source name
  getDetectionSource(method) {
    const methodName = method.name || method.toString()
    if (methodName.includes('getStoredLanguage')) return 'stored_preference'
    if (methodName.includes('getBrowserLanguage')) return 'browser_locale'
    if (methodName.includes('getCountryFromGeolocation')) return 'geolocation'
    if (methodName.includes('getLanguageFromIP')) return 'ip_geolocation'
    return 'unknown'
  }

  // Check if RTL language
  isRTL(language) {
    const rtlLanguages = ['ar', 'he', 'fa', 'ur']
    return rtlLanguages.includes(language)
  }

  // Get language display info
  getLanguageInfo(code) {
    const languageInfo = {
      'en': { name: 'English', nativeName: 'English', flag: '🇺🇸', rtl: false },
      'hi': { name: 'Hindi', nativeName: 'हिंदी', flag: '🇮🇳', rtl: false },
      'es': { name: 'Spanish', nativeName: 'Español', flag: '🇪🇸', rtl: false },
      'fr': { name: 'French', nativeName: 'Français', flag: '🇫🇷', rtl: false },
      'de': { name: 'German', nativeName: 'Deutsch', flag: '🇩🇪', rtl: false },
      'ja': { name: 'Japanese', nativeName: '日本語', flag: '🇯🇵', rtl: false },
      'zh': { name: 'Chinese', nativeName: '中文', flag: '🇨🇳', rtl: false },
      'ar': { name: 'Arabic', nativeName: 'العربية', flag: '🇸🇦', rtl: true },
      'he': { name: 'Hebrew', nativeName: 'עברית', flag: '🇮🇱', rtl: true }
    }
    
    return languageInfo[code] || languageInfo['en']
  }
}

// Singleton instance
export const languageDetector = new LanguageDetector()

// Utility function for easy detection
export async function detectUserLanguage() {
  return await languageDetector.detectLanguage()
}

// Utility function to get language info
export function getLanguageInfo(code) {
  return languageDetector.getLanguageInfo(code)
}

// Utility function to check RTL
export function isRTLLanguage(code) {
  return languageDetector.isRTL(code)
}