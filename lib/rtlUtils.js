/**
 * RTL (Right-to-Left) language utilities
 * Provides functions to detect RTL languages and apply appropriate styling
 */

// List of RTL language codes
const RTL_LANGUAGES = ['ar', 'he', 'fa', 'ur', 'yi']

/**
 * Check if a language code is RTL
 * @param {string} languageCode - The language code to check
 * @returns {boolean} - True if the language is RTL
 */
export const isRTL = (languageCode) => {
  return RTL_LANGUAGES.includes(languageCode)
}

/**
 * Get the text direction for a language
 * @param {string} languageCode - The language code
 * @returns {string} - 'rtl' or 'ltr'
 */
export const getTextDirection = (languageCode) => {
  return isRTL(languageCode) ? 'rtl' : 'ltr'
}

/**
 * Apply RTL styles to document
 * @param {string} languageCode - The current language code
 */
export const applyRTLStyles = (languageCode) => {
  const direction = getTextDirection(languageCode)
  const htmlElement = document.documentElement
  
  // Set direction attribute
  htmlElement.setAttribute('dir', direction)
  
  // Add/remove RTL class
  if (direction === 'rtl') {
    htmlElement.classList.add('rtl')
    htmlElement.classList.remove('ltr')
  } else {
    htmlElement.classList.add('ltr')
    htmlElement.classList.remove('rtl')
  }
  
  // Set CSS custom property for direction
  htmlElement.style.setProperty('--text-direction', direction)
}

/**
 * Get RTL-aware margin/padding classes
 * @param {string} languageCode - The current language code
 * @returns {object} - Object with RTL-aware class mappings
 */
export const getRTLClasses = (languageCode) => {
  const isRTLLang = isRTL(languageCode)
  
  return {
    // Margin classes
    'ml-auto': isRTLLang ? 'mr-auto' : 'ml-auto',
    'mr-auto': isRTLLang ? 'ml-auto' : 'mr-auto',
    'ml-4': isRTLLang ? 'mr-4' : 'ml-4',
    'mr-4': isRTLLang ? 'ml-4' : 'mr-4',
    'ml-2': isRTLLang ? 'mr-2' : 'ml-2',
    'mr-2': isRTLLang ? 'ml-2' : 'mr-2',
    
    // Padding classes
    'pl-4': isRTLLang ? 'pr-4' : 'pl-4',
    'pr-4': isRTLLang ? 'pl-4' : 'pr-4',
    'pl-2': isRTLLang ? 'pr-2' : 'pl-2',
    'pr-2': isRTLLang ? 'pl-2' : 'pr-2',
    
    // Text alignment
    'text-left': isRTLLang ? 'text-right' : 'text-left',
    'text-right': isRTLLang ? 'text-left' : 'text-right',
    
    // Flexbox
    'justify-start': isRTLLang ? 'justify-end' : 'justify-start',
    'justify-end': isRTLLang ? 'justify-start' : 'justify-end',
    
    // Borders
    'border-l': isRTLLang ? 'border-r' : 'border-l',
    'border-r': isRTLLang ? 'border-l' : 'border-r',
    
    // Rounded corners
    'rounded-l': isRTLLang ? 'rounded-r' : 'rounded-l',
    'rounded-r': isRTLLang ? 'rounded-l' : 'rounded-r',
    'rounded-tl': isRTLLang ? 'rounded-tr' : 'rounded-tl',
    'rounded-tr': isRTLLang ? 'rounded-tl' : 'rounded-tr',
    'rounded-bl': isRTLLang ? 'rounded-br' : 'rounded-bl',
    'rounded-br': isRTLLang ? 'rounded-bl' : 'rounded-br'
  }
}

/**
 * Hook for RTL-aware className generation
 * @param {string} languageCode - The current language code
 * @param {string} baseClasses - Base CSS classes
 * @returns {string} - RTL-aware CSS classes
 */
export const useRTLClasses = (languageCode, baseClasses) => {
  const rtlMappings = getRTLClasses(languageCode)
  
  return baseClasses.split(' ').map(className => {
    return rtlMappings[className] || className
  }).join(' ')
}