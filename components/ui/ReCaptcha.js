'use client'

import { forwardRef, useImperativeHandle, useRef } from 'react'
import ReCAPTCHA from 'react-google-recaptcha'

const ReCaptcha = forwardRef(({ onVerify, onChange, onExpired, onError, theme = 'light', size = 'normal' }, ref) => {
  const recaptchaRef = useRef(null)

  useImperativeHandle(ref, () => ({
    reset: () => {
      if (recaptchaRef.current) {
        recaptchaRef.current.reset()
      }
    },
    getValue: () => {
      if (recaptchaRef.current) {
        return recaptchaRef.current.getValue()
      }
      return null
    }
  }))

  const handleChange = (token) => {
    // Support both onVerify and onChange for backward compatibility
    if (onVerify) {
      onVerify(token)
    }
    if (onChange) {
      onChange(token)
    }
  }

  const handleExpired = () => {
    if (onExpired) {
      onExpired()
    }
  }

  const handleError = () => {
    if (onError) {
      onError()
    }
  }

  return (
    <div className="flex justify-center my-4">
      <ReCAPTCHA
        ref={recaptchaRef}
        sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}
        onChange={handleChange}
        onExpired={handleExpired}
        onError={handleError}
        theme={theme}
        size={size}
      />
    </div>
  )
})

ReCaptcha.displayName = 'ReCaptcha'

export default ReCaptcha