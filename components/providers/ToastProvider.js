'use client'

import { Toaster } from 'react-hot-toast'

export default function ToastProvider() {
  return (
    <Toaster
      position="top-center"
      reverseOrder={false}
      gutter={8}
      containerClassName=""
      containerStyle={{}}
      toastOptions={{
        // Define default options
        className: '',
        duration: 4000,
        style: {
          background: 'white',
          color: '#363636',
          border: '1px solid #e2e8f0',
          borderRadius: '12px',
          boxShadow: '0 10px 25px rgba(0, 0, 0, 0.1)',
          fontSize: '14px',
          fontWeight: '500',
          padding: '16px',
        },
        // Default options for specific types
        success: {
          duration: 4000,
          style: {
            background: '#f0fdf4',
            border: '1px solid #86efac',
            color: '#15803d',
          },
        },
        error: {
          duration: 5000,
          style: {
            background: '#fef2f2',
            border: '1px solid #fca5a5',
            color: '#dc2626',
          },
        },
        loading: {
          style: {
            background: '#f8fafc',
            border: '1px solid #cbd5e1',
            color: '#475569',
          },
        },
      }}
    />
  )
}
