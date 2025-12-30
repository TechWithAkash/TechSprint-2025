'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Mic } from 'lucide-react'
import VoiceExpenseEntry from '@/components/voice/VoiceExpenseEntry'

const triggerHaptic = (intensity = 'medium') => {
  if (typeof window !== 'undefined' && 'vibrate' in navigator) {
    const patterns = {
      light: 10,
      medium: 20,
      heavy: 30
    }
    navigator.vibrate(patterns[intensity] || 20)
  }
}

export default function FABMenu() {
  const [showVoiceModal, setShowVoiceModal] = useState(false)

  const handleFABClick = () => {
    triggerHaptic('heavy')
    setShowVoiceModal(true)
  }

  const handleExpenseAdded = (expense) => {
    console.log('Expense added via voice:', expense)
    setShowVoiceModal(false)
    // Trigger a page refresh or update to show the new expense
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('expenseAdded'))
    }
  }

  return (
    <>
      {/* Simplified FAB Button - Just Voice Entry */}
      <motion.button
        onClick={handleFABClick}
        whileTap={{ scale: 0.9 }}
        whileHover={{ scale: 1.05 }}
        className="lg:hidden fixed bottom-20 right-6 z-50 w-16 h-16 rounded-full bg-gradient-to-br from-green-500 via-emerald-500 to-teal-500 shadow-2xl flex items-center justify-center tap-target group"
        style={{
          filter: 'drop-shadow(0 10px 20px rgba(16, 185, 129, 0.4))',
        }}
      >
        {/* Pulse Animation Ring */}
        <div className="absolute inset-0 rounded-full bg-green-400 animate-ping opacity-30"></div>

        {/* Mic Icon */}
        <Mic className="w-8 h-8 text-white relative z-10 group-hover:scale-110 transition-transform" strokeWidth={2.5} />

        {/* Hover Glow Effect */}
        <div className="absolute inset-0 rounded-full bg-gradient-to-br from-green-300 to-emerald-300 opacity-0 group-hover:opacity-30 transition-opacity blur-xl"></div>
      </motion.button>

      {/* Voice Modal */}
      {showVoiceModal && (
        <VoiceExpenseEntry
          onExpenseAdded={handleExpenseAdded}
          onClose={() => setShowVoiceModal(false)}
        />
      )}
    </>
  )
}
