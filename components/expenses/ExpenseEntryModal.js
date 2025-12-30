'use client'

import { useState } from 'react'
import VoiceExpenseEntry from '@/components/voice/VoiceExpenseEntry'
import ManualExpenseEntry from '@/components/expenses/ManualExpenseEntry'

export default function ExpenseEntryModal({ isOpen, onClose, onExpenseAdded }) {
  const [entryMode, setEntryMode] = useState('voice') // 'voice' or 'manual'

  if (!isOpen) return null

  const handleExpenseAdded = (expense) => {
    if (onExpenseAdded) {
      onExpenseAdded(expense)
    }
    if (onClose) {
      onClose()
    }
  }

  const switchToManual = () => {
    setEntryMode('manual')
  }

  const switchToVoice = () => {
    setEntryMode('voice')
  }

  const handleClose = () => {
    setEntryMode('voice') // Reset to voice for next time
    if (onClose) {
      onClose()
    }
  }

  return (
    <>
      {entryMode === 'voice' ? (
        <VoiceExpenseEntry
          onExpenseAdded={handleExpenseAdded}
          onClose={handleClose}
        />
      ) : (
        <ManualExpenseEntry
          onExpenseAdded={handleExpenseAdded}
          onVoiceEntry={switchToVoice}
          onClose={handleClose}
        />
      )}
    </>
  )
}
