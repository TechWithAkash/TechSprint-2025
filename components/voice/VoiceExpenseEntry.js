'use client'

import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { Mic, MicOff, Check, X, Edit3, ChevronDown, RefreshCw, AlertCircle, Sparkles } from 'lucide-react'

// Category options with emojis for selection
const CATEGORY_OPTIONS = [
  { id: 'food', name: 'Food & Dining', emoji: '🍽️', keywords: ['food', 'lunch', 'dinner', 'breakfast', 'chai', 'coffee', 'snack'] },
  { id: 'transport', name: 'Transportation', emoji: '🚗', keywords: ['metro', 'bus', 'uber', 'ola', 'petrol', 'taxi', 'auto'] },
  { id: 'shopping', name: 'Shopping', emoji: '🛍️', keywords: ['clothes', 'shoes', 'amazon', 'flipkart', 'mall'] },
  { id: 'entertainment', name: 'Entertainment', emoji: '🎬', keywords: ['movie', 'netflix', 'game', 'party', 'gym'] },
  { id: 'healthcare', name: 'Healthcare', emoji: '💊', keywords: ['medicine', 'doctor', 'hospital', 'pharmacy'] },
  { id: 'utilities', name: 'Home & Utilities', emoji: '🏠', keywords: ['electricity', 'water', 'gas', 'internet', 'rent', 'bill'] },
  { id: 'other', name: 'Other', emoji: '💳', keywords: [] }
]

export default function VoiceExpenseEntry({ onExpenseAdded, onClose }) {
  const [isListening, setIsListening] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [transcript, setTranscript] = useState('')
  const [processedExpense, setProcessedExpense] = useState(null)
  const [error, setError] = useState('')
  const [confidence, setConfidence] = useState(0)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [audioQuality, setAudioQuality] = useState('good')
  const [transcriptAlternatives, setTranscriptAlternatives] = useState([])
  const [retryCount, setRetryCount] = useState(0)
  const [isVisible, setIsVisible] = useState(false)
  const [isMounted, setIsMounted] = useState(false)

  // Edit mode states
  const [isEditing, setIsEditing] = useState(false)
  const [editAmount, setEditAmount] = useState('')
  const [editCategory, setEditCategory] = useState('')
  const [editDescription, setEditDescription] = useState('')
  const [showCategoryDropdown, setShowCategoryDropdown] = useState(false)

  const recognitionRef = useRef(null)
  const timeoutRef = useRef(null)

  // Entrance animation
  useEffect(() => {
    setIsMounted(true)
    setIsVisible(true)
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [])

  // Initialize speech recognition
  useEffect(() => {
    if (typeof window !== 'undefined' && ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window)) {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
      recognitionRef.current = new SpeechRecognition()

      recognitionRef.current.continuous = false
      recognitionRef.current.interimResults = true
      recognitionRef.current.maxAlternatives = 5
      recognitionRef.current.lang = 'hi-IN'

      recognitionRef.current.onstart = () => {
        setIsListening(true)
        setError('')
        setAudioQuality('good')
      }

      recognitionRef.current.onresult = (event) => {
        let finalTranscript = ''
        let interimTranscript = ''
        const alternatives = []

        for (let i = event.resultIndex; i < event.results.length; i++) {
          const result = event.results[i]
          const transcriptPart = result[0].transcript

          for (let j = 0; j < Math.min(result.length, 3); j++) {
            alternatives.push({
              transcript: result[j].transcript,
              confidence: result[j].confidence
            })
          }

          if (result.isFinal) {
            finalTranscript += transcriptPart
            const avgConfidence = alternatives.reduce((sum, alt) => sum + alt.confidence, 0) / alternatives.length
            if (avgConfidence < 0.5) setAudioQuality('poor')
            else if (avgConfidence < 0.7) setAudioQuality('moderate')
            else setAudioQuality('good')
          } else {
            interimTranscript += transcriptPart
          }
        }

        setTranscript(finalTranscript || interimTranscript)
        setTranscriptAlternatives(alternatives)

        if (finalTranscript) {
          processVoiceInput(finalTranscript, alternatives)
        }
      }

      recognitionRef.current.onerror = (event) => {
        let errorMessage = 'Voice recognition error'
        if (event.error === 'no-speech') {
          errorMessage = 'No speech detected. Please speak clearly and try again.'
        } else if (event.error === 'audio-capture') {
          errorMessage = 'Microphone not accessible. Please check permissions.'
        } else if (event.error === 'network') {
          errorMessage = 'Network error. Please check your connection.'
        } else if (event.error === 'aborted') {
          errorMessage = 'Recording stopped. Please try again.'
        }
        setError(errorMessage)
        setIsListening(false)
        setIsProcessing(false)
      }

      recognitionRef.current.onend = () => {
        setIsListening(false)
      }
    } else {
      setError('Speech recognition not supported. Please use Chrome, Edge, or Safari.')
    }

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [])

  const startListening = () => {
    if (recognitionRef.current) {
      setTranscript('')
      setProcessedExpense(null)
      setError('')
      setShowConfirmation(false)
      setIsEditing(false)
      setTranscriptAlternatives([])

      try {
        recognitionRef.current.start()
        timeoutRef.current = setTimeout(() => {
          stopListening()
          if (!transcript) {
            setError('No speech detected. Please try again.')
          }
        }, 15000)
      } catch (err) {
        setError('Failed to start voice recognition. Please try again.')
      }
    }
  }

  const stopListening = () => {
    if (recognitionRef.current && isListening) {
      recognitionRef.current.stop()
    }
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }
  }

  const processVoiceInput = async (voiceText, alternatives = []) => {
    setIsProcessing(true)

    try {
      const response = await fetch('/api/voice/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          voiceText,
          alternatives: alternatives.map(alt => alt.transcript),
          audioQuality: audioQuality
        }),
      })

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`)
      }

      const data = await response.json()

      if (!data) {
        throw new Error('Empty response from server')
      }

      if (data.success) {
        setProcessedExpense(data.expenseData)
        setConfidence(data.confidence)
        setShowConfirmation(true)
        setError('')
        setRetryCount(0)

        // Pre-fill edit fields
        setEditAmount(data.expenseData.amount?.toString() || '')
        setEditCategory(data.expenseData.category || 'other')
        setEditDescription(data.expenseData.description || '')
      } else {
        if (data.confidence && data.confidence < 0.6 && retryCount < 2) {
          setRetryCount(retryCount + 1)
          setError(`Low confidence (${Math.round(data.confidence * 100)}%). Please speak more clearly.`)
          setTimeout(() => {
            if (!isListening) startListening()
          }, 2000)
        } else {
          setError(data.error || 'Failed to process voice input. Please try manual entry.')
        }
      }
    } catch (err) {
      console.error('Error processing voice:', err)
      setError('Failed to process voice input. Please check your connection.')
    } finally {
      setIsProcessing(false)
    }
  }

  const confirmExpense = async () => {
    if (isSaving) return

    // Use edited values if in edit mode, otherwise use processed values
    const amount = isEditing ? parseFloat(editAmount) : processedExpense?.amount
    const category = isEditing ? editCategory : processedExpense?.category
    const description = isEditing ? editDescription : processedExpense?.description

    if (!amount || amount <= 0) {
      setError('Please enter a valid amount')
      return
    }

    setIsSaving(true)
    setError('')

    try {
      const payload = {
        amount: Number(amount),
        category: category || 'other',
        description: description || '',
        merchant: processedExpense?.merchant || null,
        date: processedExpense?.date || new Date().toISOString().split('T')[0],
        entryMethod: 'voice',
        originalText: processedExpense?.originalText || transcript || null,
        confidence: isEditing ? 1.0 : (processedExpense?.confidence ?? confidence ?? null)
      }

      const res = await fetch('/api/expenses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await res.json()
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to save expense')
      }

      if (onExpenseAdded) onExpenseAdded(data.expense)

      // Reset and close
      setShowConfirmation(false)
      setTranscript('')
      setProcessedExpense(null)
      setIsEditing(false)

      // Show success briefly before closing
      setTimeout(() => onClose?.(), 500)

    } catch (e) {
      console.error('Voice expense save error:', e)
      setError(e.message || 'Failed to save expense')
    } finally {
      setIsSaving(false)
    }
  }

  const toggleEditMode = () => {
    if (!isEditing && processedExpense) {
      setEditAmount(processedExpense.amount?.toString() || '')
      setEditCategory(processedExpense.category || 'other')
      setEditDescription(processedExpense.description || '')
    }
    setIsEditing(!isEditing)
    setShowCategoryDropdown(false)
  }

  const getCategoryDisplay = (categoryId) => {
    return CATEGORY_OPTIONS.find(c => c.id === categoryId) || CATEGORY_OPTIONS[6]
  }

  if (!isMounted) return null

  const modalContent = (
    <div
      className={`fixed inset-0 bg-black/60 backdrop-blur-md flex items-center justify-center z-[9999] p-4 overflow-y-auto transition-opacity duration-300 ${isVisible ? 'opacity-100' : 'opacity-0'}`}
      style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0 }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isListening && !isProcessing && !isSaving) {
          onClose?.()
        }
      }}
    >
      <div
        className={`bg-white rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl my-8 transition-all duration-300 ease-out ${isVisible ? 'scale-100 opacity-100 translate-y-0' : 'scale-95 opacity-0 translate-y-4'}`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="text-center border-b pb-4">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Sparkles className="w-5 h-5 text-emerald-500" />
            <h2 className="text-xl font-bold text-gray-900">Voice Expense Entry</h2>
          </div>
          <p className="text-sm text-gray-600">Speak in Hindi, English, or Hinglish</p>
        </div>

        {/* Voice Input Section */}
        {!showConfirmation && (
          <div className="space-y-4">
            {/* Microphone Button */}
            <div className="flex justify-center py-3">
              <button
                onClick={isListening ? stopListening : startListening}
                disabled={isProcessing}
                className={`relative w-20 h-20 rounded-full flex items-center justify-center transition-all duration-300 shadow-lg ${
                  isListening
                    ? 'bg-gradient-to-br from-red-500 to-red-600 animate-pulse shadow-red-300'
                    : 'bg-gradient-to-br from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 hover:scale-110 shadow-emerald-300'
                } ${isProcessing ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-xl'}`}
              >
                {isListening ? (
                  <MicOff className="w-8 h-8 text-white" />
                ) : (
                  <Mic className="w-8 h-8 text-white" />
                )}
                {isListening && (
                  <>
                    <div className="absolute inset-0 rounded-full border-4 border-red-400 animate-ping opacity-75"></div>
                    <div className="absolute inset-0 rounded-full border-2 border-red-300 animate-pulse"></div>
                  </>
                )}
              </button>
            </div>

            {/* Status */}
            <div className="text-center">
              {isListening && (
                <div className="space-y-2">
                  <p className="text-red-500 font-medium flex items-center justify-center gap-2">
                    <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
                    Listening... Speak now
                  </p>
                  <div className="flex items-center justify-center space-x-2">
                    <div className={`w-2 h-2 rounded-full ${
                      audioQuality === 'good' ? 'bg-green-500' :
                      audioQuality === 'moderate' ? 'bg-yellow-500' : 'bg-red-500'
                    }`}></div>
                    <span className={`text-xs ${
                      audioQuality === 'good' ? 'text-green-600' :
                      audioQuality === 'moderate' ? 'text-yellow-600' : 'text-red-600'
                    }`}>
                      Audio: {audioQuality === 'good' ? 'Clear' : audioQuality === 'moderate' ? 'Moderate' : 'Noisy'}
                    </span>
                  </div>
                </div>
              )}
              {isProcessing && (
                <div className="flex items-center justify-center gap-2 text-emerald-600">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span className="font-medium">Processing with AI...</span>
                </div>
              )}
              {!isListening && !isProcessing && (
                <p className="text-gray-500">Tap microphone to start</p>
              )}
            </div>

            {/* Transcript Display */}
            {transcript && (
              <div className="bg-gray-50 rounded-lg p-3 border">
                <p className="text-xs text-gray-500 mb-1">You said:</p>
                <p className="text-gray-900 font-medium">&quot;{transcript}&quot;</p>
              </div>
            )}

            {/* Example Commands */}
            <div className="bg-gradient-to-br from-emerald-50 to-teal-50 border border-emerald-200 rounded-xl p-4">
              <p className="text-sm text-emerald-700 font-semibold mb-2">Try saying:</p>
              <div className="grid grid-cols-1 gap-1.5 text-xs text-emerald-600">
                <p className="bg-white/60 rounded px-2 py-1">&quot;200 ka dosa khaya&quot;</p>
                <p className="bg-white/60 rounded px-2 py-1">&quot;Metro में 45 rupees&quot;</p>
                <p className="bg-white/60 rounded px-2 py-1">&quot;Swiggy से 180 ka order&quot;</p>
                <p className="bg-white/60 rounded px-2 py-1">&quot;Bought shoes for 500 rupees&quot;</p>
              </div>
            </div>
          </div>
        )}

        {/* Confirmation Section */}
        {showConfirmation && processedExpense && (
          <div className="space-y-4">
            {/* Edit Toggle */}
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-900">
                {isEditing ? 'Edit Expense' : 'Confirm Expense'}
              </h3>
              <button
                onClick={toggleEditMode}
                className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  isEditing
                    ? 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    : 'bg-blue-100 text-blue-700 hover:bg-blue-200'
                }`}
              >
                <Edit3 className="w-3.5 h-3.5" />
                {isEditing ? 'Cancel Edit' : 'Edit'}
              </button>
            </div>

            {/* Expense Details Card */}
            <div className={`rounded-xl p-4 border-2 ${
              isEditing ? 'bg-blue-50 border-blue-200' : 'bg-emerald-50 border-emerald-200'
            }`}>
              {/* Confidence Badge */}
              {!isEditing && (
                <div className="flex justify-end mb-2">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    confidence >= 0.8 ? 'bg-green-100 text-green-700' :
                    confidence >= 0.6 ? 'bg-yellow-100 text-yellow-700' :
                    'bg-orange-100 text-orange-700'
                  }`}>
                    {Math.round(confidence * 100)}% confident
                  </span>
                </div>
              )}

              <div className="space-y-3">
                {/* Amount */}
                <div className="flex items-center justify-between">
                  <span className="text-gray-600 text-sm">Amount</span>
                  {isEditing ? (
                    <div className="flex items-center">
                      <span className="text-gray-500 mr-1">₹</span>
                      <input
                        type="number"
                        value={editAmount}
                        onChange={(e) => setEditAmount(e.target.value)}
                        className="w-24 px-2 py-1 border rounded-lg text-right font-bold text-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="0"
                      />
                    </div>
                  ) : (
                    <span className="font-bold text-xl text-emerald-700">₹{processedExpense.amount}</span>
                  )}
                </div>

                {/* Category */}
                <div className="flex items-center justify-between">
                  <span className="text-gray-600 text-sm">Category</span>
                  {isEditing ? (
                    <div className="relative">
                      <button
                        onClick={() => setShowCategoryDropdown(!showCategoryDropdown)}
                        className="flex items-center gap-2 px-3 py-1.5 border rounded-lg bg-white hover:bg-gray-50 transition-colors"
                      >
                        <span>{getCategoryDisplay(editCategory).emoji}</span>
                        <span className="font-medium">{getCategoryDisplay(editCategory).name}</span>
                        <ChevronDown className="w-4 h-4 text-gray-400" />
                      </button>

                      {showCategoryDropdown && (
                        <div className="absolute right-0 mt-1 w-48 bg-white border rounded-xl shadow-lg z-10 py-1 max-h-60 overflow-y-auto">
                          {CATEGORY_OPTIONS.map((cat) => (
                            <button
                              key={cat.id}
                              onClick={() => {
                                setEditCategory(cat.id)
                                setShowCategoryDropdown(false)
                              }}
                              className={`w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-100 transition-colors ${
                                editCategory === cat.id ? 'bg-emerald-50 text-emerald-700' : ''
                              }`}
                            >
                              <span>{cat.emoji}</span>
                              <span className="text-sm">{cat.name}</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{processedExpense.categoryInfo?.emoji}</span>
                      <span className="font-medium">{processedExpense.categoryInfo?.englishName}</span>
                    </div>
                  )}
                </div>

                {/* Description */}
                <div className="flex items-center justify-between">
                  <span className="text-gray-600 text-sm">Description</span>
                  {isEditing ? (
                    <input
                      type="text"
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      className="w-40 px-2 py-1 border rounded-lg text-right text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Enter description"
                    />
                  ) : (
                    <span className="font-medium text-sm">{processedExpense.description || '-'}</span>
                  )}
                </div>

                {/* Merchant (if detected) */}
                {processedExpense.merchant && !isEditing && (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 text-sm">Merchant</span>
                    <span className="font-medium text-sm">{processedExpense.merchant}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Original Voice Text */}
            <div className="bg-gray-50 rounded-lg p-2.5 border">
              <p className="text-xs text-gray-500 mb-0.5">Original voice input:</p>
              <p className="text-sm text-gray-700">&quot;{processedExpense.originalText}&quot;</p>
            </div>

            {/* Low Confidence Warning */}
            {confidence < 0.7 && !isEditing && (
              <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg p-3">
                <AlertCircle className="w-4 h-4 text-amber-600 mt-0.5 flex-shrink-0" />
                <div className="text-xs text-amber-700">
                  <p className="font-medium">Low confidence detection</p>
                  <p>Please verify the details above or tap Edit to correct them.</p>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex gap-3">
              <button
                onClick={confirmExpense}
                disabled={isSaving}
                className={`flex-1 py-3 px-4 rounded-xl font-medium flex items-center justify-center text-white transition-all ${
                  isSaving
                    ? 'bg-emerald-400 cursor-not-allowed'
                    : 'bg-emerald-500 hover:bg-emerald-600 hover:shadow-lg'
                }`}
              >
                {isSaving ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Check className="w-4 h-4 mr-2" />
                )}
                {isSaving ? 'Saving...' : (isEditing ? 'Save Changes' : 'Confirm & Add')}
              </button>

              <button
                onClick={() => {
                  setShowConfirmation(false)
                  setProcessedExpense(null)
                  setIsEditing(false)
                }}
                disabled={isSaving}
                className="py-3 px-4 rounded-xl font-medium bg-gray-100 hover:bg-gray-200 text-gray-700 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
            <p className="text-red-700 text-sm">{error}</p>
          </div>
        )}

        {/* Close Button */}
        <div className="flex justify-center pt-2 border-t">
          <button
            onClick={onClose}
            disabled={isListening || isSaving}
            className={`text-gray-500 hover:text-gray-700 flex items-center py-2 px-4 rounded-lg transition-all hover:bg-gray-100 ${
              (isListening || isSaving) ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            <X className="w-4 h-4 mr-1" />
            Close
          </button>
        </div>
      </div>
    </div>
  )

  return createPortal(modalContent, document.body)
}
