import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import dbConnect from '@/lib/dbConnect'
import UserProfile from '@/models/UserProfile'
import { voiceProcessor } from '@/lib/voiceProcessor'

// POST - Process voice input for expense entry
export async function POST(request) {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { voiceText } = await request.json()
    
    if (!voiceText || typeof voiceText !== 'string') {
      return NextResponse.json(
        { error: 'Voice text is required' },
        { status: 400 }
      )
    }

    console.log('Processing voice input:', voiceText)

    // Process voice input to extract expense data
    const result = await voiceProcessor.processVoiceInput(voiceText)
    
    if (!result.success) {
      return NextResponse.json(
        { error: result.error || 'Failed to process voice input' },
        { status: 400 }
      )
    }

    // Validate the extracted data
    const validation = voiceProcessor.validateExpenseData(result.data)
    if (!validation.isValid) {
      return NextResponse.json(
        { 
          error: 'Invalid expense data extracted',
          details: validation.errors,
          extractedData: result.data
        },
        { status: 400 }
      )
    }

    // Get category display information
    const categoryInfo = voiceProcessor.getCategoryInfo(result.data.category)

    // Prepare the response with extracted expense data
    const expenseData = {
      amount: result.data.amount,
      category: result.data.category,
      categoryInfo: categoryInfo,
      merchant: result.data.merchant,
      description: result.data.description,
      originalText: result.data.originalText,
      processingMethod: result.data.method,
      confidence: result.confidence,
      date: new Date().toISOString().split('T')[0], // Today's date
      timestamp: new Date()
    }

    console.log('Successfully processed voice input:', expenseData)

    return NextResponse.json({
      success: true,
      message: 'Voice input processed successfully',
      expenseData: expenseData,
      confidence: result.confidence
    })

  } catch (error) {
    console.error('Voice processing API error:', error)
    return NextResponse.json(
      { error: 'Failed to process voice input', details: error.message },
      { status: 500 }
    )
  }
}

// GET - Get voice processing statistics
export async function GET() {
  try {
    const session = await auth()
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    await dbConnect()

    // Return voice processing capabilities and stats
    return NextResponse.json({
      success: true,
      capabilities: {
        languages: ['Hindi', 'English', 'Hinglish'],
        supportedFormats: [
          'आज पचास रुपए चाय पी',
          'Metro में ₹45 spend kiya', 
          'Bought lunch for 200 rupees',
          'Swiggy से ₹180 का order'
        ],
        categories: [
          { id: 'food', name: 'Food & Dining', emoji: '🍽️' },
          { id: 'transport', name: 'Transportation', emoji: '🚗' },
          { id: 'entertainment', name: 'Entertainment', emoji: '🎬' },
          { id: 'shopping', name: 'Shopping', emoji: '👕' },
          { id: 'healthcare', name: 'Healthcare', emoji: '💊' },
          { id: 'utilities', name: 'Home & Utilities', emoji: '🏠' }
        ]
      }
    })

  } catch (error) {
    console.error('Voice processing info error:', error)
    return NextResponse.json(
      { error: 'Failed to get voice processing info' },
      { status: 500 }
    )
  }
}
