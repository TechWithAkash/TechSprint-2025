import { NextResponse } from 'next/server'

const GOOGLE_TRANSLATE_API_KEY = process.env.GOOGLE_TRANSLATE_API_KEY

export async function POST(request) {
  try {
    const body = await request.json()
    const { text, texts, targetLang } = body

    if (!GOOGLE_TRANSLATE_API_KEY) {
      return NextResponse.json(
        { error: 'Translation API key not configured' },
        { status: 500 }
      )
    }

    if (!targetLang) {
      return NextResponse.json(
        { error: 'Target language is required' },
        { status: 400 }
      )
    }

    // Handle batch translation
    if (texts && Array.isArray(texts)) {
      const translations = await translateBatch(texts, targetLang)
      return NextResponse.json({ translations })
    }

    // Handle single text translation
    if (text) {
      const translatedText = await translateSingle(text, targetLang)
      return NextResponse.json({ translatedText })
    }

    return NextResponse.json(
      { error: 'Text or texts array is required' },
      { status: 400 }
    )

  } catch (error) {
    console.error('Translation API error:', error)
    return NextResponse.json(
      { error: 'Translation failed', details: error.message },
      { status: 500 }
    )
  }
}

async function translateSingle(text, targetLang) {
  const url = `https://translation.googleapis.com/language/translate/v2?key=${GOOGLE_TRANSLATE_API_KEY}`

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      q: text,
      source: 'en',
      target: targetLang,
      format: 'text'
    })
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.error?.message || 'Translation API error')
  }

  const data = await response.json()
  return data.data?.translations?.[0]?.translatedText || text
}

async function translateBatch(texts, targetLang) {
  if (texts.length === 0) return []

  const url = `https://translation.googleapis.com/language/translate/v2?key=${GOOGLE_TRANSLATE_API_KEY}`

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      q: texts,
      source: 'en',
      target: targetLang,
      format: 'text'
    })
  })

  if (!response.ok) {
    const errorData = await response.json()
    console.error('Google Translate API error:', errorData)
    throw new Error(errorData.error?.message || 'Translation API error')
  }

  const data = await response.json()
  const translations = data.data?.translations || []

  return translations.map((t, i) => t.translatedText || texts[i])
}
