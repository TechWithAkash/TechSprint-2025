// Voice Processing for Hindi, Hinglish, and English Expense Entry
// lib/voiceProcessor.js
import { GoogleGenerativeAI } from '@google/generative-ai'

export class VoiceExpenseProcessor {
  constructor() {
    // Bug fix: Validate GEMINI_API_KEY before initializing
    if (!process.env.GEMINI_API_KEY) {
      console.warn('⚠️ GEMINI_API_KEY not set. Voice processing will use fallback mode.')
      this.genAI = null
      this.model = null
    } else {
      this.genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
      // Use gemini-2.5-flash as the stable model
      this.model = this.genAI.getGenerativeModel({ model: "gemini-2.5-flash" })
    }

    // Enhanced financial terms dictionary for better recognition
    this.financialTerms = {
      hindi: ['रुपए', 'रुपये', 'खर्च', 'खरीदा', 'पैसे', 'लिया', 'दिया', 'भुगतान', 'दे दिया', 'खर्चे'],
      english: ['rupees', 'spent', 'bought', 'paid', 'cost', 'money', 'expense', 'rs', 'inr'],

      // Hindi number words for amount extraction
      hindiNumbers: {
        'एक': 1, 'दो': 2, 'तीन': 3, 'चार': 4, 'पांच': 5, 'पाँच': 5,
        'छह': 6, 'सात': 7, 'आठ': 8, 'नौ': 9, 'दस': 10,
        'बीस': 20, 'तीस': 30, 'चालीस': 40, 'पचास': 50,
        'साठ': 60, 'सत्तर': 70, 'अस्सी': 80, 'नब्बे': 90,
        'सौ': 100, 'हजार': 1000, 'लाख': 100000
      },

      // Action verbs that indicate consumption/purchase
      actionVerbs: {
        food: ['खाया', 'खाई', 'खा', 'पिया', 'पी', 'खरीदा', 'मंगाया', 'ate', 'eat', 'drink', 'had', 'ordered'],
        transport: ['गया', 'आया', 'लिया', 'बुक', 'booked', 'took', 'traveled', 'ride'],
        shopping: ['खरीदा', 'लिया', 'दिया', 'bought', 'purchased', 'buy', 'लिए', 'दिए'],
        entertainment: ['देखा', 'देखी', 'खेला', 'watched', 'played', 'saw'],
        healthcare: ['लिया', 'खरीदा', 'bought', 'consulted', 'visited'],
        utilities: ['भरा', 'paid', 'recharged', 'recharge']
      },

      merchants: ['swiggy', 'zomato', 'uber', 'ola', 'amazon', 'flipkart', 'paytm', 'blinkit', 'zepto', 'dunzo', 'rapido'],

      // Comprehensive category keywords (expanded for Indian context)
      categories: {
        food: [
          // General food terms
          'खाना', 'खाने', 'भोजन', 'food', 'lunch', 'breakfast', 'dinner', 'snack', 'snacks',
          // Drinks
          'चाय', 'tea', 'coffee', 'कॉफी', 'chai', 'juice', 'जूस', 'lassi', 'लस्सी', 'milk', 'दूध',
          // Indian dishes
          'dosa', 'डोसा', 'idli', 'इडली', 'vada', 'वड़ा', 'biryani', 'बिरयानी',
          'paratha', 'पराठा', 'roti', 'रोटी', 'naan', 'नान', 'rice', 'चावल',
          'dal', 'दाल', 'curry', 'करी', 'sabzi', 'सब्जी', 'samosa', 'समोसा',
          'pakora', 'पकोड़ा', 'chaat', 'चाट', 'pav', 'bhaji', 'वड़ा पाव',
          // Meals
          'thali', 'थाली', 'combo', 'meal', 'मील',
          // Restaurant/Delivery
          'restaurant', 'रेस्टोरेंट', 'cafe', 'कैफे', 'dhaba', 'ढाबा',
          'order', 'ऑर्डर', 'delivery', 'डिलीवरी', 'takeaway', 'टेकअवे'
        ],
        transport: [
          'metro', 'मेट्रो', 'bus', 'बस', 'auto', 'ऑटो', 'rickshaw', 'रिक्शा',
          'uber', 'ola', 'taxi', 'टैक्सी', 'cab', 'कैब',
          'petrol', 'पेट्रोल', 'diesel', 'डीजल', 'fuel', 'फ्यूल',
          'parking', 'पार्किंग', 'toll', 'टोल',
          'train', 'ट्रेन', 'flight', 'फ्लाइट', 'ticket', 'टिकट',
          'यातायात', 'travel', 'trip', 'ride', 'रेप', 'rapido', 'bike'
        ],
        entertainment: [
          'movie', 'मूवी', 'cinema', 'सिनेमा', 'film', 'फिल्म', 'show', 'शो',
          'gaming', 'game', 'गेम', 'मनोरंजन', 'entertainment',
          'netflix', 'amazon prime', 'hotstar', 'ott', 'subscription',
          'concert', 'event', 'इवेंट', 'party', 'पार्टी',
          'sports', 'स्पोर्ट्स', 'gym', 'जिम', 'membership'
        ],
        shopping: [
          'कपड़े', 'clothes', 'shirt', 'शर्ट', 'pant', 'pants', 'jeans',
          'shoes', 'जूते', 'शूज', 'chappal', 'चप्पल', 'sandal', 'सैंडल',
          'shopping', 'शॉपिंग', 'mall', 'मॉल', 'market', 'मार्केट',
          'amazon', 'flipkart', 'myntra', 'ajio',
          'dress', 'ड्रेस', 'saree', 'साड़ी', 'kurta', 'कुर्ता',
          'watch', 'घड़ी', 'bag', 'बैग', 'wallet', 'वॉलेट',
          'electronics', 'mobile', 'मोबाइल', 'phone', 'laptop', 'लैपटॉप',
          'नया', 'new', 'पुराना', 'old', 'सामान', 'item', 'चीज'
        ],
        healthcare: [
          'medicine', 'दवाई', 'दवा', 'tablet', 'टैबलेट',
          'doctor', 'डॉक्टर', 'hospital', 'हॉस्पिटल', 'clinic', 'क्लिनिक',
          'pharmacy', 'medical', 'मेडिकल', 'checkup', 'चेकअप',
          'test', 'टेस्ट', 'lab', 'लैब', 'xray', 'scan', 'स्कैन',
          'health', 'स्वास्थ्य', 'treatment', 'इलाज', 'consultation'
        ],
        utilities: [
          'बिजली', 'electricity', 'bijli', 'power', 'पावर',
          'water', 'पानी', 'gas', 'गैस', 'cylinder', 'सिलेंडर',
          'internet', 'इंटरनेट', 'wifi', 'broadband',
          'mobile', 'मोबाइल', 'recharge', 'रिचार्ज',
          'bill', 'बिल', 'rent', 'किराया', 'maintenance'
        ]
      }
    }
  }

  // Process voice input and extract expense data
  async processVoiceInput(voiceText) {
    try {
      console.log('Processing voice input:', voiceText)

      // First try rule-based extraction for common patterns
      const ruleBasedResult = this.extractWithRules(voiceText)
      if (ruleBasedResult.confidence > 0.8) {
        return ruleBasedResult
      }

      // Fallback to AI processing for complex cases
      return await this.extractWithAI(voiceText)

    } catch (error) {
      console.error('Voice processing error:', error)
      return {
        success: false,
        error: 'Failed to process voice input',
        confidence: 0
      }
    }
  }

  // Parse Hindi number words to digits
  parseHindiNumber(text) {
    const normalizedText = text.toLowerCase()
    let amount = null

    // Check for Hindi number words
    for (const [word, value] of Object.entries(this.financialTerms.hindiNumbers)) {
      const pattern = new RegExp(`(${word})\\s*(?:रुपए|रुपये|का|की|के)`, 'i')
      const match = normalizedText.match(pattern)
      if (match) {
        amount = value
        break
      }
    }

    // Handle compound numbers like "हजार रुपए" (thousand rupees)
    const compoundPattern = /(एक\s*)?हजार\s*(?:रुपए|रुपये)/i
    if (compoundPattern.test(normalizedText)) {
      amount = 1000
    }

    // Handle "पचास हजार" (fifty thousand), etc.
    const hindiNumberWords = Object.keys(this.financialTerms.hindiNumbers).join('|')
    const complexPattern = new RegExp(`(${hindiNumberWords})\\s*(हजार|सौ|लाख)`, 'i')
    const complexMatch = normalizedText.match(complexPattern)
    if (complexMatch) {
      const multiplier = this.financialTerms.hindiNumbers[complexMatch[1]] || 1
      const base = this.financialTerms.hindiNumbers[complexMatch[2]] || 1
      amount = multiplier * base
    }

    return amount
  }

  // Rule-based extraction for common patterns
  extractWithRules(text) {
    const normalizedText = text.toLowerCase()

    // First try to parse Hindi number words
    let amount = this.parseHindiNumber(text)

    // If no Hindi number found, try numeric patterns
    if (!amount) {
      const amountPatterns = [
        // Standard patterns
        /(?:₹|rs\.?|rupees?)\s*(\d+(?:,\d{3})*(?:\.\d{2})?)/i,
        /(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(?:₹|rs\.?|rupees?|रुपए|रुपये)/i,
        /(\d+)\s*(?:का|की|के|spend|spent|खर्च)/i,
        // English patterns - "bought X of Y rupees" or "spent Y on X"
        /(?:bought|spent|paid|cost)\s+.*?(?:of|for)?\s*(\d+)\s*(?:rupees?|rs\.?|₹)/i,
        // "X rupees for Y" or "X rupees on Y"
        /(\d+)\s*(?:rupees?|rs\.?|₹)?\s*(?:for|on|in)/i,
        // Simple "X rupees" anywhere in sentence
        /(\d+)\s*rupees?/i,
        // "of X rupees" pattern
        /of\s+(\d+)\s*rupees?/i
      ]

      for (const pattern of amountPatterns) {
        const match = text.match(pattern)
        if (match) {
          amount = parseFloat(match[1].replace(/,/g, ''))
          break
        }
      }
    }

    if (!amount) {
      return { success: false, confidence: 0, error: 'No amount found' }
    }

    // Category detection
    const category = this.detectCategory(normalizedText)

    // Merchant detection
    const merchant = this.detectMerchant(normalizedText)

    return {
      success: true,
      confidence: 0.9,
      data: {
        amount: amount,
        category: category || 'other',
        merchant: merchant || null,
        description: text.trim(),
        originalText: text,
        method: 'rule-based'
      }
    }
  }

  // AI-powered extraction for complex cases with enhanced prompts
  async extractWithAI(text) {
    try {
      const prompt = `
You are an expert expense categorizer for Indian users who speak Hindi, English, and Hinglish. Extract expense information from: "${text}"

CRITICAL RULES FOR HINDI NUMBER WORDS:
- हजार = 1000 (thousand)
- सौ = 100 (hundred)
- पचास = 50 (fifty)
- बीस = 20 (twenty)
- दस = 10 (ten)
- Examples: "हजार रुपए" = 1000, "पचास रुपए" = 50, "दो सौ" = 200

IMPORTANT CONTEXT:
- Users mix Hindi, English, Hinglish freely
- Action verbs indicate category: खाया/ate (food), गया/went (transport), खरीदा/bought (shopping), दिया/gave (shopping)
- Hindi words for shopping: शूज (shoes), कपड़े (clothes), जूते (shoes), नया (new)
- Common patterns: "[number word] रुपए का [item] [action]" or "[item] के लिए [number word] रुपए"
- English patterns: "bought [item] of [amount] rupees" or "spent [amount] on [item]"

CATEGORIZATION RULES (STRICTLY FOLLOW):
1. **food**: Any edible item, drinks, restaurants, food delivery
   - Keywords: खाना, dosa, idli, chai, coffee, lunch, dinner, breakfast
   - Actions: खाया, खाई, पिया, मंगाया, ate, drink, ordered
   - Example: "dosa khaya" → food

2. **transport**: Travel, commute, fuel, parking, ride services
   - Keywords: metro, bus, auto, uber, ola, petrol, taxi
   - Actions: गया, आया, traveled, booked
   - Example: "metro me gaya" → transport

3. **shopping**: Clothes, accessories, electronics, online shopping
   - Keywords: कपड़े, shoes, शूज, जूते, amazon, flipkart, mall, नया (new), bought, purchased
   - Actions: खरीदा, लिया, दिया, bought, purchased, buy
   - Example: "bought new shoes" → shopping, "नया शूज दिया" → shopping

4. **entertainment**: Movies, games, OTT, events, gym
   - Keywords: movie, cinema, game, netflix, gym, party
   - Actions: देखा, watched, played
   
5. **healthcare**: Medicine, doctor, hospital, tests
   - Keywords: दवाई, medicine, doctor, hospital, pharmacy
   - Actions: लिया, consulted, visited

6. **utilities**: Bills, electricity, water, internet, rent
   - Keywords: बिजली, electricity, water, gas, internet, bill
   - Actions: भरा, paid, recharged

EXAMPLES (LEARN FROM THESE):
✓ "bought new shoes of 200 rupees" → {"amount": 200, "category": "shopping", "merchant": null, "description": "New shoes", "confidence": 0.95}
✓ "spent 500 on petrol" → {"amount": 500, "category": "transport", "merchant": null, "description": "Petrol", "confidence": 0.95}
✓ "200 ka dosa khaya" → {"amount": 200, "category": "food", "merchant": null, "description": "Dosa", "confidence": 0.95}
✓ "Metro में 45 spend kiya" → {"amount": 45, "category": "transport", "merchant": "Metro", "description": "Metro travel", "confidence": 0.9}
✓ "Swiggy से biryani order 350 ka" → {"amount": 350, "category": "food", "merchant": "Swiggy", "description": "Biryani from Swiggy", "confidence": 0.95}

AMOUNT EXTRACTION:
- Look for: digits (100, 200), Hindi number words (हजार, सौ, पचास)
- Convert: हजार→1000, सौ→100, पचास→50, बीस→20
- If amount is in words, convert to number

Return ONLY valid JSON (no markdown code blocks, no extra text):
{
  "amount": number (in rupees, convert from Hindi words if needed),
  "category": "food" | "transport" | "entertainment" | "shopping" | "healthcare" | "utilities" | "other",
  "merchant": string or null,
  "description": string (brief English description),
  "confidence": number (0.7-1.0)
}
`

      const result = await this.model.generateContent(prompt)
      const response = await result.response
      const aiText = response.text()

      console.log('AI Response:', aiText)

      // Extract JSON from AI response (handle markdown code blocks)
      let jsonText = aiText

      // Remove markdown code blocks if present
      jsonText = jsonText.replace(/```json\s*/g, '').replace(/```\s*/g, '')

      // Find JSON object
      const jsonMatch = jsonText.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        throw new Error('No JSON found in AI response')
      }

      const extracted = JSON.parse(jsonMatch[0])

      // Validate and normalize category
      const validCategories = ['food', 'transport', 'entertainment', 'shopping', 'healthcare', 'utilities', 'other']
      if (!validCategories.includes(extracted.category)) {
        extracted.category = 'other'
      }

      return {
        success: true,
        confidence: extracted.confidence || 0.7,
        data: {
          amount: extracted.amount,
          category: extracted.category,
          merchant: extracted.merchant,
          description: extracted.description,
          originalText: text,
          method: 'ai-powered'
        }
      }

    } catch (error) {
      console.error('AI extraction error:', error)

      // If AI fails, try one more time with rule-based extraction with lower confidence threshold
      const fallbackResult = this.extractWithRulesFallback(text)
      if (fallbackResult.success) {
        return fallbackResult
      }

      return {
        success: false,
        confidence: 0,
        error: 'AI processing failed: ' + error.message
      }
    }
  }

  // Aggressive fallback extraction - tries to extract amount and guess category
  extractWithRulesFallback(text) {
    const normalizedText = text.toLowerCase()
    let amount = null

    // Try every possible number pattern
    const allNumberPatterns = [
      /(\d+\.?\d*)/g  // Any number in the text
    ]

    const matches = text.match(allNumberPatterns[0])
    if (matches && matches.length > 0) {
      // Take the first number found
      amount = parseFloat(matches[0])
    }

    if (!amount || amount <= 0 || amount > 100000) {
      return { success: false, confidence: 0, error: 'Could not extract valid amount' }
    }

    // Try to detect category
    const category = this.detectCategory(normalizedText) || 'other'
    const merchant = this.detectMerchant(normalizedText)

    return {
      success: true,
      confidence: 0.6,  // Lower confidence for fallback
      data: {
        amount: amount,
        category: category,
        merchant: merchant,
        description: text.trim(),
        originalText: text,
        method: 'fallback-extraction'
      }
    }
  }

  // Enhanced category detection with action verb analysis and scoring
  detectCategory(text) {
    const normalizedText = text.toLowerCase()
    const categoryScores = {}

    // Initialize scores
    for (const category of Object.keys(this.financialTerms.categories)) {
      categoryScores[category] = 0
    }

    // Score based on keywords (weight: 1.0)
    for (const [category, keywords] of Object.entries(this.financialTerms.categories)) {
      for (const keyword of keywords) {
        if (normalizedText.includes(keyword.toLowerCase())) {
          categoryScores[category] += 1.0
        }
      }
    }

    // Score based on action verbs (weight: 1.5 - stronger signal)
    for (const [category, verbs] of Object.entries(this.financialTerms.actionVerbs)) {
      for (const verb of verbs) {
        if (normalizedText.includes(verb.toLowerCase())) {
          categoryScores[category] += 1.5
        }
      }
    }

    // Compound word detection (e.g., "dosa khaya" = food + food action)
    // This gives extra weight to phrase combinations
    const words = normalizedText.split(/\s+/)
    for (let i = 0; i < words.length - 1; i++) {
      const bigram = `${words[i]} ${words[i + 1]} `

      // Check if bigram contains both a category keyword and action verb
      for (const [category, keywords] of Object.entries(this.financialTerms.categories)) {
        const hasKeyword = keywords.some(k => bigram.includes(k.toLowerCase()))
        const hasAction = this.financialTerms.actionVerbs[category]?.some(v =>
          bigram.includes(v.toLowerCase())
        )

        if (hasKeyword && hasAction) {
          categoryScores[category] += 2.0 // Strong signal
        }
      }
    }

    // Context-aware scoring (time-based hints)
    const hour = new Date().getHours()
    if (hour >= 7 && hour <= 10) {
      // Breakfast time - boost food score
      categoryScores.food += 0.3
    } else if (hour >= 12 && hour <= 14) {
      // Lunch time - boost food score
      categoryScores.food += 0.3
    } else if (hour >= 19 && hour <= 22) {
      // Dinner time - boost food score
      categoryScores.food += 0.3
    }

    // Find category with highest score
    let maxScore = 0
    let bestCategory = 'other'

    for (const [category, score] of Object.entries(categoryScores)) {
      if (score > maxScore) {
        maxScore = score
        bestCategory = category
      }
    }

    // Return best category if score is above threshold, otherwise 'other'
    return maxScore >= 0.5 ? bestCategory : 'other'
  }

  // Fuzzy matching for similar words (handles typos and variations)
  fuzzyMatch(word, targetWords, threshold = 0.7) {
    word = word.toLowerCase()

    for (const target of targetWords) {
      const targetLower = target.toLowerCase()
      const similarity = this.calculateSimilarity(word, targetLower)

      if (similarity >= threshold) {
        return target
      }
    }
    return null
  }

  // Calculate string similarity (Levenshtein-based)
  calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2
    const shorter = str1.length > str2.length ? str2 : str1

    if (longer.length === 0) return 1.0

    const editDistance = this.levenshteinDistance(longer, shorter)
    return (longer.length - editDistance) / longer.length
  }

  // Levenshtein distance algorithm
  levenshteinDistance(str1, str2) {
    const matrix = []

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i]
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          )
        }
      }
    }

    return matrix[str2.length][str1.length]
  }

  // Detect merchant from text
  detectMerchant(text) {
    for (const merchant of this.financialTerms.merchants) {
      if (text.includes(merchant.toLowerCase())) {
        return merchant.charAt(0).toUpperCase() + merchant.slice(1)
      }
    }
    return null
  }

  // Validate extracted data
  validateExpenseData(data) {
    const errors = []

    if (!data.amount || data.amount <= 0) {
      errors.push('Invalid amount')
    }

    if (data.amount > 100000) {
      errors.push('Amount seems too high')
    }

    if (!data.category) {
      errors.push('Category not detected')
    }

    return {
      isValid: errors.length === 0,
      errors: errors
    }
  }

  // Get category display info
  getCategoryInfo(category) {
    const categoryMap = {
      food: { emoji: '🍽️', englishName: 'Food & Dining', hindiName: 'खाना-पीना' },
      transport: { emoji: '🚗', englishName: 'Transportation', hindiName: 'यातायात' },
      entertainment: { emoji: '🎬', englishName: 'Entertainment', hindiName: 'मनोरंजन' },
      shopping: { emoji: '👕', englishName: 'Shopping', hindiName: 'कपड़े-लत्ते' },
      healthcare: { emoji: '💊', englishName: 'Healthcare', hindiName: 'दवाई-इलाज' },
      utilities: { emoji: '🏠', englishName: 'Home & Utilities', hindiName: 'घर का खर्च' },
      other: { emoji: '💳', englishName: 'Other', hindiName: 'अन्य' }
    }

    return categoryMap[category] || categoryMap.other
  }
}

// Singleton instance
export const voiceProcessor = new VoiceExpenseProcessor()
