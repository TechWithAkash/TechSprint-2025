/**
 * Indian Financial Calendar
 * Pre-built seasonal events data for WealthWise
 * Includes festivals, education expenses, tax deadlines
 */

// Seasonal Event Categories
export const SEASONAL_EVENT_CATEGORIES = {
  FESTIVAL: 'festival',
  EDUCATION: 'education',
  INSURANCE: 'insurance',
  TAX: 'tax',
  UTILITY: 'utility',
  CUSTOM: 'custom'
}

// Pre-computed festival dates for 2024-2030
// (Hindu festivals follow lunar calendar, dates vary each year)
const FESTIVAL_DATES = {
  diwali: {
    2024: new Date(2024, 10, 1),   // Nov 1, 2024
    2025: new Date(2025, 9, 20),   // Oct 20, 2025
    2026: new Date(2026, 10, 8),   // Nov 8, 2026
    2027: new Date(2027, 9, 29),   // Oct 29, 2027
    2028: new Date(2028, 9, 17),   // Oct 17, 2028
    2029: new Date(2029, 10, 5),   // Nov 5, 2029
    2030: new Date(2030, 9, 26),   // Oct 26, 2030
  },
  holi: {
    2024: new Date(2024, 2, 25),   // Mar 25, 2024
    2025: new Date(2025, 2, 14),   // Mar 14, 2025
    2026: new Date(2026, 2, 3),    // Mar 3, 2026
    2027: new Date(2027, 2, 22),   // Mar 22, 2027
    2028: new Date(2028, 2, 11),   // Mar 11, 2028
    2029: new Date(2029, 2, 1),    // Mar 1, 2029
    2030: new Date(2030, 2, 20),   // Mar 20, 2030
  },
  durga_puja: {
    2024: new Date(2024, 9, 9),    // Oct 9, 2024
    2025: new Date(2025, 9, 1),    // Oct 1, 2025
    2026: new Date(2026, 9, 20),   // Oct 20, 2026
    2027: new Date(2027, 9, 10),   // Oct 10, 2027
    2028: new Date(2028, 8, 28),   // Sep 28, 2028
    2029: new Date(2029, 9, 16),   // Oct 16, 2029
    2030: new Date(2030, 9, 6),    // Oct 6, 2030
  },
  ganesh_chaturthi: {
    2024: new Date(2024, 8, 7),    // Sep 7, 2024
    2025: new Date(2025, 7, 27),   // Aug 27, 2025
    2026: new Date(2026, 8, 15),   // Sep 15, 2026
    2027: new Date(2027, 8, 4),    // Sep 4, 2027
    2028: new Date(2028, 7, 23),   // Aug 23, 2028
    2029: new Date(2029, 8, 11),   // Sep 11, 2029
    2030: new Date(2030, 8, 1),    // Sep 1, 2030
  },
  eid_ul_fitr: {
    2024: new Date(2024, 3, 10),   // Apr 10, 2024
    2025: new Date(2025, 2, 30),   // Mar 30, 2025
    2026: new Date(2026, 2, 20),   // Mar 20, 2026
    2027: new Date(2027, 2, 9),    // Mar 9, 2027
    2028: new Date(2028, 1, 26),   // Feb 26, 2028
    2029: new Date(2029, 1, 14),   // Feb 14, 2029
    2030: new Date(2030, 1, 4),    // Feb 4, 2030
  },
  eid_ul_adha: {
    2024: new Date(2024, 5, 17),   // Jun 17, 2024
    2025: new Date(2025, 5, 6),    // Jun 6, 2025
    2026: new Date(2026, 4, 27),   // May 27, 2026
    2027: new Date(2027, 4, 16),   // May 16, 2027
    2028: new Date(2028, 4, 5),    // May 5, 2028
    2029: new Date(2029, 3, 24),   // Apr 24, 2029
    2030: new Date(2030, 3, 13),   // Apr 13, 2030
  },
  onam: {
    2024: new Date(2024, 8, 15),   // Sep 15, 2024
    2025: new Date(2025, 8, 5),    // Sep 5, 2025
    2026: new Date(2026, 7, 25),   // Aug 25, 2026
    2027: new Date(2027, 8, 13),   // Sep 13, 2027
    2028: new Date(2028, 8, 2),    // Sep 2, 2028
    2029: new Date(2029, 7, 22),   // Aug 22, 2029
    2030: new Date(2030, 8, 10),   // Sep 10, 2030
  },
  pongal: {
    2024: new Date(2024, 0, 15),   // Jan 15, 2024
    2025: new Date(2025, 0, 14),   // Jan 14, 2025
    2026: new Date(2026, 0, 14),   // Jan 14, 2026
    2027: new Date(2027, 0, 14),   // Jan 14, 2027
    2028: new Date(2028, 0, 15),   // Jan 15, 2028
    2029: new Date(2029, 0, 14),   // Jan 14, 2029
    2030: new Date(2030, 0, 14),   // Jan 14, 2030
  },
  navratri: {
    2024: new Date(2024, 9, 3),    // Oct 3, 2024
    2025: new Date(2025, 8, 22),   // Sep 22, 2025
    2026: new Date(2026, 9, 12),   // Oct 12, 2026
    2027: new Date(2027, 9, 2),    // Oct 2, 2027
    2028: new Date(2028, 8, 20),   // Sep 20, 2028
    2029: new Date(2029, 9, 8),    // Oct 8, 2029
    2030: new Date(2030, 8, 28),   // Sep 28, 2030
  }
}

// Get festival date for a given year
function getFestivalDate(festivalId, year) {
  const dates = FESTIVAL_DATES[festivalId]
  if (dates && dates[year]) {
    return dates[year]
  }
  // Fallback: estimate based on 2025 date
  return dates?.[2025] || null
}

// Get next occurrence of a festival
function getNextFestivalDate(festivalId) {
  const now = new Date()
  const currentYear = now.getFullYear()

  // Check current year first
  let date = getFestivalDate(festivalId, currentYear)
  if (date && date > now) {
    return date
  }

  // Check next year
  return getFestivalDate(festivalId, currentYear + 1)
}

// Main calendar data
export const INDIAN_FINANCIAL_CALENDAR = {
  festivals: [
    {
      id: 'diwali',
      name: 'Diwali',
      hindiName: 'दिवाली',
      description: 'Festival of Lights - gifts, decorations, clothing, sweets, crackers',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🪔',
      getDate: (year) => getFestivalDate('diwali', year),
      getNextDate: () => getNextFestivalDate('diwali'),
      typicalExpenseRange: { min: 10000, max: 50000 },
      expenseByFamilySize: {
        1: { min: 5000, max: 15000 },
        2: { min: 8000, max: 25000 },
        3: { min: 15000, max: 40000 },
        4: { min: 20000, max: 50000 },
        '5+': { min: 25000, max: 60000 }
      },
      expenseByIncome: {
        'lower_middle': 0.15,    // 15% of monthly income
        'middle': 0.20,          // 20% of monthly income
        'upper_middle': 0.15,    // 15% of monthly income
        'affluent': 0.10         // 10% of monthly income
      },
      defaultBudgetMultiplier: 1.5,
      preparationWeeks: 8,
      subCategories: [
        { name: 'Gifts', percentage: 30 },
        { name: 'Clothing', percentage: 25 },
        { name: 'Decorations', percentage: 15 },
        { name: 'Sweets & Food', percentage: 15 },
        { name: 'Crackers', percentage: 10 },
        { name: 'Puja Items', percentage: 5 }
      ],
      financialTips: [
        'Start saving 3 months before Diwali',
        'Set a fixed gift budget per person',
        'Buy decorations early for best prices',
        'Compare prices online before buying',
        'Consider eco-friendly alternatives to crackers'
      ],
      regionalRelevance: ['All India']
    },
    {
      id: 'holi',
      name: 'Holi',
      hindiName: 'होली',
      description: 'Festival of Colors - colors, sweets, new clothes, gatherings',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🎨',
      getDate: (year) => getFestivalDate('holi', year),
      getNextDate: () => getNextFestivalDate('holi'),
      typicalExpenseRange: { min: 3000, max: 15000 },
      expenseByFamilySize: {
        1: { min: 2000, max: 5000 },
        2: { min: 3000, max: 8000 },
        3: { min: 5000, max: 12000 },
        4: { min: 6000, max: 15000 },
        '5+': { min: 8000, max: 20000 }
      },
      defaultBudgetMultiplier: 1.2,
      preparationWeeks: 4,
      subCategories: [
        { name: 'Colors & Pichkari', percentage: 20 },
        { name: 'Sweets & Snacks', percentage: 30 },
        { name: 'New Clothes', percentage: 30 },
        { name: 'Party & Gatherings', percentage: 20 }
      ],
      financialTips: [
        'Buy colors in bulk for savings',
        'Prepare sweets at home to save money',
        'Plan gatherings with friends to share costs'
      ],
      regionalRelevance: ['North India', 'West India', 'Central India']
    },
    {
      id: 'durga_puja',
      name: 'Durga Puja',
      hindiName: 'दुर्गा पूजा',
      description: 'Major festival in Eastern India - pandal hopping, new clothes, feasts',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🙏',
      getDate: (year) => getFestivalDate('durga_puja', year),
      getNextDate: () => getNextFestivalDate('durga_puja'),
      typicalExpenseRange: { min: 8000, max: 35000 },
      expenseByFamilySize: {
        1: { min: 5000, max: 12000 },
        2: { min: 8000, max: 20000 },
        3: { min: 12000, max: 30000 },
        4: { min: 15000, max: 35000 },
        '5+': { min: 20000, max: 45000 }
      },
      defaultBudgetMultiplier: 1.4,
      preparationWeeks: 6,
      subCategories: [
        { name: 'New Clothes', percentage: 35 },
        { name: 'Pandal Hopping & Travel', percentage: 25 },
        { name: 'Food & Dining', percentage: 25 },
        { name: 'Puja Items', percentage: 15 }
      ],
      financialTips: [
        'Book travel in advance for better prices',
        'Buy clothes during pre-Puja sales',
        'Set daily spending limits for pandal visits'
      ],
      regionalRelevance: ['West Bengal', 'Odisha', 'Bihar', 'Jharkhand', 'Assam']
    },
    {
      id: 'eid_ul_fitr',
      name: 'Eid ul-Fitr',
      hindiName: 'ईद उल-फ़ित्र',
      description: 'End of Ramadan - new clothes, gifts, feasts, charity',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '☪️',
      getDate: (year) => getFestivalDate('eid_ul_fitr', year),
      getNextDate: () => getNextFestivalDate('eid_ul_fitr'),
      typicalExpenseRange: { min: 8000, max: 30000 },
      expenseByFamilySize: {
        1: { min: 4000, max: 10000 },
        2: { min: 6000, max: 15000 },
        3: { min: 10000, max: 25000 },
        4: { min: 12000, max: 30000 },
        '5+': { min: 15000, max: 40000 }
      },
      defaultBudgetMultiplier: 1.4,
      preparationWeeks: 4,
      subCategories: [
        { name: 'New Clothes', percentage: 35 },
        { name: 'Food & Feasts', percentage: 25 },
        { name: 'Gifts (Eidi)', percentage: 20 },
        { name: 'Charity (Zakat/Fitrah)', percentage: 15 },
        { name: 'Decorations', percentage: 5 }
      ],
      financialTips: [
        'Calculate Zakat/Fitrah obligation early',
        'Plan Eid shopping during Ramadan sales',
        'Set fixed Eidi amounts for children'
      ],
      regionalRelevance: ['All India']
    },
    {
      id: 'christmas',
      name: 'Christmas',
      hindiName: 'क्रिसमस',
      description: 'Christmas celebrations - gifts, decorations, parties, travel',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🎄',
      getDate: (year) => new Date(year, 11, 25),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const christmas = new Date(thisYear, 11, 25)
        return christmas > now ? christmas : new Date(thisYear + 1, 11, 25)
      },
      typicalExpenseRange: { min: 5000, max: 30000 },
      expenseByFamilySize: {
        1: { min: 3000, max: 10000 },
        2: { min: 5000, max: 15000 },
        3: { min: 8000, max: 25000 },
        4: { min: 10000, max: 30000 },
        '5+': { min: 12000, max: 35000 }
      },
      defaultBudgetMultiplier: 1.3,
      preparationWeeks: 4,
      subCategories: [
        { name: 'Gifts', percentage: 40 },
        { name: 'Decorations & Tree', percentage: 20 },
        { name: 'Food & Cake', percentage: 25 },
        { name: 'Parties & Events', percentage: 15 }
      ],
      financialTips: [
        'Take advantage of year-end sales',
        'Start gift shopping early',
        'Consider Secret Santa for group gifting'
      ],
      regionalRelevance: ['Goa', 'Kerala', 'Northeast', 'Metro Cities']
    },
    {
      id: 'ganesh_chaturthi',
      name: 'Ganesh Chaturthi',
      hindiName: 'गणेश चतुर्थी',
      description: 'Ganesh festival - idol, decorations, prasad, visarjan',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🐘',
      getDate: (year) => getFestivalDate('ganesh_chaturthi', year),
      getNextDate: () => getNextFestivalDate('ganesh_chaturthi'),
      typicalExpenseRange: { min: 3000, max: 25000 },
      expenseByFamilySize: {
        1: { min: 2000, max: 8000 },
        2: { min: 3000, max: 12000 },
        3: { min: 5000, max: 18000 },
        4: { min: 8000, max: 25000 },
        '5+': { min: 10000, max: 30000 }
      },
      defaultBudgetMultiplier: 1.2,
      preparationWeeks: 3,
      subCategories: [
        { name: 'Ganesh Idol', percentage: 30 },
        { name: 'Decorations & Pandal', percentage: 25 },
        { name: 'Prasad & Food', percentage: 25 },
        { name: 'Puja Items', percentage: 15 },
        { name: 'Visarjan', percentage: 5 }
      ],
      financialTips: [
        'Consider eco-friendly clay idols',
        'Buy decorations reusable for next year',
        'Prepare modak and prasad at home'
      ],
      regionalRelevance: ['Maharashtra', 'Karnataka', 'Goa', 'Gujarat', 'Andhra Pradesh']
    },
    {
      id: 'navratri',
      name: 'Navratri / Dandiya',
      hindiName: 'नवरात्रि',
      description: '9 nights of celebration - garba, dandiya, new clothes',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '💃',
      getDate: (year) => getFestivalDate('navratri', year),
      getNextDate: () => getNextFestivalDate('navratri'),
      typicalExpenseRange: { min: 5000, max: 25000 },
      expenseByFamilySize: {
        1: { min: 3000, max: 10000 },
        2: { min: 5000, max: 15000 },
        3: { min: 8000, max: 20000 },
        4: { min: 10000, max: 25000 },
        '5+': { min: 12000, max: 30000 }
      },
      defaultBudgetMultiplier: 1.3,
      preparationWeeks: 4,
      subCategories: [
        { name: 'Traditional Outfits', percentage: 40 },
        { name: 'Event Passes', percentage: 25 },
        { name: 'Accessories & Jewelry', percentage: 20 },
        { name: 'Food & Dining', percentage: 15 }
      ],
      financialTips: [
        'Buy chaniya choli during pre-season sales',
        'Look for combo/group discounts on passes',
        'Rent expensive jewelry instead of buying'
      ],
      regionalRelevance: ['Gujarat', 'Maharashtra', 'Rajasthan', 'West India']
    },
    {
      id: 'onam',
      name: 'Onam',
      hindiName: 'ओणम',
      description: 'Kerala harvest festival - Onam Sadya, new clothes, boat races',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🛶',
      getDate: (year) => getFestivalDate('onam', year),
      getNextDate: () => getNextFestivalDate('onam'),
      typicalExpenseRange: { min: 5000, max: 25000 },
      expenseByFamilySize: {
        1: { min: 3000, max: 8000 },
        2: { min: 5000, max: 15000 },
        3: { min: 8000, max: 20000 },
        4: { min: 10000, max: 25000 },
        '5+': { min: 12000, max: 30000 }
      },
      defaultBudgetMultiplier: 1.3,
      preparationWeeks: 3,
      subCategories: [
        { name: 'New Clothes (Kasavu)', percentage: 35 },
        { name: 'Onam Sadya Feast', percentage: 30 },
        { name: 'Pookalam & Decorations', percentage: 15 },
        { name: 'Gifts', percentage: 20 }
      ],
      financialTips: [
        'Shop during Onam sale season',
        'Plan Sadya ingredients in advance',
        'Consider group celebrations to share costs'
      ],
      regionalRelevance: ['Kerala']
    },
    {
      id: 'pongal',
      name: 'Pongal',
      hindiName: 'पोंगल',
      description: 'Tamil harvest festival - new clothes, Pongal dishes, cattle worship',
      category: SEASONAL_EVENT_CATEGORIES.FESTIVAL,
      icon: '🌾',
      getDate: (year) => getFestivalDate('pongal', year),
      getNextDate: () => getNextFestivalDate('pongal'),
      typicalExpenseRange: { min: 4000, max: 20000 },
      expenseByFamilySize: {
        1: { min: 2000, max: 6000 },
        2: { min: 4000, max: 12000 },
        3: { min: 6000, max: 16000 },
        4: { min: 8000, max: 20000 },
        '5+': { min: 10000, max: 25000 }
      },
      defaultBudgetMultiplier: 1.2,
      preparationWeeks: 2,
      subCategories: [
        { name: 'New Clothes', percentage: 35 },
        { name: 'Pongal Ingredients', percentage: 25 },
        { name: 'Kolam & Decorations', percentage: 15 },
        { name: 'Gifts', percentage: 25 }
      ],
      financialTips: [
        'Buy rice and jaggery during harvest season',
        'Prepare traditional dishes at home'
      ],
      regionalRelevance: ['Tamil Nadu', 'Andhra Pradesh', 'Karnataka']
    }
  ],

  education: [
    {
      id: 'school_fees_q1',
      name: 'School Fees (April)',
      hindiName: 'स्कूल फीस (अप्रैल)',
      description: 'First quarter school fees - new academic year begins',
      category: SEASONAL_EVENT_CATEGORIES.EDUCATION,
      icon: '📚',
      getDate: (year) => new Date(year, 3, 1),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const aprilDate = new Date(thisYear, 3, 1)
        return aprilDate > now ? aprilDate : new Date(thisYear + 1, 3, 1)
      },
      typicalExpenseRange: { min: 15000, max: 100000 },
      expenseBySchoolType: {
        'government': { min: 2000, max: 10000 },
        'private': { min: 15000, max: 50000 },
        'international': { min: 50000, max: 150000 }
      },
      preparationWeeks: 8,
      isRecurring: true,
      recurringPattern: 'yearly',
      financialTips: [
        'Set up monthly savings for annual fees',
        'Check for sibling discounts',
        'Pay early for early-bird discounts'
      ],
      additionalCosts: [
        { name: 'Books & Stationery', range: { min: 3000, max: 15000 } },
        { name: 'Uniforms', range: { min: 2000, max: 8000 } },
        { name: 'School Bag & Supplies', range: { min: 1500, max: 5000 } }
      ]
    },
    {
      id: 'school_fees_q2',
      name: 'School Fees (July)',
      hindiName: 'स्कूल फीस (जुलाई)',
      description: 'Second quarter school fees',
      category: SEASONAL_EVENT_CATEGORIES.EDUCATION,
      icon: '📚',
      getDate: (year) => new Date(year, 6, 1),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const julyDate = new Date(thisYear, 6, 1)
        return julyDate > now ? julyDate : new Date(thisYear + 1, 6, 1)
      },
      typicalExpenseRange: { min: 10000, max: 80000 },
      preparationWeeks: 4,
      isRecurring: true,
      recurringPattern: 'yearly',
      financialTips: [
        'Budget a fixed amount each month for fees'
      ]
    },
    {
      id: 'school_fees_q3',
      name: 'School Fees (October)',
      hindiName: 'स्कूल फीस (अक्टूबर)',
      description: 'Third quarter school fees',
      category: SEASONAL_EVENT_CATEGORIES.EDUCATION,
      icon: '📚',
      getDate: (year) => new Date(year, 9, 1),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const octDate = new Date(thisYear, 9, 1)
        return octDate > now ? octDate : new Date(thisYear + 1, 9, 1)
      },
      typicalExpenseRange: { min: 10000, max: 80000 },
      preparationWeeks: 4,
      isRecurring: true,
      recurringPattern: 'yearly'
    },
    {
      id: 'college_admission',
      name: 'College Admission Season',
      hindiName: 'कॉलेज एडमिशन',
      description: 'College admission fees, donations - May to July',
      category: SEASONAL_EVENT_CATEGORIES.EDUCATION,
      icon: '🎓',
      getDate: (year) => new Date(year, 4, 1),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const mayDate = new Date(thisYear, 4, 1)
        return mayDate > now ? mayDate : new Date(thisYear + 1, 4, 1)
      },
      typicalExpenseRange: { min: 50000, max: 500000 },
      preparationWeeks: 24,
      financialTips: [
        'Start education fund early',
        'Explore education loans options',
        'Check for scholarships and grants',
        'Compare fees across institutions'
      ]
    },
    {
      id: 'board_exam_prep',
      name: 'Board Exam Preparation',
      hindiName: 'बोर्ड परीक्षा तैयारी',
      description: 'Coaching, study material for Class 10/12 boards',
      category: SEASONAL_EVENT_CATEGORIES.EDUCATION,
      icon: '📝',
      getDate: (year) => new Date(year, 10, 1),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const novDate = new Date(thisYear, 10, 1)
        return novDate > now ? novDate : new Date(thisYear + 1, 10, 1)
      },
      typicalExpenseRange: { min: 10000, max: 100000 },
      preparationWeeks: 12,
      financialTips: [
        'Compare coaching center fees',
        'Consider online alternatives',
        'Buy second-hand reference books'
      ]
    }
  ],

  tax: [
    {
      id: 'itr_filing',
      name: 'Income Tax Return Filing',
      hindiName: 'आयकर रिटर्न फाइलिंग',
      description: 'ITR filing deadline - CA fees, tax payment',
      category: SEASONAL_EVENT_CATEGORIES.TAX,
      icon: '📋',
      getDate: (year) => new Date(year, 6, 31),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const julyDate = new Date(thisYear, 6, 31)
        return julyDate > now ? julyDate : new Date(thisYear + 1, 6, 31)
      },
      typicalExpenseRange: { min: 500, max: 15000 },
      preparationWeeks: 8,
      financialTips: [
        'Collect all investment proofs early',
        'File before deadline to avoid penalty',
        'Consider online filing for simple returns'
      ]
    },
    {
      id: 'advance_tax_q1',
      name: 'Advance Tax (Q1)',
      hindiName: 'अग्रिम कर (Q1)',
      description: 'First quarter advance tax - June 15',
      category: SEASONAL_EVENT_CATEGORIES.TAX,
      icon: '💰',
      getDate: (year) => new Date(year, 5, 15),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const juneDate = new Date(thisYear, 5, 15)
        return juneDate > now ? juneDate : new Date(thisYear + 1, 5, 15)
      },
      typicalExpenseRange: { min: 0, max: 100000 },
      preparationWeeks: 4
    },
    {
      id: 'advance_tax_q2',
      name: 'Advance Tax (Q2)',
      hindiName: 'अग्रिम कर (Q2)',
      description: 'Second quarter advance tax - September 15',
      category: SEASONAL_EVENT_CATEGORIES.TAX,
      icon: '💰',
      getDate: (year) => new Date(year, 8, 15),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const septDate = new Date(thisYear, 8, 15)
        return septDate > now ? septDate : new Date(thisYear + 1, 8, 15)
      },
      typicalExpenseRange: { min: 0, max: 100000 },
      preparationWeeks: 4
    },
    {
      id: 'advance_tax_q3',
      name: 'Advance Tax (Q3)',
      hindiName: 'अग्रिम कर (Q3)',
      description: 'Third quarter advance tax - December 15',
      category: SEASONAL_EVENT_CATEGORIES.TAX,
      icon: '💰',
      getDate: (year) => new Date(year, 11, 15),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const decDate = new Date(thisYear, 11, 15)
        return decDate > now ? decDate : new Date(thisYear + 1, 11, 15)
      },
      typicalExpenseRange: { min: 0, max: 100000 },
      preparationWeeks: 4
    },
    {
      id: 'advance_tax_q4',
      name: 'Advance Tax (Q4)',
      hindiName: 'अग्रिम कर (Q4)',
      description: 'Fourth quarter advance tax - March 15',
      category: SEASONAL_EVENT_CATEGORIES.TAX,
      icon: '💰',
      getDate: (year) => new Date(year, 2, 15),
      getNextDate: () => {
        const now = new Date()
        const thisYear = now.getFullYear()
        const marchDate = new Date(thisYear, 2, 15)
        return marchDate > now ? marchDate : new Date(thisYear + 1, 2, 15)
      },
      typicalExpenseRange: { min: 0, max: 100000 },
      preparationWeeks: 4
    }
  ],

  insurance: [
    {
      id: 'health_insurance_renewal',
      name: 'Health Insurance Renewal',
      hindiName: 'स्वास्थ्य बीमा नवीनीकरण',
      description: 'Annual health insurance premium',
      category: SEASONAL_EVENT_CATEGORIES.INSURANCE,
      icon: '🏥',
      isUserSpecific: true,
      typicalExpenseRange: { min: 10000, max: 80000 },
      expenseByFamilySize: {
        1: { min: 8000, max: 25000 },
        2: { min: 15000, max: 40000 },
        3: { min: 20000, max: 55000 },
        4: { min: 25000, max: 70000 },
        '5+': { min: 30000, max: 80000 }
      },
      preparationWeeks: 4,
      financialTips: [
        'Compare plans before renewal',
        'Check for no-claim bonus',
        'Consider increasing cover with age',
        'Pay annually for premium discounts'
      ]
    },
    {
      id: 'vehicle_insurance',
      name: 'Vehicle Insurance Renewal',
      hindiName: 'वाहन बीमा नवीनीकरण',
      description: 'Annual car/bike insurance premium',
      category: SEASONAL_EVENT_CATEGORIES.INSURANCE,
      icon: '🚗',
      isUserSpecific: true,
      typicalExpenseRange: { min: 5000, max: 50000 },
      preparationWeeks: 2,
      financialTips: [
        'Compare quotes from multiple insurers',
        'Opt for higher deductible to reduce premium',
        'Maintain NCB by avoiding small claims'
      ]
    },
    {
      id: 'life_insurance',
      name: 'Life Insurance Premium',
      hindiName: 'जीवन बीमा प्रीमियम',
      description: 'Annual life insurance premium',
      category: SEASONAL_EVENT_CATEGORIES.INSURANCE,
      icon: '🛡️',
      isUserSpecific: true,
      typicalExpenseRange: { min: 10000, max: 100000 },
      preparationWeeks: 4,
      financialTips: [
        'Pay annually for premium discounts',
        'Review coverage adequacy periodically'
      ]
    }
  ]
}

// Helper: Get all upcoming events for next N months
export function getUpcomingEvents(monthsAhead = 12, region = null) {
  const now = new Date()
  const futureDate = new Date(now)
  futureDate.setMonth(futureDate.getMonth() + monthsAhead)

  const allEvents = []
  const currentYear = now.getFullYear()

  // Add festivals
  INDIAN_FINANCIAL_CALENDAR.festivals.forEach(festival => {
    if (region && !festival.regionalRelevance.includes(region) && !festival.regionalRelevance.includes('All India')) {
      return
    }

    const nextDate = festival.getNextDate()
    if (nextDate && nextDate <= futureDate) {
      allEvents.push({
        ...festival,
        date: nextDate,
        type: 'festival'
      })
    }
  })

  // Add education events
  INDIAN_FINANCIAL_CALENDAR.education.forEach(event => {
    const nextDate = event.getNextDate()
    if (nextDate && nextDate <= futureDate) {
      allEvents.push({
        ...event,
        date: nextDate,
        type: 'education'
      })
    }
  })

  // Add tax events
  INDIAN_FINANCIAL_CALENDAR.tax.forEach(event => {
    const nextDate = event.getNextDate()
    if (nextDate && nextDate <= futureDate) {
      allEvents.push({
        ...event,
        date: nextDate,
        type: 'tax'
      })
    }
  })

  // Sort by date
  allEvents.sort((a, b) => a.date - b.date)

  return allEvents
}

// Helper: Get event by ID
export function getEventById(eventId) {
  const allCategories = [
    ...INDIAN_FINANCIAL_CALENDAR.festivals,
    ...INDIAN_FINANCIAL_CALENDAR.education,
    ...INDIAN_FINANCIAL_CALENDAR.tax,
    ...INDIAN_FINANCIAL_CALENDAR.insurance
  ]

  return allCategories.find(event => event.id === eventId)
}

// Helper: Estimate expense for an event based on user profile
export function estimateEventExpense(eventId, userProfile) {
  const event = getEventById(eventId)
  if (!event) return null

  const { monthlyIncome = 50000, familySize = 1 } = userProfile || {}

  // Get family size key
  const familySizeKey = familySize >= 5 ? '5+' : familySize.toString()

  // Calculate income-based scaling factor
  // This ensures expenses scale appropriately for all income levels
  const baseIncomeForCalculation = 50000 // Standard reference income
  const incomeScaleFactor = Math.min(monthlyIncome / baseIncomeForCalculation, 2) // Cap at 2x

  // For very low incomes (< 20,000), use a more conservative approach
  const isLowIncome = monthlyIncome < 20000

  let baseExpense = 0

  // Try to get expense by family size first
  if (event.expenseByFamilySize && event.expenseByFamilySize[familySizeKey]) {
    const range = event.expenseByFamilySize[familySizeKey]
    // Use minimum for low incomes, otherwise midpoint
    baseExpense = isLowIncome ? range.min : Math.round((range.min + range.max) / 2)
  }
  // Try expense by income ratio
  else if (event.expenseByIncome && monthlyIncome) {
    const bracket = getIncomeBracket(monthlyIncome)
    const ratio = event.expenseByIncome[bracket] || 0.10
    return Math.round(monthlyIncome * ratio) // This already scales with income
  }
  // Fallback to typical range
  else if (event.typicalExpenseRange) {
    baseExpense = isLowIncome ? event.typicalExpenseRange.min :
                  Math.round((event.typicalExpenseRange.min + event.typicalExpenseRange.max) / 2)
  }
  else {
    baseExpense = 5000 // Default fallback
  }

  // Scale the expense based on income
  // For low incomes, ensure expense doesn't exceed 30% of monthly income per event
  let scaledExpense = Math.round(baseExpense * incomeScaleFactor)

  // Cap expense at reasonable percentage of monthly income
  const maxExpensePercent = isLowIncome ? 0.20 : 0.30 // 20% for low income, 30% otherwise
  const maxExpense = Math.round(monthlyIncome * maxExpensePercent)

  return Math.min(scaledExpense, maxExpense)
}

// Helper: Get income bracket
function getIncomeBracket(monthlyIncome) {
  if (monthlyIncome < 40000) return 'lower_middle'
  if (monthlyIncome < 75000) return 'middle'
  if (monthlyIncome < 150000) return 'upper_middle'
  return 'affluent'
}

// Helper: Get festivals relevant to a region/state
export function getFestivalsByRegion(region) {
  return INDIAN_FINANCIAL_CALENDAR.festivals.filter(festival =>
    festival.regionalRelevance.includes(region) ||
    festival.regionalRelevance.includes('All India')
  )
}

// Helper: Format date in Indian format
export function formatEventDate(date) {
  return date.toLocaleDateString('en-IN', {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  })
}

// Helper: Calculate days until event
export function getDaysUntilEvent(eventDate) {
  const now = new Date()
  const diffTime = eventDate - now
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24))
}

// Helper: Calculate months until event
export function getMonthsUntilEvent(eventDate) {
  const now = new Date()
  const months = (eventDate.getFullYear() - now.getFullYear()) * 12 +
                 (eventDate.getMonth() - now.getMonth())
  return Math.max(0, months)
}

export default INDIAN_FINANCIAL_CALENDAR
