// Test file to verify budget save functionality
export const testBudgetSave = async () => {
  const testBudget = {
    totalBudget: 100000,
    categories: {
      food: { amount: 20000, percentage: 20, emoji: '🍽️', englishName: 'Food & Dining' },
      transport: { amount: 15000, percentage: 15, emoji: '🚗', englishName: 'Transportation' },
      savings: { amount: 25000, percentage: 25, emoji: '💰', englishName: 'Savings' }
    },
    healthScore: 75
  }

  try {
    const response = await fetch('/api/budget/save', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ budget: testBudget }),
    })

    const data = await response.json()
    console.log('Test budget save result:', data)
    return data
  } catch (error) {
    console.error('Test budget save error:', error)
    return { success: false, error: error.message }
  }
}

// You can run this in the browser console to test
// testBudgetSave()
