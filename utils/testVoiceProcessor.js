// Voice Processor Test Script
// Run this in browser console or as a Node.js script

const testCases = {
    food: [
        "200 ka dosa khaya",
        "50 rupees chai pi",
        "Swiggy se biryani order kiya 350 ka",
        "idli vada khaya 80 rupees",
        "coffee pi 100 ka",
        "paratha khaya breakfast me",
        "samosa liya 20 rupees",
        "lunch kiya 300 ka"
    ],
    transport: [
        "Metro me 45 spend kiya",
        "Ola me gaya 150 rupees",
        "Auto liya 60 ka",
        "Petrol bharaya 500",
        "Bus me gaya 20 rupees",
        "uber book kiya 200"
    ],
    shopping: [
        "Shirt kharida 1200",
        "Amazon se mobile order",
        "Jeans liya 2000 ka",
        "Flipkart se shoes 1500"
    ],
    entertainment: [
        "Movie dekha 300 ka",
        "Netflix subscription 199",
        "Gaming kiya arcade me 500"
    ],
    healthcare: [
        "Dawai li 250",
        "Doctor ko dikhaya 500",
        "Medicine kharida pharmacy se"
    ],
    utilities: [
        "Bijli bill bhara 2000",
        "Mobile recharge kiya 299",
        "Internet bill paid 800"
    ]
}

// Test function
async function testVoiceProcessor() {
    console.log("🧪 Voice Processor Test Suite\n")
    console.log("=".repeat(60))

    let totalTests = 0
    let passedTests = 0

    for (const [expectedCategory, phrases] of Object.entries(testCases)) {
        console.log(`\n📂 Testing ${expectedCategory.toUpperCase()} category:`)
        console.log("-".repeat(60))

        for (const phrase of phrases) {
            totalTests++

            try {
                const response = await fetch('/api/voice/process', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ voiceText: phrase })
                })

                const data = await response.json()

                if (data.success) {
                    const detected = data.expenseData.category
                    const confidence = Math.round(data.confidence * 100)
                    const passed = detected === expectedCategory

                    if (passed) passedTests++

                    const status = passed ? "✅ PASS" : "❌ FAIL"
                    const icon = passed ? "✅" : "❌"

                    console.log(`${icon} "${phrase}"`)
                    console.log(`   Expected: ${expectedCategory} | Got: ${detected} | Confidence: ${confidence}%`)
                    console.log(`   Method: ${data.expenseData.processingMethod}`)
                } else {
                    console.log(`❌ ERROR: "${phrase}"`)
                    console.log(`   ${data.error}`)
                }
            } catch (error) {
                console.log(`❌ EXCEPTION: "${phrase}"`)
                console.log(`   ${error.message}`)
            }

            // Small delay to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 500))
        }
    }

    console.log("\n" + "=".repeat(60))
    console.log(`\n📊 RESULTS: ${passedTests}/${totalTests} tests passed`)
    console.log(`   Success Rate: ${Math.round((passedTests / totalTests) * 100)}%`)

    if (passedTests === totalTests) {
        console.log("\n🎉 All tests passed! Voice processor is working perfectly!")
    } else if (passedTests / totalTests >= 0.85) {
        console.log("\n✅ Good! Accuracy is above 85% threshold.")
    } else {
        console.log("\n⚠️ Needs improvement. Target is 85%+ accuracy.")
    }
}

// Quick manual test
async function quickTest(phrase) {
    console.log(`🎤 Testing: "${phrase}"`)

    try {
        const response = await fetch('/api/voice/process', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voiceText: phrase })
        })

        const data = await response.json()

        if (data.success) {
            console.log("✅ Success!")
            console.log({
                amount: data.expenseData.amount,
                category: data.expenseData.category,
                merchant: data.expenseData.merchant,
                description: data.expenseData.description,
                confidence: Math.round(data.confidence * 100) + "%",
                method: data.expenseData.processingMethod
            })
        } else {
            console.log("❌ Failed:", data.error)
        }
    } catch (error) {
        console.log("❌ Error:", error.message)
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { testVoiceProcessor, quickTest, testCases }
}

// Usage examples:
console.log("🎤 Voice Processor Test Utilities Loaded!")
console.log("\nUsage:")
console.log("  1. Full test suite: await testVoiceProcessor()")
console.log('  2. Quick test: await quickTest("200 ka dosa khaya")')
console.log("  3. View test cases: console.log(testCases)")
