import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'

// Enhanced AI Loan Advisor with contextual responses
async function generateAdvancedResponse(message, calculationData = null) {
  // Simulate API delay for realistic experience
  await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1500))
  
  const lowerMessage = message.toLowerCase()
  
  // Context-aware responses when calculation data is available
  if (calculationData) {
    const { principal, emi, totalInterest, interestRate, months } = calculationData
    
    if (lowerMessage.includes('advice') || lowerMessage.includes('recommend') || lowerMessage.includes('strategy')) {
      return `## 📊 **Analysis of Your Loan Calculation**

**Your Loan Details:**
- **Principal:** ₹${principal.toLocaleString()}
- **EMI:** ₹${emi.toFixed(0).toLocaleString()}/month
- **Interest Rate:** ${interestRate}% per annum
- **Total Interest:** ₹${totalInterest.toFixed(0).toLocaleString()}

### 🎯 **Personalized Recommendations:**

**1. Extra Payment Strategy** 💰
- Pay an extra ₹${Math.round(emi * 0.1).toLocaleString()}/month
- **Potential Savings:** ~₹${Math.round(totalInterest * 0.12).toLocaleString()} in interest
- **Reduced Tenure:** Save ~${Math.floor(months * 0.15)} months

**2. Interest Rate Optimization** 📉
- Current rate: ${interestRate}%
- Shop for rates 0.5-1% lower
- **Potential Savings:** ₹${Math.round(principal * 0.005).toLocaleString()}/year

**3. Prepayment Strategy** 🚀
- Annual prepayment of ₹${Math.round(principal * 0.1).toLocaleString()}
- Could reduce tenure by 20-30%

Would you like me to calculate specific scenarios for any of these strategies?`
    }
    
    if (lowerMessage.includes('prepay') || lowerMessage.includes('extra')) {
      const extraAmount = Math.round(emi * 0.2)
      const savings = Math.round(totalInterest * 0.25)
      return `## 💡 **Prepayment Analysis for Your Loan**

**Current Loan:** ₹${principal.toLocaleString()} at ${interestRate}%

### **Prepayment Options:**

**Option 1: Monthly Extra Payment** 📅
- Extra ₹${Math.round(emi * 0.1).toLocaleString()}/month (10% of EMI)
- **Interest Savings:** ~₹${Math.round(totalInterest * 0.12).toLocaleString()}
- **Time Saved:** ~${Math.floor(months * 0.15)} months

**Option 2: Quarterly Prepayment** 📊
- ₹${extraAmount.toLocaleString()} every quarter
- **Interest Savings:** ~₹${savings.toLocaleString()}
- **Time Saved:** ~${Math.floor(months * 0.25)} months

**Option 3: Annual Lump Sum** 💰
- ₹${Math.round(principal * 0.1).toLocaleString()} once a year
- **Interest Savings:** ~₹${Math.round(totalInterest * 0.3).toLocaleString()}
- **Time Saved:** ~${Math.floor(months * 0.35)} months

### 🎯 **Best Strategy:**
For your loan amount, **quarterly prepayments** offer the best balance of savings and flexibility.`
    }
  }
  
  // Enhanced EMI calculation responses
  if (lowerMessage.includes('emi') || lowerMessage.includes('calculate')) {
    // Extract numbers from the message
    const amounts = message.match(/(\d+(?:,\d+)*(?:\.\d+)?)\s*(?:l|lakh|lac|cr|crore|k|thousand)?/gi)
    const rates = message.match(/(\d+(?:\.\d+)?)\s*%/g)
    const years = message.match(/(\d+)\s*(?:year|yr)/gi)
    
    if (amounts && rates && years) {
      const amount = parseFloat(amounts[0].replace(/[^0-9.]/g, ''))
      const rate = parseFloat(rates[0].replace('%', ''))
      const duration = parseInt(years[0].replace(/[^0-9]/g, ''))
      
      // Determine if amount is in lakhs/crores
      const finalAmount = message.includes('l') || message.includes('lakh') ? amount * 100000 :
                         message.includes('cr') || message.includes('crore') ? amount * 10000000 :
                         message.includes('k') ? amount * 1000 : amount
      
      const months = duration * 12
      const monthlyRate = rate / 100 / 12
      const emi = finalAmount * (monthlyRate * Math.pow(1 + monthlyRate, months)) / (Math.pow(1 + monthlyRate, months) - 1)
      const totalPayable = emi * months
      const totalInterest = totalPayable - finalAmount
      
      return `## 🧮 **EMI Calculation Result**

**Loan Details:**
- **Principal Amount:** ₹${finalAmount.toLocaleString()}
- **Interest Rate:** ${rate}% per annum
- **Loan Tenure:** ${duration} years (${months} months)

### **📊 Financial Breakdown:**

| Component | Amount |
|-----------|--------|
| **Monthly EMI** | **₹${emi.toFixed(0).toLocaleString()}** |
| **Total Amount Payable** | ₹${totalPayable.toFixed(0).toLocaleString()} |
| **Total Interest** | ₹${totalInterest.toFixed(0).toLocaleString()} |
| **Interest as % of Principal** | ${((totalInterest/finalAmount)*100).toFixed(1)}% |

### **💡 Quick Tips:**
- **EMI-to-Income Ratio:** Keep below 40% of monthly income
- **Interest Optimization:** Even 0.5% rate reduction saves ₹${(finalAmount * 0.005 / 12).toFixed(0)} per month
- **Prepayment Impact:** Extra ₹${Math.round(emi * 0.1).toLocaleString()}/month can save significant interest

Would you like me to compare different tenure options or calculate prepayment scenarios?`
    }
    
    return `## 🧮 **EMI Calculator Guide**

To calculate your EMI accurately, I need:

### **Required Information:**
1. **Principal Amount** (loan amount)
2. **Interest Rate** (% per annum)  
3. **Loan Tenure** (months/years)

### **📝 Example Format:**
- *"Calculate EMI for ₹10 lakh at 12% for 5 years"*
- *"What's the EMI for ₹500000 at 10.5% interest for 3 years?"*

### **📊 EMI Formula:**
\`EMI = P × [r(1+r)^n] / [(1+r)^n-1]\`

Where:
- **P** = Principal amount
- **r** = Monthly interest rate (annual rate ÷ 12)
- **n** = Number of months

### **🎯 What I'll Calculate:**
- Monthly EMI amount
- Total interest payable
- Total amount payable
- Interest as percentage of principal
- Prepayment recommendations

Please provide your loan details, and I'll calculate everything for you!`
  }
  
  // Enhanced repayment strategy responses
  if (lowerMessage.includes('snowball') || lowerMessage.includes('avalanche') || lowerMessage.includes('strategy') || lowerMessage.includes('repay')) {
    return `## 🏔️ **Debt Repayment Strategies Explained**

### **1. Avalanche Method** ❄️ *(Mathematically Optimal)*

**How it works:**
- Pay minimum on all debts
- Extra payments go to **highest interest rate** debt first
- Move to next highest rate after clearing each debt

**✅ Advantages:**
- **Saves most money** in total interest
- **Fastest debt elimination** mathematically
- Best for disciplined borrowers

**📊 Example:**
- Credit Card (24% interest): Pay extra here first
- Personal Loan (12% interest): Pay minimum
- Home Loan (8% interest): Pay minimum

---

### **2. Snowball Method** ⛄ *(Psychologically Motivating)*

**How it works:**
- Pay minimum on all debts
- Extra payments go to **smallest balance** first
- Move to next smallest after clearing each debt

**✅ Advantages:**
- **Quick wins** boost motivation
- **Psychological momentum** builds
- Better for emotional spenders

**📊 Example:**
- Personal Loan: ₹50,000 (clear first)
- Car Loan: ₹200,000 (clear second)
- Home Loan: ₹1,000,000 (clear last)

---

### **🎯 My Recommendation:**

**Choose Avalanche if:**
- You're disciplined with money
- Want to minimize total interest
- Comfortable with delayed gratification

**Choose Snowball if:**
- You need motivation to stay on track
- Have struggled with debt before
- Prefer psychological wins

### **🚀 Hybrid Approach:**
Start with Snowball for motivation, then switch to Avalanche once you build momentum!

**💡 Pro Tip:** Consider debt consolidation if you have multiple high-interest debts (>15% interest rate).

Which strategy appeals to you more, or would you like help choosing based on your specific situation?`
  }
  
  // Enhanced bank recommendations
  if (lowerMessage.includes('bank') || lowerMessage.includes('lender') || lowerMessage.includes('best rate')) {
    return `## 🏦 **Best Banks for Loans (Updated Rates)**

### **🏅 Top Banks for Personal Loans**

| Bank | Interest Rate | Processing Fee | Key Features |
|------|---------------|----------------|--------------|
| **SBI** | 10.50% - 16.00% | 0.50% + GST | ✅ Low rates for existing customers |
| **HDFC Bank** | 10.75% - 21.00% | Up to 2.50% | ✅ Quick approval process |
| **ICICI Bank** | 10.85% - 19.00% | Up to 2.25% | ✅ Digital processing |
| **Axis Bank** | 10.49% - 22.00% | Up to 2.00% | ✅ Flexible tenure options |
| **Kotak Mahindra** | 10.99% - 24.00% | Up to 3.00% | ✅ Instant approval |

### **💰 Alternative Lenders**

| Lender | Interest Rate | Specialization |
|--------|---------------|----------------|
| **Bajaj Finserv** | 11.99% - 35.00% | ✅ Quick disbursal |
| **Tata Capital** | 10.99% - 21.00% | ✅ Flexible documentation |
| **Fullerton India** | 11.99% - 36.00% | ✅ Lower income segments |

### **🎯 Factors to Compare:**

**1. Interest Rate** 📊
- Check for hidden charges
- Understand reducing vs. flat rates
- Ask about rate changes during tenure

**2. Processing Fees** 💸
- Ranges from 0.50% to 3.00% of loan amount
- Some banks waive fees for existing customers
- Calculate total cost, not just interest rate

**3. Prepayment Charges** 🔄
- Many banks: NIL charges after 1 year
- Some charge 2-5% of outstanding amount
- Crucial if you plan prepayments

**4. Documentation** 📄
- Salary slips (3 months)
- Bank statements (6 months)
- Income tax returns (2 years)
- Identity and address proof

### **💡 Pro Tips:**

**🔥 Get Better Rates:**
- Use existing banking relationship
- Maintain good credit score (750+)
- Compare offers from 3-4 banks
- Negotiate based on competitor rates

**⚡ Quick Approval Banks:**
1. HDFC Bank (24-48 hours)
2. ICICI Bank (instant approval)
3. Axis Bank (same day)

**🏆 Best Overall:** SBI for lowest rates, HDFC for quick processing

Would you like me to help you compare specific loan offers or check eligibility criteria?`
  }
  
  // Credit score and improvement advice
  if (lowerMessage.includes('credit') || lowerMessage.includes('score') || lowerMessage.includes('cibil') || lowerMessage.includes('improve')) {
    return `## ⭐ **Credit Score Improvement Guide**

### **📊 Understanding Credit Scores**

| Score Range | Rating | Loan Approval | Interest Rate |
|-------------|--------|---------------|---------------|
| **750-900** | Excellent | ✅ Instant | Lowest rates |
| **700-749** | Good | ✅ High chance | Good rates |
| **650-699** | Fair | ⚠️ Moderate | Higher rates |
| **550-649** | Poor | ❌ Difficult | Very high rates |
| **Below 550** | Very Poor | ❌ Rejected | N/A |

### **🎯 Score Improvement Strategies**

**1. Payment History (35% weightage)** 💳
- **Pay all EMIs on time** - Most important factor
- Set up auto-debit for EMIs
- Never miss credit card payments
- Pay minimum amount if cash-strapped

**2. Credit Utilization (30% weightage)** 📊
- Keep **credit utilization below 30%**
- If limit is ₹100,000, use max ₹30,000
- Pay before statement generation
- Request credit limit increase

**3. Credit History Length (15% weightage)** 📅
- **Don't close old credit cards**
- Keep oldest card active with small purchases
- Average account age matters
- Maintain long-term banking relationships

**4. Credit Mix (10% weightage)** 🔄
- Mix of secured (home, car) and unsecured (personal, credit card) loans
- Don't take loans just for credit mix
- Gradual addition is better than sudden changes

**5. New Credit Inquiries (10% weightage)** 🔍
- **Avoid multiple loan applications** in short time
- Each hard inquiry reduces score by 5-10 points
- Space applications at least 3-6 months apart

### **📈 Quick Improvement Timeline**

**0-3 Months:** 📅
- Start paying all bills on time
- Reduce credit utilization
- Check credit report for errors

**3-6 Months:** 📊
- See initial score improvements
- Maintain consistent payment behavior
- Dispute any incorrect information

**6-12 Months:** 🚀
- Significant score improvements visible
- Eligible for better loan rates
- Build stronger credit profile

**12-24 Months:** 🏆
- Achieve excellent credit score
- Access to premium credit products
- Lowest interest rates available

### **🔧 Free Credit Score Checks**
- CIBIL: Once free per year
- Experian, Equifax, CRIF: Free reports
- Bank apps often provide free scores
- Credit monitoring services

### **⚠️ Common Mistakes to Avoid**
- Applying for multiple loans simultaneously
- Closing old credit cards
- Ignoring credit report errors
- Making only minimum payments on credit cards
- Co-signing loans carelessly

### **🎯 Pro Tips for Faster Improvement**
1. **Pay credit card bills before due date**
2. **Maintain 10-20% credit utilization**
3. **Keep old accounts open**
4. **Check credit report quarterly**
5. **Pay off collections/defaults**

Current credit score? I can provide specific strategies based on your situation!`
  }
  
  // Interest calculation and comparison
  if (lowerMessage.includes('interest') || lowerMessage.includes('compound') || lowerMessage.includes('simple')) {
    return `## 📊 **Interest Calculation Methods Explained**

### **1. Simple Interest** 📐 *(Rare in modern loans)*

**Formula:** \`SI = (P × R × T) / 100\`

- **P** = Principal amount
- **R** = Rate of interest per annum
- **T** = Time period in years

**Example:**
- Principal: ₹100,000
- Rate: 10% per annum  
- Time: 2 years
- **Simple Interest** = (100,000 × 10 × 2) / 100 = ₹20,000

---

### **2. Compound Interest** 📈 *(Most investments)*

**Formula:** \`CI = P(1 + R/100)^T - P\`

**Example (Annual Compounding):**
- Principal: ₹100,000
- Rate: 10% per annum
- Time: 2 years
- **Compound Interest** = 100,000(1.10)² - 100,000 = ₹21,000

**Compounding Frequency Impact:**
- **Annual:** ₹21,000
- **Monthly:** ₹21,494  
- **Daily:** ₹22,140

---

### **3. EMI Calculation** 🏦 *(Reducing Balance)*

**Formula:** \`EMI = P × [r(1+r)^n] / [(1+r)^n-1]\`

- **P** = Principal loan amount
- **r** = Monthly interest rate (annual rate ÷ 12)
- **n** = Number of months

**Example:**
- Loan: ₹1,000,000
- Rate: 12% per annum (1% per month)
- Tenure: 5 years (60 months)
- **EMI** = ₹22,244

### **📊 Interest Types in Loans**

**1. Reducing Balance** ✅ *(Most Common)*
- Interest calculated on **outstanding balance**
- Balance reduces with each EMI payment
- **Lower total interest**
- Used in: Home loans, car loans, personal loans

**2. Flat Rate** ❌ *(Avoid if possible)*
- Interest calculated on **original principal**
- Interest doesn't reduce with payments
- **Higher total interest**
- Sometimes used in: Personal loans, credit cards

### **💡 Real vs. Effective Interest Rates**

**Processing Fees Impact:**
- Loan: ₹1,000,000 at 10%
- Processing fee: 2% (₹20,000)
- **Effective rate** ≈ 10.5-11%

**Prepayment Charges:**
- Can increase effective rate
- Check terms before taking loan

### **🎯 Best Practices:**

**For Loans:**
- Choose **reducing balance** method
- Compare **effective interest rates**
- Factor in all charges and fees
- Understand prepayment terms

**For Investments:**
- Prefer **monthly/quarterly** compounding
- Reinvest returns for compounding benefit
- Start early for maximum benefit
- Consider tax implications

### **🔍 Rate Comparison Example:**

| Loan Type | Stated Rate | Effective Rate | Why Different? |
|-----------|-------------|----------------|----------------|
| Home Loan | 8.5% | 8.7% | Processing fees |
| Car Loan | 9.0% | 9.5% | Insurance linkage |
| Personal Loan | 12.0% | 13.2% | High processing fees |

Would you like me to calculate effective rates for your specific loan scenario?`
  }
  
  // Loan comparison and tenure advice
  if (lowerMessage.includes('tenure') || lowerMessage.includes('duration') || lowerMessage.includes('compare') || lowerMessage.includes('better')) {
    return `## ⚖️ **Loan Tenure Comparison Guide**

### **🎯 Shorter vs. Longer Tenure Analysis**

**Example Loan:** ₹10,00,000 at 12% interest

| Tenure | EMI | Total Interest | Total Payment | Monthly Savings |
|--------|-----|----------------|---------------|-----------------|
| **3 Years** | ₹33,214 | ₹3,95,704 | ₹13,95,704 | Base |
| **5 Years** | ₹22,244 | ₹7,34,640 | ₹17,34,640 | ₹10,970 |
| **7 Years** | ₹17,776 | ₹11,93,584 | ₹21,93,584 | ₹15,438 |
| **10 Years** | ₹14,347 | ₹19,21,640 | ₹29,21,640 | ₹18,867 |

### **📊 Decision Framework**

**Choose SHORTER Tenure (3-5 years) if:** ✅
- High disposable income
- Stable job/business
- Want to minimize total interest
- Planning major expenses later
- Risk-averse personality

**Choose LONGER Tenure (7-10 years) if:** ✅
- Limited monthly income
- Multiple financial goals
- Want cash flow flexibility
- Planning investments with higher returns
- Young age with long earning years

### **💡 Smart Strategies**

**1. Start Long, Pay Short** 🎯
- Take longer tenure for lower EMI
- Make prepayments when possible
- **Best of both worlds**

**2. Step-up EMI** 📈
- Start with lower EMI
- Increase EMI annually (5-10%)
- Matches salary growth

**3. Part-prepayment Strategy** 💰
- Annual bonus → Loan prepayment
- Tax refunds → Principal reduction
- Extra income → EMI increase

### **🔄 Tenure Change Impact**

**Reducing 10-year to 7-year tenure:**
- **EMI Increase:** ₹3,429/month
- **Interest Savings:** ₹7,28,056
- **Time Saved:** 36 months

**Extending 5-year to 7-year tenure:**
- **EMI Reduction:** ₹4,468/month
- **Extra Interest:** ₹4,58,944
- **Extended Time:** 24 months

### **🎲 Risk Assessment**

**High-Risk Scenarios:**
- Very short tenure with tight budget
- Long tenure without inflation adjustment
- Fixed income with variable EMI

**Low-Risk Scenarios:**
- 25-30% EMI-to-income ratio
- Emergency fund = 6 months EMI
- Stable income source

### **📈 Optimal Strategy by Age**

**25-35 Years:** 👨‍💼
- Longer tenure initially
- Aggressive prepayments
- Focus on career growth

**35-45 Years:** 👨‍💻  
- Balanced approach
- Moderate tenure (5-7 years)
- Peak earning years

**45+ Years:** 👨‍🎓
- Shorter tenure
- Clear debts before retirement
- Stable income utilization

### **🔍 Industry-Specific Advice**

**IT/Tech Professionals:** 💻
- Longer tenure + bonus prepayments
- Stock options for prepayment

**Government Employees:** 🏛️
- Moderate tenure
- Utilize HRA benefits

**Business Owners:** 🏢
- Flexible tenure options
- Match with business cycles

**Doctors/Lawyers:** ⚕️
- Initially longer, then shorter
- Income grows with experience

Would you like me to analyze your specific situation or compare different tenure options for your loan amount?`
  }
  
  // General financial advice and tips
  return `## 🎯 **AI Loan Advisor - Your Finance Assistant**

I'm here to help you make **smart financial decisions**! Here's what I can assist you with:

### **🧮 Loan Calculations**
- **EMI calculations** with detailed breakdowns
- **Interest comparisons** (simple vs compound)
- **Tenure optimization** strategies
- **Prepayment impact** analysis

### **🏦 Banking & Loans**
- **Best banks** for different loan types
- **Interest rate negotiations** tips
- **Documentation requirements**
- **Loan approval strategies**

### **📊 Debt Management**
- **Repayment strategies** (Snowball vs Avalanche)
- **Debt consolidation** advice
- **Credit utilization** optimization
- **Multiple loan management**

### **⭐ Credit Score**
- **Score improvement** strategies
- **Credit report** analysis tips
- **Factors affecting** your score
- **Timeline for improvements**

### **💡 Investment vs. Debt**
- **ROI comparisons**
- **Tax implications**
- **Risk assessments**
- **Opportunity cost** analysis

### **🎯 Example Questions to Try:**

**Calculations:** 🧮
- *"Calculate EMI for ₹5 lakh at 10% for 2 years"*
- *"Compare 3-year vs 5-year tenure for ₹10 lakh loan"*

**Strategy:** 📈
- *"Should I prepay my loan or invest in mutual funds?"*
- *"Which repayment method saves more money?"*

**Banking:** 🏦
- *"Best banks for home loans under ₹50 lakh"*
- *"How to negotiate better interest rates?"*

**Credit:** ⭐
- *"How to improve credit score from 650 to 750?"*
- *"What's the impact of multiple loan applications?"*

### **🚀 Quick Tips:**
- Always compare **effective interest rates**
- Maintain **EMI-to-income ratio** under 40%
- Build **emergency fund** = 6 months expenses
- **Pay bills on time** for better credit score

**What specific loan question can I help you with today?** 🤔

Just type your question, and I'll provide detailed, actionable advice!`
}

export async function POST(request) {
  try {
    const session = await auth()
    
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const { message, calculationData } = await request.json()

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return NextResponse.json(
        { error: 'Message is required' },
        { status: 400 }
      )
    }

    // Enhanced AI response with context
    const response = await generateAdvancedResponse(message.trim(), calculationData)

    return NextResponse.json({
      success: true,
      response,
      timestamp: new Date().toISOString(),
      hasContext: !!calculationData
    })

  } catch (error) {
    console.error('Loan advisor error:', error)
    return NextResponse.json(
      { error: 'Failed to get loan advice. Please try again.' },
      { status: 500 }
    )
  }
}
