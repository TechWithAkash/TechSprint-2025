// PDF Generator for AI Insights Report
// Uses jsPDF for PDF generation

export async function generateInsightsPDF(report) {
  const jsPDF = (await import('jspdf')).default

  const pdf = new jsPDF('p', 'mm', 'a4')
  const pageWidth = pdf.internal.pageSize.getWidth()
  const pageHeight = pdf.internal.pageSize.getHeight()
  const margin = 15
  let yPos = margin

  // Helper functions
  const addText = (text, x, y, options = {}) => {
    const { fontSize = 10, fontStyle = 'normal', color = [0, 0, 0] } = options
    pdf.setFontSize(fontSize)
    pdf.setFont('helvetica', fontStyle)
    pdf.setTextColor(...color)
    pdf.text(text, x, y)
    return y + (fontSize * 0.5)
  }

  const addLine = (y) => {
    pdf.setDrawColor(200, 200, 200)
    pdf.line(margin, y, pageWidth - margin, y)
    return y + 5
  }

  const formatCurrency = (amount) => {
    return `Rs.${(amount || 0).toLocaleString('en-IN')}`
  }

  const checkPageBreak = (requiredSpace) => {
    if (yPos + requiredSpace > pageHeight - margin) {
      pdf.addPage()
      yPos = margin
      return true
    }
    return false
  }

  // ===== HEADER =====
  pdf.setFillColor(139, 92, 246) // Purple
  pdf.rect(0, 0, pageWidth, 35, 'F')

  pdf.setTextColor(255, 255, 255)
  pdf.setFontSize(22)
  pdf.setFont('helvetica', 'bold')
  pdf.text('WealthWise', margin, 15)

  pdf.setFontSize(14)
  pdf.setFont('helvetica', 'normal')
  pdf.text('AI Financial Insights Report', margin, 24)

  pdf.setFontSize(10)
  pdf.text(`Generated: ${new Date(report.generatedAt).toLocaleDateString('en-IN', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  })}`, margin, 31)

  yPos = 45

  // ===== SUMMARY SECTION =====
  pdf.setTextColor(0, 0, 0)
  yPos = addText('FINANCIAL SUMMARY', margin, yPos, { fontSize: 14, fontStyle: 'bold', color: [139, 92, 246] })
  yPos += 3

  const { summary, predictions } = report

  // Summary boxes
  const boxWidth = (pageWidth - margin * 2 - 15) / 4
  const summaryData = [
    { label: 'Total Spent', value: formatCurrency(summary.totalSpent) },
    { label: 'Savings Rate', value: `${summary.savingsRate}%` },
    { label: 'Transactions', value: String(summary.transactionCount) },
    { label: 'Forecast', value: formatCurrency(predictions.monthEndForecast) }
  ]

  summaryData.forEach((item, idx) => {
    const x = margin + (idx * (boxWidth + 5))
    pdf.setFillColor(249, 250, 251)
    pdf.roundedRect(x, yPos, boxWidth, 18, 2, 2, 'F')

    pdf.setFontSize(8)
    pdf.setTextColor(100, 100, 100)
    pdf.text(item.label, x + 3, yPos + 6)

    pdf.setFontSize(12)
    pdf.setTextColor(0, 0, 0)
    pdf.setFont('helvetica', 'bold')
    pdf.text(item.value, x + 3, yPos + 14)
    pdf.setFont('helvetica', 'normal')
  })

  yPos += 25
  yPos = addLine(yPos)

  // ===== SPENDING PATTERNS =====
  checkPageBreak(60)
  yPos = addText('SPENDING PATTERNS', margin, yPos, { fontSize: 14, fontStyle: 'bold', color: [59, 130, 246] })
  yPos += 5

  // Category breakdown
  const { spendingPatterns } = report
  if (spendingPatterns?.categoryBreakdown?.length > 0) {
    yPos = addText('Category Breakdown:', margin, yPos, { fontSize: 11, fontStyle: 'bold' })
    yPos += 3

    spendingPatterns.categoryBreakdown.slice(0, 6).forEach((cat) => {
      checkPageBreak(8)
      const barWidth = (pageWidth - margin * 2 - 80) * (cat.percentage / 100)

      pdf.setFontSize(9)
      pdf.setTextColor(60, 60, 60)
      pdf.text(cat.category, margin, yPos)

      // Progress bar background
      pdf.setFillColor(229, 231, 235)
      pdf.roundedRect(margin + 50, yPos - 3, pageWidth - margin * 2 - 80, 4, 1, 1, 'F')

      // Progress bar fill
      const [r, g, b] = hexToRgb(cat.color || '#6B7280')
      pdf.setFillColor(r, g, b)
      pdf.roundedRect(margin + 50, yPos - 3, Math.max(barWidth, 2), 4, 1, 1, 'F')

      // Amount
      pdf.text(`${formatCurrency(cat.amount)} (${cat.percentage}%)`, pageWidth - margin - 30, yPos, { align: 'right' })

      yPos += 7
    })
  }

  yPos += 5
  yPos = addLine(yPos)

  // ===== SAVINGS OPPORTUNITIES =====
  checkPageBreak(50)
  yPos = addText('SAVINGS OPPORTUNITIES', margin, yPos, { fontSize: 14, fontStyle: 'bold', color: [16, 185, 129] })
  yPos += 5

  const { savingsOpportunities } = report

  // Potential savings highlight
  pdf.setFillColor(236, 253, 245)
  pdf.roundedRect(margin, yPos, pageWidth - margin * 2, 15, 2, 2, 'F')
  pdf.setFontSize(10)
  pdf.setTextColor(5, 150, 105)
  pdf.text('Potential Monthly Savings:', margin + 5, yPos + 7)
  pdf.setFontSize(14)
  pdf.setFont('helvetica', 'bold')
  pdf.text(formatCurrency(savingsOpportunities.potentialSavings), margin + 60, yPos + 7)
  pdf.setFont('helvetica', 'normal')
  yPos += 20

  // Areas to reduce
  if (savingsOpportunities?.areasToReduce?.length > 0) {
    yPos = addText('Areas to Reduce:', margin, yPos, { fontSize: 11, fontStyle: 'bold' })
    yPos += 3

    savingsOpportunities.areasToReduce.slice(0, 3).forEach((area) => {
      checkPageBreak(15)
      pdf.setFillColor(254, 243, 199)
      pdf.roundedRect(margin, yPos, pageWidth - margin * 2, 12, 2, 2, 'F')

      pdf.setFontSize(9)
      pdf.setTextColor(146, 64, 14)
      pdf.text(`${area.emoji || ''} ${area.category}: Over by ${formatCurrency(area.overBy)}`, margin + 3, yPos + 5)
      pdf.setTextColor(5, 150, 105)
      pdf.text(`Save ${formatCurrency(area.suggestedReduction)}/month`, margin + 3, yPos + 10)

      yPos += 15
    })
  }

  yPos += 3
  yPos = addLine(yPos)

  // ===== PREDICTIONS =====
  checkPageBreak(40)
  yPos = addText('PREDICTIONS & ALERTS', margin, yPos, { fontSize: 14, fontStyle: 'bold', color: [245, 158, 11] })
  yPos += 5

  // Month end forecast
  const forecastColor = predictions.willExceedBudget ? [239, 68, 68] : [16, 185, 129]
  pdf.setFillColor(...(predictions.willExceedBudget ? [254, 242, 242] : [236, 253, 245]))
  pdf.roundedRect(margin, yPos, pageWidth - margin * 2, 20, 2, 2, 'F')

  pdf.setFontSize(10)
  pdf.setTextColor(100, 100, 100)
  pdf.text('Month-End Forecast:', margin + 5, yPos + 7)
  pdf.setFontSize(16)
  pdf.setTextColor(...forecastColor)
  pdf.setFont('helvetica', 'bold')
  pdf.text(formatCurrency(predictions.monthEndForecast), margin + 55, yPos + 7)
  pdf.setFont('helvetica', 'normal')

  if (predictions.willExceedBudget) {
    pdf.setFontSize(9)
    pdf.text(`May exceed budget by ${formatCurrency(predictions.exceedBy)}`, margin + 5, yPos + 15)
  } else {
    pdf.setFontSize(9)
    pdf.setTextColor(16, 185, 129)
    pdf.text('On track to stay within budget!', margin + 5, yPos + 15)
  }

  yPos += 25

  // Warnings
  if (predictions?.warnings?.length > 0) {
    yPos = addText('Category Warnings:', margin, yPos, { fontSize: 11, fontStyle: 'bold' })
    yPos += 3

    predictions.warnings.slice(0, 3).forEach((warning) => {
      checkPageBreak(10)
      pdf.setFontSize(9)
      pdf.setTextColor(146, 64, 14)
      pdf.text(`• ${warning.category}: Projected ${formatCurrency(warning.projectedSpend)} (+${formatCurrency(warning.projectedOverage)} over)`, margin + 3, yPos)
      yPos += 6
    })
  }

  yPos += 3
  yPos = addLine(yPos)

  // ===== RECOMMENDATIONS =====
  checkPageBreak(50)
  yPos = addText('AI RECOMMENDATIONS', margin, yPos, { fontSize: 14, fontStyle: 'bold', color: [139, 92, 246] })
  yPos += 5

  const { recommendations } = report
  if (recommendations?.length > 0) {
    recommendations.slice(0, 5).forEach((rec, idx) => {
      checkPageBreak(20)

      const priorityColors = {
        high: [239, 68, 68],
        medium: [245, 158, 11],
        low: [59, 130, 246]
      }
      const color = priorityColors[rec.priority] || [100, 100, 100]

      // Priority indicator
      pdf.setFillColor(...color)
      pdf.circle(margin + 3, yPos + 2, 2, 'F')

      // Title
      pdf.setFontSize(10)
      pdf.setTextColor(0, 0, 0)
      pdf.setFont('helvetica', 'bold')
      pdf.text(rec.title, margin + 8, yPos + 3)
      pdf.setFont('helvetica', 'normal')

      // Description
      yPos += 6
      pdf.setFontSize(9)
      pdf.setTextColor(80, 80, 80)
      const descLines = pdf.splitTextToSize(rec.description, pageWidth - margin * 2 - 10)
      pdf.text(descLines, margin + 8, yPos)
      yPos += descLines.length * 4

      // Impact
      if (rec.impact) {
        pdf.setTextColor(16, 185, 129)
        pdf.text(`→ ${rec.impact}`, margin + 8, yPos)
        yPos += 4
      }

      yPos += 5
    })
  }

  // ===== FOOTER =====
  const footerY = pageHeight - 10
  pdf.setFontSize(8)
  pdf.setTextColor(150, 150, 150)
  pdf.text('Generated by WealthWise AI • www.mywealthwise.tech', pageWidth / 2, footerY, { align: 'center' })

  // Save the PDF
  const fileName = `wealthwise-insights-${new Date().toISOString().split('T')[0]}.pdf`
  pdf.save(fileName)

  return fileName
}

// Helper function to convert hex to RGB
function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return result
    ? [parseInt(result[1], 16), parseInt(result[2], 16), parseInt(result[3], 16)]
    : [107, 114, 128] // Default gray
}
