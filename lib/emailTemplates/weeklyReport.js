/**
 * Weekly Email Report Template
 * Beautiful, responsive HTML email for weekly financial summary
 */

const GRADE_STYLES = {
  'A+': { bg: '#10B981', emoji: '🌟' },
  'A': { bg: '#10B981', emoji: '⭐' },
  'B+': { bg: '#3B82F6', emoji: '👍' },
  'B': { bg: '#3B82F6', emoji: '👌' },
  'C': { bg: '#F59E0B', emoji: '💪' },
  'D': { bg: '#EF4444', emoji: '📈' }
}

const CATEGORY_EMOJIS = {
  'Food & Dining': '🍔',
  'Food': '🍔',
  'Transportation': '🚗',
  'Housing': '🏠',
  'Entertainment': '🎬',
  'Healthcare': '🏥',
  'Shopping': '🛒',
  'Utilities': '💡',
  'Personal Care': '💆',
  'Other': '📦'
}

export function generateWeeklyReportEmail(data) {
  const {
    userName,
    period,
    summary,
    topCategories,
    highlights,
    tipOfWeek,
    dashboardUrl = 'https://mywealthwise.tech/dashboard'
  } = data

  const gradeStyle = GRADE_STYLES[summary.grade] || GRADE_STYLES['C']

  const categoriesHtml = topCategories.map(cat => {
    const emoji = CATEGORY_EMOJIS[cat.name] || '📦'
    const barWidth = Math.min(cat.percentage, 100)
    return `
      <tr>
        <td style="padding: 8px 0; font-size: 14px; color: #374151;">
          ${emoji} ${cat.name}
        </td>
        <td style="padding: 8px 0; text-align: right; font-size: 14px; color: #374151; font-weight: 600;">
          ₹${cat.amount.toLocaleString('en-IN')}
        </td>
        <td style="padding: 8px 0; width: 120px;">
          <div style="background: #E5E7EB; border-radius: 4px; height: 8px; overflow: hidden;">
            <div style="background: #10B981; height: 100%; width: ${barWidth}%; border-radius: 4px;"></div>
          </div>
        </td>
        <td style="padding: 8px 0 8px 8px; font-size: 12px; color: #6B7280; text-align: right;">
          ${cat.percentage}%
        </td>
      </tr>
    `
  }).join('')

  const highlightsHtml = highlights.map(h => {
    const bgColor = h.type === 'positive' ? '#ECFDF5' : h.type === 'warning' ? '#FEF3C7' : '#EFF6FF'
    const textColor = h.type === 'positive' ? '#065F46' : h.type === 'warning' ? '#92400E' : '#1E40AF'
    return `
      <div style="background: ${bgColor}; padding: 12px 16px; border-radius: 8px; margin-bottom: 8px;">
        <span style="font-size: 14px; color: ${textColor};">
          ${h.emoji} ${h.text}
        </span>
      </div>
    `
  }).join('')

  return {
    subject: `Your Week in Numbers: ₹${summary.totalSpent.toLocaleString('en-IN')} spent 📊`,
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Weekly Financial Report</title>
</head>
<body style="margin: 0; padding: 0; background-color: #F3F4F6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #F3F4F6;">
    <tr>
      <td align="center" style="padding: 40px 20px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">

          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #10B981 0%, #3B82F6 100%); padding: 32px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 700;">WealthWise</h1>
              <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.9); font-size: 14px;">Your Weekly Financial Report</p>
            </td>
          </tr>

          <!-- Greeting -->
          <tr>
            <td style="padding: 32px 32px 16px 32px;">
              <h2 style="margin: 0 0 8px 0; color: #1F2937; font-size: 20px; font-weight: 600;">
                Hi ${userName || 'there'}! 👋
              </h2>
              <p style="margin: 0; color: #6B7280; font-size: 14px;">
                Here's your financial week (${period.formatted})
              </p>
            </td>
          </tr>

          <!-- Summary Cards -->
          <tr>
            <td style="padding: 0 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="25%" style="padding: 8px;">
                    <div style="background: #F3F4F6; border-radius: 12px; padding: 16px; text-align: center;">
                      <div style="font-size: 20px; font-weight: 700; color: #1F2937;">₹${(summary.totalSpent / 1000).toFixed(1)}k</div>
                      <div style="font-size: 11px; color: #6B7280; margin-top: 4px;">Spent</div>
                    </div>
                  </td>
                  <td width="25%" style="padding: 8px;">
                    <div style="background: #F3F4F6; border-radius: 12px; padding: 16px; text-align: center;">
                      <div style="font-size: 20px; font-weight: 700; color: #10B981;">${summary.savingsRate}%</div>
                      <div style="font-size: 11px; color: #6B7280; margin-top: 4px;">Saved</div>
                    </div>
                  </td>
                  <td width="25%" style="padding: 8px;">
                    <div style="background: #F3F4F6; border-radius: 12px; padding: 16px; text-align: center;">
                      <div style="font-size: 20px; font-weight: 700; color: #3B82F6;">${summary.transactionCount}</div>
                      <div style="font-size: 11px; color: #6B7280; margin-top: 4px;">Txns</div>
                    </div>
                  </td>
                  <td width="25%" style="padding: 8px;">
                    <div style="background: ${gradeStyle.bg}; border-radius: 12px; padding: 16px; text-align: center;">
                      <div style="font-size: 20px; font-weight: 700; color: #FFFFFF;">${summary.grade}</div>
                      <div style="font-size: 11px; color: rgba(255,255,255,0.9); margin-top: 4px;">Grade ${gradeStyle.emoji}</div>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Top Categories -->
          <tr>
            <td style="padding: 24px 32px;">
              <h3 style="margin: 0 0 16px 0; color: #1F2937; font-size: 16px; font-weight: 600; border-bottom: 1px solid #E5E7EB; padding-bottom: 8px;">
                Top Categories
              </h3>
              <table width="100%" cellpadding="0" cellspacing="0">
                ${categoriesHtml}
              </table>
            </td>
          </tr>

          <!-- Highlights -->
          ${highlights.length > 0 ? `
          <tr>
            <td style="padding: 0 32px 24px 32px;">
              <h3 style="margin: 0 0 16px 0; color: #1F2937; font-size: 16px; font-weight: 600; border-bottom: 1px solid #E5E7EB; padding-bottom: 8px;">
                Highlights
              </h3>
              ${highlightsHtml}
            </td>
          </tr>
          ` : ''}

          <!-- Tip of the Week -->
          <tr>
            <td style="padding: 0 32px 32px 32px;">
              <div style="background: linear-gradient(135deg, #EEF2FF 0%, #E0E7FF 100%); border-radius: 12px; padding: 20px; border-left: 4px solid #6366F1;">
                <h4 style="margin: 0 0 8px 0; color: #4338CA; font-size: 14px; font-weight: 600;">
                  💡 Tip of the Week
                </h4>
                <p style="margin: 0; color: #4338CA; font-size: 14px; line-height: 1.5;">
                  "${tipOfWeek}"
                </p>
              </div>
            </td>
          </tr>

          <!-- CTA Button -->
          <tr>
            <td style="padding: 0 32px 32px 32px; text-align: center;">
              <a href="${dashboardUrl}" style="display: inline-block; background: linear-gradient(135deg, #10B981 0%, #059669 100%); color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px;">
                See Full Dashboard →
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background: #F9FAFB; padding: 24px 32px; text-align: center; border-top: 1px solid #E5E7EB;">
              <p style="margin: 0 0 8px 0; color: #6B7280; font-size: 12px;">
                WealthWise · Smart Financial Planning
              </p>
              <p style="margin: 0; color: #9CA3AF; font-size: 11px;">
                <a href="${dashboardUrl}/settings" style="color: #9CA3AF; text-decoration: underline;">Unsubscribe</a> ·
                <a href="${dashboardUrl}/settings" style="color: #9CA3AF; text-decoration: underline;">Email Preferences</a>
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `,
    text: `
Your Weekly Financial Report - WealthWise

Hi ${userName || 'there'}!

Here's your financial week (${period.formatted}):

SUMMARY
- Spent: ₹${summary.totalSpent.toLocaleString('en-IN')}
- Saved: ${summary.savingsRate}%
- Transactions: ${summary.transactionCount}
- Grade: ${summary.grade}

TOP CATEGORIES
${topCategories.map(c => `- ${c.name}: ₹${c.amount.toLocaleString('en-IN')} (${c.percentage}%)`).join('\n')}

HIGHLIGHTS
${highlights.map(h => `${h.emoji} ${h.text}`).join('\n')}

TIP OF THE WEEK
"${tipOfWeek}"

See your full dashboard: ${dashboardUrl}

---
WealthWise · Smart Financial Planning
    `
  }
}

export default generateWeeklyReportEmail
