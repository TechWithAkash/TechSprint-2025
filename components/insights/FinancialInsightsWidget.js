'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Sparkles, RefreshCw, ChevronRight, Brain } from 'lucide-react'
import InsightCard from './InsightCard'
import Link from 'next/link'

export default function FinancialInsightsWidget({ compact = false, maxInsights = 6 }) {
  const [insights, setInsights] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchInsights()
  }, [])

  const fetchInsights = async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/insights')
      const data = await response.json()

      if (data.success) {
        setInsights(data.insights || [])
      } else {
        setError(data.error || 'Failed to load insights')
      }
    } catch (err) {
      console.error('Error fetching insights:', err)
      setError('Failed to load insights')
    } finally {
      setLoading(false)
    }
  }

  const displayedInsights = compact ? insights.slice(0, 3) : insights.slice(0, maxInsights)

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            AI Insights
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <div className="flex items-center gap-3 text-purple-600">
              <Sparkles className="w-5 h-5 animate-pulse" />
              <span className="text-sm font-medium">Analyzing your finances...</span>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            AI Insights
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6">
            <p className="text-gray-500 mb-3">{error}</p>
            <Button variant="outline" size="sm" onClick={fetchInsights}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Try Again
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (insights.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            AI Insights
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6">
            <Sparkles className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">Add more expenses and goals to get personalized insights!</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            AI-Powered Insights
            <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full font-normal">
              {insights.length} new
            </span>
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={fetchInsights}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className={`space-y-3 ${compact ? '' : 'max-h-[600px] overflow-y-auto pr-1'}`}>
          {displayedInsights.map((insight, index) => (
            <InsightCard
              key={`${insight.type}-${index}`}
              insight={insight}
              compact={compact}
            />
          ))}
        </div>

        {compact && insights.length > 3 && (
          <Link
            href="/dashboard/analytics"
            className="flex items-center justify-center gap-2 mt-4 py-2 text-sm text-purple-600 hover:text-purple-700 font-medium"
          >
            View All {insights.length} Insights
            <ChevronRight className="w-4 h-4" />
          </Link>
        )}
      </CardContent>
    </Card>
  )
}
