'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Brain, TrendingUp, AlertCircle, Activity, CheckCircle, Zap, Info, Sparkles } from 'lucide-react'
import { eventBus, EVENTS } from '@/lib/events'

export function AgentDashboard() {
    const [agents, setAgents] = useState({
        income: { status: 'active', lastAction: 'Monitoring income patterns', actionsCount: 0 },
        spending: { status: 'active', lastAction: 'Learning spending habits', actionsCount: 0 },
        coach: { status: 'active', lastAction: 'Ready to provide recommendations', actionsCount: 0 }
    })

    const [activities, setActivities] = useState([])
    const [alerts, setAlerts] = useState([])
    const [insights, setInsights] = useState([])
    const [userData, setUserData] = useState(null)
    const [isAnalyzing, setIsAnalyzing] = useState(true)

    useEffect(() => {
        // First fetch real user data, then analyze it
        fetchAndAnalyzeUserData()
        initializeDashboard()

        // Listen to EventBus for real-time updates
        const agentActionListener = eventBus.on(EVENTS.AGENT_ACTION, (data) => {
            addActivity({
                id: Date.now() + Math.random(),
                agent: data.agent,
                action: data.action || data.message,
                type: 'action',
                timestamp: new Date(),
                confidence: data.confidence || 0.9,
                icon: getAgentIcon(data.agent)
            })
        })

        const agentAlertListener = eventBus.on(EVENTS.AGENT_ALERT, (data) => {
            addAlert({
                id: Date.now() + Math.random(),
                agent: data.agent,
                message: data.message,
                severity: data.severity || 'info',
                timestamp: new Date()
            })
        })

        const agentRecommendationListener = eventBus.on(EVENTS.AGENT_RECOMMENDATION, (data) => {
            addInsight({
                id: Date.now() + Math.random(),
                agent: data.agent,
                insight: data.recommendation,
                impact: data.impact || 'medium',
                timestamp: new Date()
            })
        })

        // Simulate real-time monitoring
        const monitoringInterval = setInterval(() => {
            updateAgentActivity()
        }, 20000) // Every 20 seconds

        return () => {
            eventBus.off(EVENTS.AGENT_ACTION, agentActionListener)
            eventBus.off(EVENTS.AGENT_ALERT, agentAlertListener)
            eventBus.off(EVENTS.AGENT_RECOMMENDATION, agentRecommendationListener)
            clearInterval(monitoringInterval)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    const fetchAndAnalyzeUserData = async () => {
        try {
            setIsAnalyzing(true)

            // Fetch real user expenses
            const expensesRes = await fetch('/api/expenses')
            const expensesData = await expensesRes.json()

            if (expensesData.expenses && expensesData.expenses.length > 0) {
                setUserData(expensesData)
                analyzeRealData(expensesData)
            } else {
                // No data yet - show welcome messages
                setIsAnalyzing(false)
            }
        } catch (error) {
            console.error('Failed to fetch user data:', error)
            setIsAnalyzing(false)
        }
    }

    const analyzeRealData = (data) => {
        const expenses = data.expenses || []
        const currentMonth = new Date().toISOString().slice(0, 7)

        // Calculate real metrics
        const thisMonthExpenses = expenses.filter(e => e.date && e.date.startsWith(currentMonth))
        const totalThisMonth = thisMonthExpenses.reduce((sum, e) => sum + e.amount, 0)
        const expenseCount = thisMonthExpenses.length

        // Category breakdown
        const categoryTotals = {}
        thisMonthExpenses.forEach(e => {
            categoryTotals[e.category] = (categoryTotals[e.category] || 0) + e.amount
        })

        const topCategory = Object.entries(categoryTotals)
            .sort((a, b) => b[1] - a[1])[0]

        // Generate REAL insights based on actual data
        const realActivities = [
            {
                id: Date.now() + 1,
                agent: 'Spending Agent',
                icon: '🧠',
                action: `Analyzed ${expenseCount} expenses this month totaling ₹${totalThisMonth.toLocaleString('en-IN')}`,
                type: 'analysis',
                timestamp: new Date(),
                confidence: 0.95
            }
        ]

        const realInsights = []

        if (topCategory) {
            realInsights.push({
                id: Date.now() + 1,
                agent: 'Spending Agent',
                insight: `Your highest spending is in ${topCategory[0]}: ₹${topCategory[1].toLocaleString('en-IN')} (${Math.round(topCategory[1] / totalThisMonth * 100)}% of total). Consider if this aligns with your priorities.`,
                impact: 'high',
                timestamp: new Date()
            })

            realActivities.push({
                id: Date.now() + 2,
                agent: 'Spending Agent',
                icon: '🧠',
                action: `Detected spending pattern: ${topCategory[0]} is your top category`,
                type: 'pattern',
                timestamp: new Date(Date.now() - 1000),
                confidence: 0.92
            })
        }

        // Check if spending seems high
        if (totalThisMonth > 15000) {
            realInsights.push({
                id: Date.now() + 2,
                agent: 'Coach Agent',
                insight: `You've spent ₹${totalThisMonth.toLocaleString('en-IN')} this month. Review your biggest expenses to find saving opportunities.`,
                impact: 'medium',
                timestamp: new Date()
            })
        } else if (totalThisMonth > 0) {
            realInsights.push({
                id: Date.now() + 3,
                agent: 'Coach Agent',
                insight: `Good discipline! You've kept spending at ₹${totalThisMonth.toLocaleString('en-IN')} this month. Keep tracking consistently.`,
                impact: 'low',
                timestamp: new Date()
            })
        }

        // Income analysis (if available)
        if (data.income && data.income.length > 0) {
            const thisMonthIncome = data.income.filter(i => i.date && i.date.startsWith(currentMonth))
            const totalIncome = thisMonthIncome.reduce((sum, i) => sum + i.amount, 0)

            if (totalIncome > 0) {
                const savingsRate = Math.round((totalIncome - totalThisMonth) / totalIncome * 100)

                realActivities.push({
                    id: Date.now() + 3,
                    agent: 'Income Agent',
                    icon: '💰',
                    action: `Calculated your savings rate: ${savingsRate}%`,
                    type: 'analysis',
                    timestamp: new Date(Date.now() - 2000),
                    confidence: 0.98
                })

                if (savingsRate >= 20) {
                    realInsights.push({
                        id: Date.now() + 4,
                        agent: 'Income Agent',
                        insight: `Excellent! You're saving ${savingsRate}% of your income (₹${(totalIncome - totalThisMonth).toLocaleString('en-IN')}). This is above the recommended 20%.`,
                        impact: 'high',
                        timestamp: new Date()
                    })
                } else if (savingsRate > 0) {
                    realInsights.push({
                        id: Date.now() + 4,
                        agent: 'Income Agent',
                        insight: `You're saving ${savingsRate}% (₹${(totalIncome - totalThisMonth).toLocaleString('en-IN')}). Try to increase this to 20% for better financial security.`,
                        impact: 'medium',
                        timestamp: new Date()
                    })
                } else {
                    realInsights.push({
                        id: Date.now() + 4,
                        agent: 'Income Agent',
                        insight: `⚠️ Your expenses (₹${totalThisMonth.toLocaleString('en-IN')}) exceeded income (₹${totalIncome.toLocaleString('en-IN')}). Review your spending urgently.`,
                        impact: 'high',
                        timestamp: new Date()
                    })

                    addAlert({
                        id: Date.now() + 100,
                        agent: 'Income Agent',
                        message: `Budget alert: You're spending more than earning this month. Gap: ₹${(totalThisMonth - totalIncome).toLocaleString('en-IN')}`,
                        severity: 'critical',
                        timestamp: new Date()
                    })
                }
            }
        }

        // Add real activities and insights
        setActivities(prev => [...realActivities, ...prev])
        setInsights(prev => [...realInsights, ...prev])

        setIsAnalyzing(false)

        console.log('✅ Real user data analyzed:', {
            expenseCount,
            totalThisMonth,
            topCategory: topCategory ? topCategory[0] : 'None',
            insightsGenerated: realInsights.length
        })
    }

    const initializeDashboard = () => {
        const welcomeActivities = [
            {
                id: 1,
                agent: 'Income Agent',
                icon: '💰',
                action: 'Initialized and monitoring your income patterns',
                type: 'info',
                timestamp: new Date(),
                confidence: 1.0
            },
            {
                id: 2,
                agent: 'Spending Agent',
                icon: '🧠',
                action: 'Learning your spending behavior and preferences',
                type: 'info',
                timestamp: new Date(Date.now() - 1000),
                confidence: 1.0
            },
            {
                id: 3,
                agent: 'Coach Agent',
                icon: '🎯',
                action: 'Ready to provide personalized financial guidance',
                type: 'info',
                timestamp: new Date(Date.now() - 2000),
                confidence: 1.0
            }
        ]

        const welcomeInsights = [
            {
                id: 1,
                agent: 'Getting Started',
                insight: 'Add your first expense! Go to "Expenses" tab and track a purchase. I\'ll analyze it immediately and show you spending patterns.',
                impact: 'high',
                timestamp: new Date()
            },
            {
                id: 2,
                agent: 'Spending Agent',
                insight: 'Once you add 5+ expenses, I can detect your spending patterns by category, day of week, and time - helping you avoid overspending.',
                impact: 'medium',
                timestamp: new Date()
            },
            {
                id: 3,
                agent: 'Income Agent',
                insight: 'Track your income sources to get a personalized flex budget that adapts to earning variability - perfect for freelancers and gig workers.',
                impact: 'medium',
                timestamp: new Date()
            },
            {
                id: 4,
                agent: 'Coach Agent',
                insight: 'Set financial goals in the Goals section. I\'ll automatically track progress and suggest optimizations to reach them faster.',
                impact: 'medium',
                timestamp: new Date()
            }
        ]

        const welcomeAlerts = [
            {
                id: 1,
                agent: 'System',
                message: 'AI Agents are now active and monitoring your financial activity',
                severity: 'success',
                timestamp: new Date()
            }
        ]

        setActivities(welcomeActivities)
        setInsights(welcomeInsights)
        setAlerts(welcomeAlerts)
    }

    const getAgentIcon = (agentName) => {
        const icons = {
            'Income Agent': '💰',
            'IncomeAgent': '💰',
            'Spending Agent': '🧠',
            'SpendingPatternAgent': '🧠',
            'Coach Agent': '🎯',
            'System': '⚙️'
        }
        return icons[agentName] || '🤖'
    }

    const addActivity = (activity) => {
        setActivities(prev => [activity, ...prev].slice(0, 20))

        const agentKey = activity.agent.toLowerCase().includes('income') ? 'income'
            : activity.agent.toLowerCase().includes('spending') ? 'spending'
                : 'coach'

        setAgents(prev => ({
            ...prev,
            [agentKey]: {
                ...prev[agentKey],
                actionsCount: prev[agentKey].actionsCount + 1,
                lastAction: activity.action
            }
        }))
    }

    const addAlert = (alert) => {
        setAlerts(prev => [alert, ...prev].slice(0, 10))
    }

    const addInsight = (insight) => {
        setInsights(prev => [insight, ...prev].slice(0, 10))
    }

    const updateAgentActivity = () => {
        const agentChecks = [
            'Analyzing recent transactions',
            'Monitoring spending patterns',
            'Checking budget adherence',
            'Evaluating saving opportunities',
            'Reviewing income stability'
        ]

        const randomCheck = agentChecks[Math.floor(Math.random() * agentChecks.length)]
        const randomAgent = ['Income Agent', 'Spending Agent', 'Coach Agent'][Math.floor(Math.random() * 3)]

        if (Math.random() > 0.7) {
            addActivity({
                id: Date.now(),
                agent: randomAgent,
                icon: getAgentIcon(randomAgent),
                action: randomCheck,
                type: 'monitoring',
                timestamp: new Date(),
                confidence: 0.75
            })
        }
    }

    const refreshStatus = () => {
        setAgents({
            income: { status: 'active', lastAction: 'Monitoring income patterns', actionsCount: agents.income.actionsCount },
            spending: { status: 'active', lastAction: 'Learning spending habits', actionsCount: agents.spending.actionsCount },
            coach: { status: 'active', lastAction: 'Ready to provide recommendations', actionsCount: agents.coach.actionsCount }
        })

        addActivity({
            id: Date.now(),
            agent: 'System',
            icon: '⚙️',
            action: 'Status refreshed - All agents operational',
            type: 'system',
            timestamp: new Date(),
            confidence: 1.0
        })
    }

    const formatTime = (date) => {
        return new Date(date).toLocaleTimeString('en-US', {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        })
    }

    const getConfidenceBadge = (confidence) => {
        const percentage = Math.round(confidence * 100)
        return (
            <Badge variant="secondary" className="text-xs bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-300">
                {percentage}% confidence
            </Badge>
        )
    }

    const getSeverityColor = (severity) => {
        const colors = {
            critical: 'border-l-4 border-red-500 bg-red-50 dark:bg-red-950/20',
            warning: 'border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-950/20',
            info: 'border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-950/20',
            success: 'border-l-4 border-teal-500 bg-teal-50 dark:bg-teal-950/20'
        }
        return colors[severity] || colors.info
    }

    const getImpactIcon = (impact) => {
        const icons = {
            high: <Zap className="h-4 w-4 text-teal-600" />,
            medium: <TrendingUp className="h-4 w-4 text-blue-600" />,
            low: <Info className="h-4 w-4 text-gray-600" />
        }
        return icons[impact] || icons.medium
    }

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            {/* Beta Banner */}
            <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 p-4 shadow-lg">
                <div className="absolute inset-0 bg-grid-white/10 [mask-image:linear-gradient(0deg,transparent,white)] pointer-events-none" />
                <div className="relative flex items-start gap-4">
                    <div className="flex-shrink-0">
                        <Sparkles className="h-6 w-6 text-white animate-pulse" />
                    </div>
                    <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                            <h3 className="text-lg font-bold text-white">Beta Feature - AI Agents</h3>
                            <span className="px-2 py-1 text-xs font-bold bg-white/20 backdrop-blur-sm text-white rounded-full border border-white/30">
                                IN PROGRESS
                            </span>
                        </div>
                        <p className="text-sm text-white/90 leading-relaxed">
                            Our autonomous AI agents are learning and improving! Features may evolve as we enhance their capabilities based on your feedback.
                        </p>
                    </div>
                </div>
            </div>

            {/* Header */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight flex items-center gap-2 text-gray-900 dark:text-white">
                        <Brain className="h-8 w-8 text-teal-600" />
                        Autonomous AI Agents
                    </h2>
                    <p className="text-gray-600 dark:text-gray-400 mt-1">
                        Your personal financial coaching team working 24/7
                    </p>
                </div>
                <Button
                    variant="outline"
                    onClick={refreshStatus}
                    className="border-teal-600 text-teal-600 hover:bg-teal-50 dark:hover:bg-teal-950/20"
                >
                    <Activity className="h-4 w-4 mr-2" />
                    Refresh Status
                </Button>
            </div>

            {/* Agent Status Cards */}
            <div className="grid gap-4 md:grid-cols-3">
                {/* Income Agent Card */}
                <Card className="border-l-4 border-l-teal-500 hover:shadow-lg transition-shadow">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <span className="text-2xl">💰</span>
                            Income Agent
                        </CardTitle>
                        <CheckCircle className="h-4 w-4 text-teal-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-teal-600">{agents.income.actionsCount}</div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">
                            Actions taken today
                        </p>
                        <div className="mt-3">
                            <Badge className="bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-300">
                                active
                            </Badge>
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-3 leading-relaxed">
                            Monitors income variability & creates flex budgets
                        </p>
                    </CardContent>
                </Card>

                {/* Spending Agent Card */}
                <Card className="border-l-4 border-l-purple-500 hover:shadow-lg transition-shadow">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <span className="text-2xl">🧠</span>
                            Spending Agent
                        </CardTitle>
                        <CheckCircle className="h-4 w-4 text-purple-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-purple-600">{agents.spending.actionsCount}</div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">
                            Patterns detected
                        </p>
                        <div className="mt-3">
                            <Badge className="bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300">
                                active
                            </Badge>
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-3 leading-relaxed">
                            Learns spending habits & provides proactive alerts
                        </p>
                    </CardContent>
                </Card>

                {/* Coach Agent Card */}
                <Card className="border-l-4 border-l-blue-500 hover:shadow-lg transition-shadow">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <span className="text-2xl">🎯</span>
                            Coach Agent
                        </CardTitle>
                        <CheckCircle className="h-4 w-4 text-blue-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-blue-600">{agents.coach.actionsCount}</div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">
                            Recommendations given
                        </p>
                        <div className="mt-3">
                            <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
                                active
                            </Badge>
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-3 leading-relaxed">
                            Context-aware coaching & personalized advice
                        </p>
                    </CardContent>
                </Card>
            </div>

            {/* Tabs Section */}
            <Tabs defaultValue="activity" className="w-full">
                <TabsList className="grid w-full grid-cols-3 bg-gray-100 dark:bg-gray-800">
                    <TabsTrigger value="activity" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white">
                        <Activity className="h-4 w-4 mr-2" />
                        Live Activity
                    </TabsTrigger>
                    <TabsTrigger value="alerts" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white">
                        <AlertCircle className="h-4 w-4 mr-2" />
                        Proactive Alerts
                    </TabsTrigger>
                    <TabsTrigger value="insights" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white">
                        <Sparkles className="h-4 w-4 mr-2" />
                        Insights
                    </TabsTrigger>
                </TabsList>

                {/* Live Activity Tab */}
                <TabsContent value="activity" className="space-y-4 mt-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-xl flex items-center gap-2">
                                <Activity className="h-5 w-5 text-teal-600" />
                                Real-Time Agent Activity
                            </CardTitle>
                            <CardDescription>
                                See what your AI agents are doing in real-time
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-3">
                                {activities.length === 0 ? (
                                    <div className="text-center py-8 text-gray-500">
                                        <Activity className="h-12 w-12 mx-auto mb-3 opacity-30" />
                                        <p>No activity yet. Start using the app to see agents in action!</p>
                                    </div>
                                ) : (
                                    activities.map((activity) => (
                                        <div
                                            key={activity.id}
                                            className="flex items-start gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/50 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                                        >
                                            <div className="text-2xl flex-shrink-0">{activity.icon}</div>
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="font-medium text-sm text-gray-900 dark:text-white">
                                                        {activity.agent}
                                                    </span>
                                                    {getConfidenceBadge(activity.confidence)}
                                                </div>
                                                <p className="text-sm text-gray-700 dark:text-gray-300">
                                                    {activity.action}
                                                </p>
                                            </div>
                                            <div className="text-xs text-gray-500 flex-shrink-0">
                                                {formatTime(activity.timestamp)}
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                {/* Proactive Alerts Tab */}
                <TabsContent value="alerts" className="space-y-4 mt-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-xl flex items-center gap-2">
                                <AlertCircle className="h-5 w-5 text-amber-600" />
                                Proactive Alerts
                            </CardTitle>
                            <CardDescription>
                                Important notifications and warnings from your agents
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-3">
                                {alerts.length === 0 ? (
                                    <div className="text-center py-8 text-gray-500">
                                        <AlertCircle className="h-12 w-12 mx-auto mb-3 opacity-30" />
                                        <p>No alerts at the moment. Your finances look good!</p>
                                    </div>
                                ) : (
                                    alerts.map((alert) => (
                                        <div
                                            key={alert.id}
                                            className={`p-4 rounded-lg ${getSeverityColor(alert.severity)}`}
                                        >
                                            <div className="flex items-start gap-3">
                                                <AlertCircle className="h-5 w-5 flex-shrink-0 mt-0.5" />
                                                <div className="flex-1">
                                                    <div className="font-medium text-sm mb-1">{alert.agent}</div>
                                                    <p className="text-sm">{alert.message}</p>
                                                    <div className="text-xs opacity-70 mt-2">
                                                        {formatTime(alert.timestamp)}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                {/* Insights Tab */}
                <TabsContent value="insights" className="space-y-4 mt-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-xl flex items-center gap-2">
                                <Sparkles className="h-5 w-5 text-teal-600" />
                                AI-Powered Insights
                            </CardTitle>
                            <CardDescription>
                                Smart recommendations to improve your financial health
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-3">
                                {insights.length === 0 ? (
                                    <div className="text-center py-8 text-gray-500">
                                        <Sparkles className="h-12 w-12 mx-auto mb-3 opacity-30" />
                                        <p>No insights yet. Keep tracking your finances!</p>
                                    </div>
                                ) : (
                                    insights.map((insight) => (
                                        <div
                                            key={insight.id}
                                            className="p-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-gradient-to-r from-teal-50 to-blue-50 dark:from-teal-950/20 dark:to-blue-950/20 hover:shadow-md transition-shadow"
                                        >
                                            <div className="flex items-start gap-3">
                                                {getImpactIcon(insight.impact)}
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <span className="font-medium text-sm">{insight.agent}</span>
                                                        <Badge variant="outline" className="text-xs">
                                                            {insight.impact} impact
                                                        </Badge>
                                                    </div>
                                                    <p className="text-sm text-gray-700 dark:text-gray-300">
                                                        {insight.insight}
                                                    </p>
                                                    <div className="text-xs text-gray-500 mt-2">
                                                        {formatTime(insight.timestamp)}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>

            {/* Info Card */}
            <Card className="bg-gradient-to-r from-teal-50 to-blue-50 dark:from-teal-950/20 dark:to-blue-950/20 border-teal-200 dark:border-teal-800">
                <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                        <Info className="h-5 w-5 text-teal-600" />
                        How AI Agents Work
                    </CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-gray-700 dark:text-gray-300 space-y-2">
                    <p>
                        <strong className="text-teal-600">🤖 Autonomous Operation:</strong> Agents continuously monitor your financial activity without manual intervention.
                    </p>
                    <p>
                        <strong className="text-purple-600">📊 Pattern Learning:</strong> They learn from your behavior to provide personalized, context-aware recommendations.
                    </p>
                    <p>
                        <strong className="text-blue-600">⚡ Proactive Alerts:</strong> Get notified before problems occur, not after - helping you stay ahead of financial challenges.
                    </p>
                    <p>
                        <strong className="text-teal-600">🎯 Goal-Oriented:</strong> Agents work together to help you achieve your financial goals faster and more efficiently.
                    </p>
                </CardContent>
            </Card>
        </div>
    )
}
