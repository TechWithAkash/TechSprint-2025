'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { TrendingUp, Target, Award, Zap, TrendingDown } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'

export default function WealthGrowthTracker({ simulatedInvestments = [] }) {
  const [totalInvested, setTotalInvested] = useState(0)
  const [currentValue, setCurrentValue] = useState(0)
  const [totalGains, setTotalGains] = useState(0)
  const [achievements, setAchievements] = useState([])

  // Sample data for demonstration
  const sampleInvestments = [
    { date: '2025-08-01', amount: 1500, type: 'Nifty Drop', performance: 18.5 },
    { date: '2025-08-03', amount: 2000, type: 'Banking Dip', performance: 22.1 },
    { date: '2025-08-05', amount: 1000, type: 'Market Correction', performance: 15.7 }
  ]

  const investments = simulatedInvestments.length > 0 ? simulatedInvestments : sampleInvestments

  // Chart data
  const chartData = investments.map((inv, index) => ({
    date: new Date(inv.date).toLocaleDateString(),
    investment: inv.amount,
    value: inv.amount * (1 + inv.performance / 100),
    cumulative: investments.slice(0, index + 1).reduce((sum, i) => sum + (i.amount * (1 + i.performance / 100)), 0)
  }))

  const futureProjections = [
    { year: '2027', value: Math.round(currentValue * 1.3), growth: '30%' },
    { year: '2030', value: Math.round(currentValue * 1.7), growth: '70%' },
    { year: '2035', value: Math.round(currentValue * 2.4), growth: '140%' }
  ]

  const performanceVsMarket = {
    yourTiming: ((currentValue - totalInvested) / totalInvested * 100).toFixed(1),
    marketAverage: '12.4',
    bonus: (((currentValue - totalInvested) / totalInvested * 100) - 12.4).toFixed(1)
  }

  return (
    <div className="space-y-6">
      
      {/* Portfolio Overview */}
      <Card className="bg-gradient-to-r from-emerald-500 to-blue-600 text-white border-0 shadow-lg">
        <CardContent className="p-6">
          <div className="text-center">
            <h3 className="text-lg font-medium text-emerald-100 mb-2">
              💰 Your Simulated Wealth Journey
            </h3>
            <div className="text-3xl font-bold mb-2">
              ₹{totalInvested.toLocaleString('en-IN')} → ₹{Math.round(currentValue).toLocaleString('en-IN')}
            </div>
            <div className="flex items-center justify-center space-x-2 text-emerald-100">
              <TrendingUp className="h-4 w-4" />
              <span>+₹{Math.round(totalGains).toLocaleString('en-IN')} ({((totalGains/totalInvested)*100).toFixed(1)}%)</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Investment History & Performance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Investment History */}
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="text-lg font-bold text-gray-900">
              🎯 Simulation History
            </CardTitle>
            <CardDescription>Your simulated investment timeline</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {investments.map((investment, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                >
                  <div>
                    <p className="font-medium text-gray-900">
                      {new Date(investment.date).toLocaleDateString()}
                    </p>
                    <p className="text-sm text-gray-600">{investment.type}</p>
                  </div>
                  <div className="text-right">
                    <p className="font-bold text-gray-900">₹{investment.amount}</p>
                    <p className="text-sm text-emerald-600">+{investment.performance}%</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Performance vs Market */}
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="text-lg font-bold text-gray-900">
              📊 Performance vs Market
            </CardTitle>
            <CardDescription>How your timing compares to market average</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center p-3 bg-blue-50 rounded-lg">
                <span className="text-blue-700 font-medium">Your Timing:</span>
                <span className="text-blue-900 font-bold">+{performanceVsMarket.yourTiming}%</span>
              </div>
              
              <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                <span className="text-gray-700 font-medium">Market Average:</span>
                <span className="text-gray-900 font-bold">+{performanceVsMarket.marketAverage}%</span>
              </div>
              
              <div className="flex justify-between items-center p-3 bg-emerald-50 rounded-lg">
                <span className="text-emerald-700 font-medium">Smart Timing Bonus:</span>
                <span className="text-emerald-900 font-bold">
                  +{performanceVsMarket.bonus}% 🎉
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Future Projections */}
      <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
        <CardHeader>
          <CardTitle className="text-lg font-bold text-gray-900">
            🔮 Future Projections
          </CardTitle>
          <CardDescription>Continue this pattern - here&apos;s what you could build</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {futureProjections.map((projection, index) => (
              <div
                key={projection.year}
                className="text-center p-4 bg-gradient-to-b from-blue-50 to-purple-50 rounded-lg border"
              >
                <p className="text-sm text-gray-600 mb-1">{projection.year}</p>
                <p className="text-xl font-bold text-gray-900">
                  ₹{projection.value.toLocaleString('en-IN')}
                </p>
                <p className="text-sm text-emerald-600 font-medium">
                  {projection.growth} growth
                </p>
              </div>
            ))}
          </div>
          
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-yellow-800 text-sm font-medium">
              💡 These are educational simulations based on historical market patterns. 
              Continue learning to build real wealth-building habits!
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Achievements */}
      {achievements.length > 0 && (
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="text-lg font-bold text-gray-900">
              🏆 Investment Achievements
            </CardTitle>
            <CardDescription>Milestones you&apos;ve unlocked in your journey</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {achievements.map((achievement) => (
                <div
                  key={achievement.id}
                  className={`p-4 rounded-lg border-2 border-${achievement.color}-200 bg-${achievement.color}-50`}
                >
                  <div className="flex items-center mb-2">
                    <achievement.icon className={`h-5 w-5 text-${achievement.color}-600 mr-2`} />
                    <span className={`font-bold text-${achievement.color}-800`}>
                      {achievement.title}
                    </span>
                  </div>
                  <p className={`text-sm text-${achievement.color}-700 mb-2`}>
                    {achievement.description}
                  </p>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className={`bg-${achievement.color}-500 h-2 rounded-full transition-all`}
                      style={{ width: `${achievement.progress}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Portfolio Chart */}
      {chartData.length > 0 && (
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="text-lg font-bold text-gray-900">
              📈 Portfolio Growth Chart
            </CardTitle>
            <CardDescription>Your simulated investment journey over time</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip 
                    formatter={(value, name) => [
                      `₹${Math.round(value).toLocaleString('en-IN')}`, 
                      name === 'cumulative' ? 'Portfolio Value' : 'Investment'
                    ]}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="cumulative" 
                    stroke="#059669" 
                    strokeWidth={3}
                    dot={{ fill: '#059669', strokeWidth: 2, r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
