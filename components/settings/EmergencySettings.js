'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  AlertTriangle,
  Bell,
  Mail,
  Moon,
  Clock,
  Shield,
  Save,
  RotateCcw,
  Wallet,
  TrendingUp,
  CreditCard,
  AlertCircle
} from 'lucide-react'
import toast from 'react-hot-toast'

const DEFAULT_SETTINGS = {
  enabled: true,
  emailAlertsEnabled: true,
  lowBalanceThreshold: 5000,
  criticalBalanceThreshold: 1000,
  budgetCriticalPercent: 100,
  unusualExpenseMultiplier: 3,
  quietHoursEnabled: true,
  quietHoursStart: 22,
  quietHoursEnd: 7,
  alertCooldownHours: 4,
  alertCategories: {
    lowBalance: true,
    budgetExceeded: true,
    unusualExpense: true,
    emiAtRisk: true
  }
}

export default function EmergencySettings({ initialSettings, onSave }) {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS)
  const [saving, setSaving] = useState(false)
  const [hasChanges, setHasChanges] = useState(false)

  useEffect(() => {
    if (initialSettings) {
      setSettings({
        ...DEFAULT_SETTINGS,
        ...initialSettings,
        alertCategories: {
          ...DEFAULT_SETTINGS.alertCategories,
          ...initialSettings?.alertCategories
        }
      })
    }
  }, [initialSettings])

  const handleChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }))
    setHasChanges(true)
  }

  const handleCategoryChange = (category, value) => {
    setSettings(prev => ({
      ...prev,
      alertCategories: {
        ...prev.alertCategories,
        [category]: value
      }
    }))
    setHasChanges(true)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      const response = await fetch('/api/profile/emergency-settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      })

      const data = await response.json()

      if (data.success) {
        toast.success('Emergency settings saved successfully')
        setHasChanges(false)
        if (onSave) onSave(settings)
      } else {
        throw new Error(data.error || 'Failed to save settings')
      }
    } catch (error) {
      console.error('Save emergency settings error:', error)
      toast.error('Failed to save settings. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  const handleReset = () => {
    setSettings(DEFAULT_SETTINGS)
    setHasChanges(true)
    toast.success('Settings reset to defaults')
  }

  const formatTime = (hour) => {
    const period = hour >= 12 ? 'PM' : 'AM'
    const displayHour = hour > 12 ? hour - 12 : hour === 0 ? 12 : hour
    return `${displayHour}:00 ${period}`
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              Emergency Alert Settings
            </CardTitle>
            <CardDescription>
              Configure alerts for financial emergencies
            </CardDescription>
          </div>
          <Switch
            checked={settings.enabled}
            onCheckedChange={(checked) => handleChange('enabled', checked)}
          />
        </div>
      </CardHeader>

      <CardContent className={`space-y-6 ${!settings.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        {/* Email Alerts Toggle */}
        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
          <div className="flex items-center gap-3">
            <Mail className="h-5 w-5 text-blue-600" />
            <div>
              <p className="font-medium text-slate-800">Email Notifications</p>
              <p className="text-sm text-slate-500">Receive emergency alerts via email</p>
            </div>
          </div>
          <Switch
            checked={settings.emailAlertsEnabled}
            onCheckedChange={(checked) => handleChange('emailAlertsEnabled', checked)}
          />
        </div>

        {/* Alert Categories */}
        <div className="space-y-4">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <Bell className="h-4 w-4" />
            Alert Categories
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Low Balance */}
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                <Wallet className="h-4 w-4 text-orange-500" />
                <span className="text-sm">Low Balance</span>
              </div>
              <Switch
                checked={settings.alertCategories.lowBalance}
                onCheckedChange={(checked) => handleCategoryChange('lowBalance', checked)}
              />
            </div>

            {/* Budget Exceeded */}
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-red-500" />
                <span className="text-sm">Budget Exceeded</span>
              </div>
              <Switch
                checked={settings.alertCategories.budgetExceeded}
                onCheckedChange={(checked) => handleCategoryChange('budgetExceeded', checked)}
              />
            </div>

            {/* Unusual Expense */}
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-purple-500" />
                <span className="text-sm">Unusual Expense</span>
              </div>
              <Switch
                checked={settings.alertCategories.unusualExpense}
                onCheckedChange={(checked) => handleCategoryChange('unusualExpense', checked)}
              />
            </div>

            {/* EMI at Risk */}
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                <CreditCard className="h-4 w-4 text-blue-500" />
                <span className="text-sm">EMI at Risk</span>
              </div>
              <Switch
                checked={settings.alertCategories.emiAtRisk}
                onCheckedChange={(checked) => handleCategoryChange('emiAtRisk', checked)}
              />
            </div>
          </div>
        </div>

        {/* Thresholds */}
        <div className="space-y-4">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Alert Thresholds
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Low Balance Threshold */}
            <div className="space-y-2">
              <Label htmlFor="lowBalanceThreshold" className="text-sm">
                Low Balance Warning
              </Label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">Rs.</span>
                <Input
                  id="lowBalanceThreshold"
                  type="number"
                  value={settings.lowBalanceThreshold}
                  onChange={(e) => handleChange('lowBalanceThreshold', parseInt(e.target.value) || 0)}
                  className="pl-10"
                  min="0"
                />
              </div>
              <p className="text-xs text-slate-500">Alert when balance falls below this amount</p>
            </div>

            {/* Critical Balance Threshold */}
            <div className="space-y-2">
              <Label htmlFor="criticalBalanceThreshold" className="text-sm">
                Critical Balance (Urgent)
              </Label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">Rs.</span>
                <Input
                  id="criticalBalanceThreshold"
                  type="number"
                  value={settings.criticalBalanceThreshold}
                  onChange={(e) => handleChange('criticalBalanceThreshold', parseInt(e.target.value) || 0)}
                  className="pl-10"
                  min="0"
                />
              </div>
              <p className="text-xs text-slate-500">Critical alert (bypasses quiet hours)</p>
            </div>

            {/* Budget Exceeded Threshold */}
            <div className="space-y-2">
              <Label htmlFor="budgetCriticalPercent" className="text-sm">
                Budget Exceeded Threshold
              </Label>
              <div className="relative">
                <Input
                  id="budgetCriticalPercent"
                  type="number"
                  value={settings.budgetCriticalPercent}
                  onChange={(e) => handleChange('budgetCriticalPercent', parseInt(e.target.value) || 100)}
                  className="pr-8"
                  min="50"
                  max="200"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500">%</span>
              </div>
              <p className="text-xs text-slate-500">Alert when spending exceeds this % of budget</p>
            </div>

            {/* Unusual Expense Multiplier */}
            <div className="space-y-2">
              <Label htmlFor="unusualExpenseMultiplier" className="text-sm">
                Unusual Expense Multiplier
              </Label>
              <div className="relative">
                <Input
                  id="unusualExpenseMultiplier"
                  type="number"
                  value={settings.unusualExpenseMultiplier}
                  onChange={(e) => handleChange('unusualExpenseMultiplier', parseFloat(e.target.value) || 3)}
                  className="pr-8"
                  min="2"
                  max="10"
                  step="0.5"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500">x</span>
              </div>
              <p className="text-xs text-slate-500">Alert when expense is X times your average</p>
            </div>
          </div>
        </div>

        {/* Quiet Hours */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="font-medium text-slate-800 flex items-center gap-2">
              <Moon className="h-4 w-4" />
              Quiet Hours
            </h4>
            <Switch
              checked={settings.quietHoursEnabled}
              onCheckedChange={(checked) => handleChange('quietHoursEnabled', checked)}
            />
          </div>

          <div className={`grid grid-cols-2 gap-4 ${!settings.quietHoursEnabled ? 'opacity-50' : ''}`}>
            <div className="space-y-2">
              <Label htmlFor="quietHoursStart" className="text-sm">Start Time</Label>
              <select
                id="quietHoursStart"
                value={settings.quietHoursStart}
                onChange={(e) => handleChange('quietHoursStart', parseInt(e.target.value))}
                className="w-full p-2 border rounded-md text-sm"
                disabled={!settings.quietHoursEnabled}
              >
                {Array.from({ length: 24 }, (_, i) => (
                  <option key={i} value={i}>{formatTime(i)}</option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="quietHoursEnd" className="text-sm">End Time</Label>
              <select
                id="quietHoursEnd"
                value={settings.quietHoursEnd}
                onChange={(e) => handleChange('quietHoursEnd', parseInt(e.target.value))}
                className="w-full p-2 border rounded-md text-sm"
                disabled={!settings.quietHoursEnabled}
              >
                {Array.from({ length: 24 }, (_, i) => (
                  <option key={i} value={i}>{formatTime(i)}</option>
                ))}
              </select>
            </div>
          </div>

          <p className="text-xs text-slate-500">
            Non-critical alerts will be delayed during quiet hours ({formatTime(settings.quietHoursStart)} - {formatTime(settings.quietHoursEnd)})
          </p>
        </div>

        {/* Alert Cooldown */}
        <div className="space-y-2">
          <h4 className="font-medium text-slate-800 flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Alert Cooldown
          </h4>
          <div className="flex items-center gap-4">
            <Input
              type="number"
              value={settings.alertCooldownHours}
              onChange={(e) => handleChange('alertCooldownHours', parseInt(e.target.value) || 1)}
              className="w-24"
              min="1"
              max="24"
            />
            <span className="text-sm text-slate-600">hours between similar alerts</span>
          </div>
          <p className="text-xs text-slate-500">
            Prevents alert spam by waiting before sending duplicate alerts
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-4 border-t">
          <Button
            variant="outline"
            onClick={handleReset}
            className="flex items-center gap-2"
          >
            <RotateCcw className="h-4 w-4" />
            Reset to Defaults
          </Button>

          <Button
            onClick={handleSave}
            disabled={saving || !hasChanges}
            className="flex items-center gap-2"
          >
            {saving ? (
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {saving ? 'Saving...' : 'Save Settings'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
