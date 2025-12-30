'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Settings,
  Bell,
  Globe,
  Moon,
  Sun,
  Shield,
  Download,
  Trash2,
  Save,
  RefreshCw,
  CheckCircle,
  Smartphone,
  Mail,
  IndianRupee
} from 'lucide-react'
import toast from 'react-hot-toast'

function SettingsContent() {
  const { data: session } = useSession()
  const { t, i18n } = useTranslation()
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(true)

  // Settings state
  const [settings, setSettings] = useState({
    // Notification preferences
    emailNotifications: true,
    pushNotifications: true,
    budgetAlerts: true,
    goalReminders: true,
    weeklyReports: true,
    monthlyReports: true,

    // Language & Display
    language: 'english',
    currency: 'INR',
    numberFormat: 'indian',
    dateFormat: 'DD/MM/YYYY',
    theme: 'system',

    // Privacy
    shareAnalytics: false,
    showInLeaderboard: false
  })

  // Load settings from API
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await fetch('/api/profile')
        const data = await response.json()

        if (data.success && data.profile?.budgetPreferences) {
          const prefs = data.profile.budgetPreferences
          setSettings(prev => ({
            ...prev,
            emailNotifications: prefs.emailNotifications ?? true,
            pushNotifications: prefs.pushNotifications ?? true,
            budgetAlerts: prefs.budgetAlerts ?? true,
            goalReminders: prefs.goalReminders ?? true,
            weeklyReports: prefs.weeklyReports ?? true,
            monthlyReports: prefs.monthlyReports ?? true,
            language: prefs.language || 'english',
            currency: prefs.currency || 'INR',
            numberFormat: prefs.numberFormat || 'indian',
            dateFormat: prefs.dateFormat || 'DD/MM/YYYY',
            theme: prefs.theme || 'system'
          }))
        }
      } catch (error) {
        console.error('Failed to load settings:', error)
      } finally {
        setLoading(false)
      }
    }

    if (session?.user) {
      fetchSettings()
    } else {
      setLoading(false)
    }
  }, [session])

  // Handle setting change
  const handleSettingChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }))

    // Handle language change immediately
    if (key === 'language') {
      const langMap = { 'hindi': 'hi', 'english': 'en', 'hinglish': 'hinglish' }
      i18n.changeLanguage(langMap[value] || 'en')
    }
  }

  // Save settings
  const saveSettings = async () => {
    setSaving(true)
    try {
      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          budgetPreferences: {
            emailNotifications: settings.emailNotifications,
            pushNotifications: settings.pushNotifications,
            budgetAlerts: settings.budgetAlerts,
            goalReminders: settings.goalReminders,
            weeklyReports: settings.weeklyReports,
            monthlyReports: settings.monthlyReports,
            language: settings.language,
            currency: settings.currency,
            numberFormat: settings.numberFormat,
            dateFormat: settings.dateFormat,
            theme: settings.theme
          }
        })
      })

      const data = await response.json()

      if (data.success) {
        toast.success('Settings saved successfully!')
      } else {
        toast.error(data.error || 'Failed to save settings')
      }
    } catch (error) {
      console.error('Save error:', error)
      toast.error('Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  // Export data
  const exportData = async () => {
    try {
      toast.loading('Preparing your data export...')

      const response = await fetch('/api/profile')
      const data = await response.json()

      if (data.success) {
        const exportData = {
          exportDate: new Date().toISOString(),
          profile: data.profile,
          // Remove sensitive data
          user: {
            name: session?.user?.name,
            email: session?.user?.email
          }
        }

        // Create downloadable file
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `wealthwise-export-${new Date().toISOString().split('T')[0]}.json`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)

        toast.dismiss()
        toast.success('Data exported successfully!')
      }
    } catch (error) {
      toast.dismiss()
      toast.error('Failed to export data')
    }
  }

  if (loading) {
    return (
      <DashboardLayout title="Settings">
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-emerald-600" />
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title={t('settings.title') || 'Settings'}>
      <div className="space-y-6 max-w-4xl">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-800 flex items-center gap-2">
              <Settings className="h-6 w-6 text-emerald-600" />
              Settings
            </h1>
            <p className="text-slate-600 mt-1">Manage your preferences and account settings</p>
          </div>
          <Button
            onClick={saveSettings}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-700"
          >
            {saving ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-2" />
            )}
            Save Changes
          </Button>
        </div>

        {/* Notification Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5 text-blue-600" />
              Notifications
            </CardTitle>
            <CardDescription>Choose how you want to be notified</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Mail className="h-5 w-5 text-slate-500" />
                  <div>
                    <Label className="font-medium">Email Notifications</Label>
                    <p className="text-sm text-slate-500">Receive updates via email</p>
                  </div>
                </div>
                <Switch
                  checked={settings.emailNotifications}
                  onCheckedChange={(checked) => handleSettingChange('emailNotifications', checked)}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5 text-slate-500" />
                  <div>
                    <Label className="font-medium">Push Notifications</Label>
                    <p className="text-sm text-slate-500">Get alerts on your device</p>
                  </div>
                </div>
                <Switch
                  checked={settings.pushNotifications}
                  onCheckedChange={(checked) => handleSettingChange('pushNotifications', checked)}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <IndianRupee className="h-5 w-5 text-slate-500" />
                  <div>
                    <Label className="font-medium">Budget Alerts</Label>
                    <p className="text-sm text-slate-500">Alert when approaching budget limits</p>
                  </div>
                </div>
                <Switch
                  checked={settings.budgetAlerts}
                  onCheckedChange={(checked) => handleSettingChange('budgetAlerts', checked)}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-5 w-5 text-slate-500" />
                  <div>
                    <Label className="font-medium">Goal Reminders</Label>
                    <p className="text-sm text-slate-500">Reminders about your savings goals</p>
                  </div>
                </div>
                <Switch
                  checked={settings.goalReminders}
                  onCheckedChange={(checked) => handleSettingChange('goalReminders', checked)}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Mail className="h-5 w-5 text-slate-500" />
                  <div>
                    <Label className="font-medium">Weekly Reports</Label>
                    <p className="text-sm text-slate-500">Weekly financial summary emails</p>
                  </div>
                </div>
                <Switch
                  checked={settings.weeklyReports}
                  onCheckedChange={(checked) => handleSettingChange('weeklyReports', checked)}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Language & Display */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-purple-600" />
              Language & Display
            </CardTitle>
            <CardDescription>Customize how the app looks and feels</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Language</Label>
                <Select
                  value={settings.language}
                  onValueChange={(value) => handleSettingChange('language', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select language" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="english">English</SelectItem>
                    <SelectItem value="hindi">हिंदी (Hindi)</SelectItem>
                    <SelectItem value="hinglish">Hinglish</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Currency</Label>
                <Select
                  value={settings.currency}
                  onValueChange={(value) => handleSettingChange('currency', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select currency" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="INR">₹ INR (Indian Rupee)</SelectItem>
                    <SelectItem value="USD">$ USD (US Dollar)</SelectItem>
                    <SelectItem value="EUR">€ EUR (Euro)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Number Format</Label>
                <Select
                  value={settings.numberFormat}
                  onValueChange={(value) => handleSettingChange('numberFormat', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select format" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="indian">Indian (1,00,000)</SelectItem>
                    <SelectItem value="international">International (100,000)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Date Format</Label>
                <Select
                  value={settings.dateFormat}
                  onValueChange={(value) => handleSettingChange('dateFormat', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select format" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="DD/MM/YYYY">DD/MM/YYYY</SelectItem>
                    <SelectItem value="MM/DD/YYYY">MM/DD/YYYY</SelectItem>
                    <SelectItem value="YYYY-MM-DD">YYYY-MM-DD</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Theme</Label>
                <Select
                  value={settings.theme}
                  onValueChange={(value) => handleSettingChange('theme', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select theme" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="light">
                      <div className="flex items-center gap-2">
                        <Sun className="h-4 w-4" />
                        Light
                      </div>
                    </SelectItem>
                    <SelectItem value="dark">
                      <div className="flex items-center gap-2">
                        <Moon className="h-4 w-4" />
                        Dark
                      </div>
                    </SelectItem>
                    <SelectItem value="system">System Default</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Privacy & Data */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-emerald-600" />
              Privacy & Data
            </CardTitle>
            <CardDescription>Manage your data and privacy settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <Label className="font-medium">Share Analytics</Label>
                <p className="text-sm text-slate-500">Help improve the app with anonymous usage data</p>
              </div>
              <Switch
                checked={settings.shareAnalytics}
                onCheckedChange={(checked) => handleSettingChange('shareAnalytics', checked)}
              />
            </div>

            <div className="pt-4 border-t space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label className="font-medium">Export Your Data</Label>
                  <p className="text-sm text-slate-500">Download all your financial data</p>
                </div>
                <Button variant="outline" onClick={exportData}>
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* App Info */}
        <Card className="bg-slate-50">
          <CardContent className="pt-6">
            <div className="text-center space-y-2">
              <h3 className="font-semibold text-slate-800">WealthWise</h3>
              <p className="text-sm text-slate-600">AI-Powered Personal Finance for India</p>
              <p className="text-xs text-slate-500">Version 2.0.0</p>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}

export default function SettingsPage() {
  return (
    <OnboardingGuard>
      <SettingsContent />
    </OnboardingGuard>
  )
}
