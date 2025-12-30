'use client'

import { useState, useRef, useEffect } from 'react'
import { useSession, signOut } from 'next-auth/react'
import { useTranslation } from '@/lib/i18n'
import { useProfile } from '@/contexts/ProfileContext'
import DashboardLayout from '@/components/layout/DashboardLayout'
import OnboardingGuard from '@/components/OnboardingGuard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import {
  User,
  Mail,
  Phone,
  MapPin,
  Camera,
  Save,
  Edit3,
  X,
  Calendar,
  Briefcase,
  LogOut,
  Trash2,
  AlertTriangle,
  Bell
} from 'lucide-react'
import toast from 'react-hot-toast'
import Image from 'next/image'

// Skeleton Component
function ProfileSkeleton() {
  return (
    <div className="space-y-4 max-w-3xl mx-auto animate-pulse">
      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <div className="flex items-start gap-6">
          <div className="w-24 h-24 bg-slate-200 rounded-full" />
          <div className="flex-1 space-y-3">
            <div className="h-6 w-40 bg-slate-200 rounded" />
            <div className="h-4 w-56 bg-slate-200 rounded" />
            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="h-10 bg-slate-100 rounded" />
              <div className="h-10 bg-slate-100 rounded" />
            </div>
          </div>
        </div>
      </div>
      <div className="bg-white rounded-xl border border-slate-200 p-6 h-40" />
    </div>
  )
}

function ProfileContent() {
  const { data: session, status } = useSession()
  const { profileImage, profileData, updateProfileData } = useProfile()
  const { t } = useTranslation()
  const [isEditing, setIsEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [localProfileImage, setLocalProfileImage] = useState(profileImage)
  const fileInputRef = useRef(null)

  const [profile, setProfile] = useState({
    name: '',
    email: '',
    phone: '',
    location: '',
    bio: '',
    dateOfBirth: '',
    occupation: ''
  })

  // Update local state when profileData or session changes
  useEffect(() => {
    if (profileData) {
      setProfile({
        name: profileData.name || session?.user?.name || '',
        email: profileData.email || session?.user?.email || '',
        phone: profileData.phone || '',
        location: profileData.location || '',
        bio: profileData.bio || '',
        dateOfBirth: profileData.dateOfBirth || '',
        occupation: profileData.occupation || ''
      })
    } else if (session?.user) {
      setProfile(prev => ({
        ...prev,
        name: session.user.name || '',
        email: session.user.email || ''
      }))
    }
    setLocalProfileImage(profileImage || session?.user?.image || '')
  }, [profileData, profileImage, session])

  const handleImageUpload = (event) => {
    const file = event.target.files[0]
    if (file) {
      if (file.size > 5 * 1024 * 1024) {
        toast.error(t('profile.imageSizeError'))
        return
      }

      const reader = new FileReader()
      reader.onload = (e) => {
        setLocalProfileImage(e.target.result)
        toast.success(t('profile.photoUpdated'))
      }
      reader.readAsDataURL(file)
    }
  }

  const handleSaveProfile = async () => {
    setSaving(true)
    try {
      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...profile,
          image: localProfileImage
        })
      })

      const data = await response.json()

      if (data.success) {
        setIsEditing(false)
        toast.success(t('profile.profileUpdated'))
        updateProfileData(data.profile)
      } else {
        throw new Error(data.error || 'Failed to update profile')
      }
    } catch (error) {
      console.error('Profile update error:', error)
      toast.error('Failed to update profile. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  const handleCancel = () => {
    setProfile({
      name: profileData?.name || session?.user?.name || '',
      email: profileData?.email || session?.user?.email || '',
      phone: profileData?.phone || '',
      location: profileData?.location || '',
      bio: profileData?.bio || '',
      dateOfBirth: profileData?.dateOfBirth || '',
      occupation: profileData?.occupation || ''
    })
    setLocalProfileImage(profileImage || session?.user?.image || '')
    setIsEditing(false)
  }

  const getInitials = () => {
    const name = profile.name || session?.user?.name || 'U'
    return name.charAt(0).toUpperCase()
  }

  if (status === 'loading') {
    return (
      <DashboardLayout title={t('profile.title')}>
        <ProfileSkeleton />
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title={t('profile.title')}>
      <div className="max-w-3xl mx-auto space-y-4">
        {/* Profile Card */}
        <Card className="border-slate-200">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <User className="w-5 h-5 text-emerald-600" />
                {t('profile.myProfile')}
              </CardTitle>
              {!isEditing ? (
                <Button
                  onClick={() => setIsEditing(true)}
                  variant="outline"
                  size="sm"
                  className="gap-2"
                >
                  <Edit3 className="h-4 w-4" />
                  {t('profile.editProfile')}
                </Button>
              ) : (
                <div className="flex gap-2">
                  <Button
                    onClick={handleSaveProfile}
                    disabled={saving}
                    size="sm"
                    className="gap-2 bg-emerald-600 hover:bg-emerald-700"
                  >
                    {saving ? (
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Save className="h-4 w-4" />
                    )}
                    {saving ? t('profile.saving') : t('common.save')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleCancel}>
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </div>
            <p className="text-sm text-slate-500 mt-1">{t('profile.managePersonalInfo')}</p>
          </CardHeader>

          <CardContent>
            <div className="flex flex-col md:flex-row gap-6">
              {/* Profile Photo */}
              <div className="flex flex-col items-center">
                <div className="relative">
                  <div className="w-24 h-24 rounded-full overflow-hidden border-4 border-white shadow-lg relative">
                    {localProfileImage ? (
                      <Image
                        src={localProfileImage}
                        alt="Profile"
                        fill
                        className="object-cover"
                        unoptimized={localProfileImage?.startsWith('data:')}
                      />
                    ) : (
                      <div className="w-full h-full bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center">
                        <span className="text-3xl font-bold text-white">{getInitials()}</span>
                      </div>
                    )}
                  </div>

                  {isEditing && (
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      className="absolute bottom-0 right-0 bg-emerald-600 hover:bg-emerald-700 text-white rounded-full p-2 shadow-lg transition-colors"
                    >
                      <Camera className="h-4 w-4" />
                    </button>
                  )}
                </div>

                {isEditing && (
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="text-xs text-emerald-600 hover:text-emerald-700 mt-2"
                  >
                    {t('profile.changePhoto')}
                  </button>
                )}

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  onChange={handleImageUpload}
                  className="hidden"
                />
              </div>

              {/* Profile Fields */}
              <div className="flex-1 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Full Name */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <User className="w-3 h-3" />
                      {t('profile.fullName')}
                    </Label>
                    {isEditing ? (
                      <Input
                        value={profile.name}
                        onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                        placeholder={t('profile.enterFullName')}
                        className="h-9"
                      />
                    ) : (
                      <p className="text-sm font-medium text-slate-800">
                        {profile.name || t('profile.notProvided')}
                      </p>
                    )}
                  </div>

                  {/* Email */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <Mail className="w-3 h-3" />
                      {t('profile.emailAddress')}
                    </Label>
                    <p className="text-sm text-slate-800">
                      {profile.email}
                      <span className="text-xs text-slate-400 ml-1">{t('profile.cannotBeChanged')}</span>
                    </p>
                  </div>

                  {/* Phone */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <Phone className="w-3 h-3" />
                      {t('profile.phoneNumber')}
                    </Label>
                    {isEditing ? (
                      <Input
                        value={profile.phone}
                        onChange={(e) => setProfile({ ...profile, phone: e.target.value })}
                        placeholder="+91 98765 43210"
                        className="h-9"
                      />
                    ) : (
                      <p className="text-sm text-slate-800">
                        {profile.phone || <span className="text-slate-400">{t('profile.notProvided')}</span>}
                      </p>
                    )}
                  </div>

                  {/* Location */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <MapPin className="w-3 h-3" />
                      {t('profile.location')}
                    </Label>
                    {isEditing ? (
                      <Input
                        value={profile.location}
                        onChange={(e) => setProfile({ ...profile, location: e.target.value })}
                        placeholder="Mumbai, Maharashtra"
                        className="h-9"
                      />
                    ) : (
                      <p className="text-sm text-slate-800">
                        {profile.location || <span className="text-slate-400">{t('profile.notProvided')}</span>}
                      </p>
                    )}
                  </div>

                  {/* Date of Birth */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {t('profile.dateOfBirth')}
                    </Label>
                    {isEditing ? (
                      <Input
                        type="date"
                        value={profile.dateOfBirth}
                        onChange={(e) => setProfile({ ...profile, dateOfBirth: e.target.value })}
                        className="h-9"
                      />
                    ) : (
                      <p className="text-sm text-slate-800">
                        {profile.dateOfBirth
                          ? new Date(profile.dateOfBirth).toLocaleDateString('en-IN', {
                              day: 'numeric',
                              month: 'long',
                              year: 'numeric'
                            })
                          : <span className="text-slate-400">{t('profile.notProvided')}</span>
                        }
                      </p>
                    )}
                  </div>

                  {/* Occupation */}
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-500 flex items-center gap-1">
                      <Briefcase className="w-3 h-3" />
                      {t('profile.occupation')}
                    </Label>
                    {isEditing ? (
                      <Input
                        value={profile.occupation}
                        onChange={(e) => setProfile({ ...profile, occupation: e.target.value })}
                        placeholder="Software Engineer"
                        className="h-9"
                      />
                    ) : (
                      <p className="text-sm text-slate-800">
                        {profile.occupation || <span className="text-slate-400">{t('profile.notProvided')}</span>}
                      </p>
                    )}
                  </div>
                </div>

                {/* Bio */}
                <div className="space-y-1.5 pt-2">
                  <Label className="text-xs text-slate-500">{t('profile.aboutMe')}</Label>
                  {isEditing ? (
                    <Textarea
                      value={profile.bio}
                      onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
                      placeholder={t('profile.tellAboutYourself')}
                      rows={3}
                      className="resize-none"
                    />
                  ) : (
                    <div className="text-sm text-slate-700 bg-slate-50 p-3 rounded-lg min-h-[60px]">
                      {profile.bio || <span className="text-slate-400">{t('profile.noBioProvided')}</span>}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Notification Settings */}
        <Card className="border-slate-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
              <Bell className="w-4 h-4 text-blue-600" />
              Notification Preferences
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm font-medium text-slate-700">Email Notifications</p>
                  <p className="text-xs text-slate-500">Receive financial alerts via email</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" defaultChecked className="sr-only peer" />
                  <div className="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500"></div>
                </label>
              </div>
              <div className="flex items-center justify-between py-2 border-t border-slate-100">
                <div>
                  <p className="text-sm font-medium text-slate-700">Budget Alerts</p>
                  <p className="text-xs text-slate-500">Get notified when approaching budget limits</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" defaultChecked className="sr-only peer" />
                  <div className="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500"></div>
                </label>
              </div>
              <div className="flex items-center justify-between py-2 border-t border-slate-100">
                <div>
                  <p className="text-sm font-medium text-slate-700">Weekly Summary</p>
                  <p className="text-xs text-slate-500">Weekly financial summary report</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" className="sr-only peer" />
                  <div className="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500"></div>
                </label>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Account Actions */}
        <Card className="border-slate-200">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-700 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              {t('profile.accountActions')}
            </CardTitle>
            <p className="text-xs text-slate-500">{t('profile.manageAccountSettings')}</p>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3">
              <Button
                variant="outline"
                onClick={() => signOut({ callbackUrl: '/' })}
                className="gap-2 text-slate-600 hover:text-slate-800"
              >
                <LogOut className="w-4 h-4" />
                {t('profile.signOut')}
              </Button>

              <Button
                variant="outline"
                onClick={() => {
                  if (confirm(t('profile.deleteAccountConfirm'))) {
                    toast.error(t('profile.deleteAccountSoon'))
                  }
                }}
                className="gap-2 text-red-600 border-red-200 hover:bg-red-50 hover:border-red-300"
              >
                <Trash2 className="w-4 h-4" />
                {t('profile.deleteAccount')}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}

export default function ProfilePage() {
  return (
    <OnboardingGuard>
      <ProfileContent />
    </OnboardingGuard>
  )
}
