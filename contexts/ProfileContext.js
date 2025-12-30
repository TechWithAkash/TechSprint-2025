'use client'

import { createContext, useContext, useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'

const ProfileContext = createContext()

export function ProfileProvider({ children }) {
  const { data: session } = useSession()
  const [profileImage, setProfileImage] = useState('')
  const [profileData, setProfileData] = useState(null)
  const [loading, setLoading] = useState(true)

  // Load profile data when session is available
  useEffect(() => {
    const loadProfile = async () => {
      if (!session?.user?.email) {
        setLoading(false)
        return
      }

      try {
        const response = await fetch('/api/profile')
        const data = await response.json()
        
        if (data.success) {
          setProfileData(data.profile)
          setProfileImage(data.profile.image || session.user.image || '')
        } else {
          // Fallback to session data
          setProfileImage(session.user.image || '')
        }
      } catch (error) {
        console.error('Failed to load profile:', error)
        // Fallback to session data
        setProfileImage(session.user.image || '')
      } finally {
        setLoading(false)
      }
    }

    loadProfile()
  }, [session])

  const updateProfileImage = (newImage) => {
    setProfileImage(newImage)
  }

  const updateProfileData = (newData) => {
    setProfileData(newData)
    if (newData.image) {
      setProfileImage(newData.image)
    }
  }

  const value = {
    profileImage,
    profileData,
    loading,
    updateProfileImage,
    updateProfileData
  }

  return (
    <ProfileContext.Provider value={value}>
      {children}
    </ProfileContext.Provider>
  )
}

export function useProfile() {
  const context = useContext(ProfileContext)
  if (!context) {
    throw new Error('useProfile must be used within a ProfileProvider')
  }
  return context
}
