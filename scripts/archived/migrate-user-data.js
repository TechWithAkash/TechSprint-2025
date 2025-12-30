/**
 * User Data Migration Script
 * 
 * This script migrates existing user data to work with the new User and UserProfile schemas.
 * It handles:
 * - Creating User records for existing UserProfile data
 * - Updating language preferences to support new format
 * - Adding default values for new fields
 * - Ensuring data consistency between User and UserProfile models
 * 
 * Run this script after deploying the new schemas but before the application starts using them.
 */

import mongoose from 'mongoose'
import dbConnect from './lib/dbConnect.js'

// Import models
import User from './models/User.js'
import UserProfile from './models/UserProfile.js'

const migrateUserData = async () => {
  try {
    console.log('🔗 Connecting to database...')
    await dbConnect()
    
    console.log('🔄 Starting user data migration...')
    
    // Step 1: Get all existing UserProfile records
    console.log('\n📊 Analyzing existing data...')
    const existingProfiles = await UserProfile.find({}).lean()
    console.log(`Found ${existingProfiles.length} existing user profiles`)
    
    if (existingProfiles.length === 0) {
      console.log('✅ No existing profiles found. Migration not needed.')
      return
    }
    
    // Step 2: Check for existing User records (from NextAuth)
    const existingUsers = await User.find({}).lean()
    console.log(`Found ${existingUsers.length} existing user records`)
    
    // Step 3: Migrate UserProfile language preferences
    console.log('\n🌐 Migrating language preferences...')
    let profilesUpdated = 0
    
    for (const profile of existingProfiles) {
      const updates = {}
      let needsUpdate = false
      
      // Update language preferences format
      if (profile.budgetPreferences?.language) {
        const currentLang = profile.budgetPreferences.language
        
        // Map old language values to new format if needed
        const languageMap = {
          'hindi': 'hi',
          'english': 'en',
          'hinglish': 'hinglish'
        }
        
        if (languageMap[currentLang] && languageMap[currentLang] !== currentLang) {
          updates['budgetPreferences.language'] = languageMap[currentLang]
          needsUpdate = true
        }
      }
      
      // Add new preference fields with defaults
      const newPreferences = {
        'budgetPreferences.timezone': 'Asia/Kolkata',
        'budgetPreferences.dateFormat': 'DD/MM/YYYY',
        'budgetPreferences.numberFormat': 'indian',
        'budgetPreferences.theme': 'system',
        'budgetPreferences.emailNotifications': true,
        'budgetPreferences.pushNotifications': true,
        'budgetPreferences.budgetAlerts': true,
        'budgetPreferences.goalReminders': true,
        'budgetPreferences.weeklyReports': true,
        'budgetPreferences.monthlyReports': true
      }
      
      // Only add fields that don't exist
      for (const [field, defaultValue] of Object.entries(newPreferences)) {
        const fieldPath = field.split('.')
        let current = profile
        let exists = true
        
        for (const part of fieldPath) {
          if (current && typeof current === 'object' && part in current) {
            current = current[part]
          } else {
            exists = false
            break
          }
        }
        
        if (!exists) {
          updates[field] = defaultValue
          needsUpdate = true
        }
      }
      
      // Update currency enum validation
      if (profile.budgetPreferences?.currency) {
        const validCurrencies = ['INR', 'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD']
        if (!validCurrencies.includes(profile.budgetPreferences.currency)) {
          updates['budgetPreferences.currency'] = 'INR'
          needsUpdate = true
        }
      }
      
      if (needsUpdate) {
        await UserProfile.updateOne(
          { _id: profile._id },
          { $set: updates }
        )
        profilesUpdated++
      }
    }
    
    console.log(`✅ Updated ${profilesUpdated} user profiles with new preferences`)
    
    // Step 4: Create User records for profiles without corresponding users
    console.log('\n👤 Creating missing User records...')
    let usersCreated = 0
    
    for (const profile of existingProfiles) {
      // Check if User record exists for this profile
      const existingUser = existingUsers.find(user => 
        user._id.toString() === profile.userId?.toString()
      )
      
      if (!existingUser && profile.email) {
        // Create a new User record based on profile data
        const userData = {
          _id: profile.userId || new mongoose.Types.ObjectId(),
          email: profile.email,
          name: profile.name || profile.email.split('@')[0],
          image: profile.profileImage || null,
          emailVerified: null,
          
          // Map preferences from profile
          preferences: {
            language: profile.budgetPreferences?.language || 'hinglish',
            currency: profile.budgetPreferences?.currency || 'INR',
            timezone: 'Asia/Kolkata',
            dateFormat: 'DD/MM/YYYY',
            numberFormat: 'indian',
            
            notifications: {
              email: profile.budgetPreferences?.emailNotifications !== false,
              push: profile.budgetPreferences?.pushNotifications !== false,
              budgetAlerts: profile.budgetPreferences?.budgetAlerts !== false,
              goalReminders: profile.budgetPreferences?.goalReminders !== false,
              weeklyReports: profile.budgetPreferences?.weeklyReports !== false,
              monthlyReports: profile.budgetPreferences?.monthlyReports !== false
            },
            
            privacy: {
              shareData: false,
              analytics: true,
              profileVisibility: 'private'
            },
            
            theme: profile.budgetPreferences?.theme || 'system',
            
            dashboard: {
              defaultView: 'overview',
              compactMode: false
            }
          },
          
          // Map profile information
          profile: {
            city: profile.city || '',
            country: 'India',
            familySize: profile.familySize || 1,
            ageRange: profile.age ? getAgeRange(profile.age) : '26-35',
            occupation: profile.occupation || '',
            financialExperience: 'beginner',
            bio: profile.bio || '',
            phone: profile.phone || '',
            dateOfBirth: profile.dateOfBirth || null
          },
          
          // Subscription information
          subscription: {
            plan: 'free',
            status: 'active',
            startDate: profile.createdAt || new Date(),
            endDate: null,
            features: ['basic_budgeting', 'expense_tracking']
          },
          
          // Security information
          security: {
            lastLogin: null,
            loginCount: 0,
            twoFactorEnabled: false,
            passwordChangedAt: null
          },
          
          // Onboarding status
          onboarding: {
            completed: profile.onboardingCompleted || false,
            currentStep: profile.onboardingStep || 'welcome',
            completedSteps: profile.onboardingCompleted ? ['profile', 'preferences', 'budget_setup'] : [],
            skippedSteps: []
          },
          
          // Activity information
          activity: {
            lastActiveAt: profile.updatedAt || profile.createdAt || new Date(),
            totalSessions: 1,
            averageSessionDuration: 0,
            featuresUsed: ['budgeting']
          },
          
          status: 'active',
          createdAt: profile.createdAt || new Date(),
          updatedAt: profile.updatedAt || new Date()
        }
        
        try {
          await User.create(userData)
          usersCreated++
          console.log(`✅ Created User record for profile: ${profile.email}`)
        } catch (error) {
          console.error(`❌ Failed to create User for ${profile.email}:`, error.message)
        }
      }
    }
    
    console.log(`✅ Created ${usersCreated} new User records`)
    
    // Step 5: Update UserProfile references to ensure consistency
    console.log('\n🔗 Updating UserProfile references...')
    let referencesUpdated = 0
    
    const allUsers = await User.find({}).lean()
    
    for (const profile of existingProfiles) {
      if (profile.email && !profile.userId) {
        // Find corresponding user by email
        const matchingUser = allUsers.find(user => user.email === profile.email)
        
        if (matchingUser) {
          await UserProfile.updateOne(
            { _id: profile._id },
            { $set: { userId: matchingUser._id } }
          )
          referencesUpdated++
        }
      }
    }
    
    console.log(`✅ Updated ${referencesUpdated} UserProfile references`)
    
    // Step 6: Data validation and cleanup
    console.log('\n🧹 Performing data validation and cleanup...')
    
    // Remove duplicate profiles (same userId)
    const duplicateProfiles = await UserProfile.aggregate([
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 },
          profiles: { $push: '$$ROOT' }
        }
      },
      {
        $match: {
          count: { $gt: 1 }
        }
      }
    ])
    
    let duplicatesRemoved = 0
    for (const duplicate of duplicateProfiles) {
      // Keep the most recent profile, remove others
      const sortedProfiles = duplicate.profiles.sort((a, b) => 
        new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt)
      )
      
      for (let i = 1; i < sortedProfiles.length; i++) {
        await UserProfile.deleteOne({ _id: sortedProfiles[i]._id })
        duplicatesRemoved++
      }
    }
    
    if (duplicatesRemoved > 0) {
      console.log(`✅ Removed ${duplicatesRemoved} duplicate profiles`)
    }
    
    // Step 7: Generate migration report
    console.log('\n📋 Migration Summary:')
    console.log(`• User profiles analyzed: ${existingProfiles.length}`)
    console.log(`• Profiles updated with new preferences: ${profilesUpdated}`)
    console.log(`• New User records created: ${usersCreated}`)
    console.log(`• UserProfile references updated: ${referencesUpdated}`)
    console.log(`• Duplicate profiles removed: ${duplicatesRemoved}`)
    
    // Final counts
    const finalUserCount = await User.countDocuments()
    const finalProfileCount = await UserProfile.countDocuments()
    
    console.log(`\n📊 Final Data Counts:`)
    console.log(`• Total Users: ${finalUserCount}`)
    console.log(`• Total UserProfiles: ${finalProfileCount}`)
    
    console.log('\n🎉 User data migration completed successfully!')
    
  } catch (error) {
    console.error('❌ Error during user data migration:', error)
    throw error
  } finally {
    // Close the connection
    await mongoose.connection.close()
    console.log('\n🔌 Database connection closed')
  }
}

// Helper function to map age to age range
function getAgeRange(age) {
  if (age >= 18 && age <= 25) return '18-25'
  if (age >= 26 && age <= 35) return '26-35'
  if (age >= 36 && age <= 45) return '36-45'
  if (age >= 46 && age <= 55) return '46-55'
  if (age >= 56 && age <= 65) return '56-65'
  return '65+'
}

// Export the function for use in other scripts
export default migrateUserData

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  migrateUserData()
    .then(() => {
      console.log('✅ Migration completed successfully')
      process.exit(0)
    })
    .catch((error) => {
      console.error('❌ Migration failed:', error)
      process.exit(1)
    })
}