/**
 * Database Indexes Setup Script
 * 
 * This script creates optimized indexes for the WealthWise application
 * to improve query performance, especially for language preferences,
 * user data, and localization features.
 * 
 * Run this script after deploying the new User and UserProfile schemas
 * to ensure optimal database performance.
 */

import mongoose from 'mongoose'
import dbConnect from './lib/dbConnect.js'

// Import models to ensure they're registered
import User from './models/User.js'
import UserProfile from './models/UserProfile.js'
import Transaction from './models/Transaction.js'
import Debt from './models/Debt.js'

const setupDatabaseIndexes = async () => {
  try {
    console.log('🔗 Connecting to database...')
    await dbConnect()
    
    console.log('📊 Setting up database indexes...')
    
    // User model indexes
    console.log('Creating User model indexes...')
    const userIndexes = [
      // Core user fields
      { email: 1 }, // Unique index (already defined in schema)
      { status: 1, createdAt: -1 },
      
      // Language and localization indexes
      { 'preferences.language': 1 },
      { 'preferences.currency': 1 },
      { 'preferences.timezone': 1 },
      
      // Notification preferences
      { 'preferences.notifications.email': 1 },
      { 'preferences.notifications.push': 1 },
      
      // Onboarding and user journey
      { 'onboarding.completed': 1 },
      { 'onboarding.currentStep': 1 },
      
      // Activity and engagement
      { 'activity.lastActiveAt': -1 },
      { 'activity.totalSessions': -1 },
      
      // Subscription
      { 'subscription.plan': 1, 'subscription.status': 1 },
      
      // Profile information
      { 'profile.city': 1 },
      { 'profile.country': 1 },
      { 'profile.ageRange': 1 },
      { 'profile.occupation': 1 },
      
      // Compound indexes for common queries
      { 'preferences.language': 1, status: 1 },
      { 'preferences.currency': 1, 'profile.country': 1 },
      { 'onboarding.completed': 1, 'activity.lastActiveAt': -1 },
      { 'subscription.plan': 1, 'preferences.language': 1 },
      { 'profile.city': 1, 'preferences.language': 1 },
      { status: 1, 'activity.lastActiveAt': -1, 'preferences.language': 1 }
    ]
    
    for (const index of userIndexes) {
      try {
        await User.collection.createIndex(index)
        console.log(`✅ Created User index: ${JSON.stringify(index)}`)
      } catch (error) {
        if (error.code === 85) {
          console.log(`⚠️  Index already exists: ${JSON.stringify(index)}`)
        } else {
          console.error(`❌ Failed to create User index ${JSON.stringify(index)}:`, error.message)
        }
      }
    }
    
    // UserProfile model indexes
    console.log('\nCreating UserProfile model indexes...')
    const userProfileIndexes = [
      // Core profile fields
      { userId: 1 }, // Unique index (already defined in schema)
      { city: 1 },
      { onboardingCompleted: 1 },
      
      // Enhanced language and localization indexes
      { 'budgetPreferences.language': 1 },
      { 'budgetPreferences.currency': 1 },
      { 'budgetPreferences.timezone': 1 },
      { 'budgetPreferences.theme': 1 },
      { 'budgetPreferences.dateFormat': 1 },
      { 'budgetPreferences.numberFormat': 1 },
      
      // Notification preferences
      { 'budgetPreferences.emailNotifications': 1 },
      { 'budgetPreferences.pushNotifications': 1 },
      { 'budgetPreferences.budgetAlerts': 1 },
      { 'budgetPreferences.goalReminders': 1 },
      
      // Financial data indexes
      { monthlyIncome: 1 },
      { age: 1 },
      { incomeSource: 1 },
      { familySize: 1 },
      { budgetHealthScore: -1 },
      
      // Timestamps
      { createdAt: -1 },
      { updatedAt: -1 },
      { lastBudgetGenerated: -1 },
      
      // Compound indexes for common queries
      { city: 1, monthlyIncome: 1 },
      { 'budgetPreferences.language': 1, onboardingCompleted: 1 },
      { age: 1, incomeSource: 1 },
      { 'budgetPreferences.currency': 1, monthlyIncome: 1 },
      { city: 1, 'budgetPreferences.language': 1 },
      { incomeSource: 1, 'budgetPreferences.language': 1 },
      { onboardingCompleted: 1, 'budgetPreferences.language': 1, createdAt: -1 },
      { budgetHealthScore: -1, 'budgetPreferences.language': 1 },
      
      // Advanced compound indexes for analytics
      { city: 1, age: 1, incomeSource: 1 },
      { 'budgetPreferences.language': 1, 'budgetPreferences.currency': 1, city: 1 },
      { monthlyIncome: 1, familySize: 1, 'budgetPreferences.language': 1 }
    ]
    
    for (const index of userProfileIndexes) {
      try {
        await UserProfile.collection.createIndex(index)
        console.log(`✅ Created UserProfile index: ${JSON.stringify(index)}`)
      } catch (error) {
        if (error.code === 85) {
          console.log(`⚠️  Index already exists: ${JSON.stringify(index)}`)
        } else {
          console.error(`❌ Failed to create UserProfile index ${JSON.stringify(index)}:`, error.message)
        }
      }
    }
    
    // Transaction model indexes (for localization support)
    console.log('\nCreating Transaction model indexes...')
    const transactionIndexes = [
      // Core transaction fields
      { userId: 1, date: -1 },
      { category: 1 },
      { amount: -1 },
      { type: 1 },
      
      // Localization support
      { userId: 1, currency: 1 },
      { userId: 1, createdAt: -1 },
      
      // Compound indexes for reporting
      { userId: 1, category: 1, date: -1 },
      { userId: 1, type: 1, date: -1 },
      { userId: 1, amount: -1, date: -1 }
    ]
    
    for (const index of transactionIndexes) {
      try {
        await Transaction.collection.createIndex(index)
        console.log(`✅ Created Transaction index: ${JSON.stringify(index)}`)
      } catch (error) {
        if (error.code === 85) {
          console.log(`⚠️  Index already exists: ${JSON.stringify(index)}`)
        } else {
          console.error(`❌ Failed to create Transaction index ${JSON.stringify(index)}:`, error.message)
        }
      }
    }
    
    // Debt model indexes (for localization support)
    console.log('\nCreating Debt model indexes...')
    const debtIndexes = [
      // Core debt fields
      { userId: 1 },
      { status: 1 },
      { dueDate: 1 },
      { amount: -1 },
      
      // Compound indexes
      { userId: 1, status: 1 },
      { userId: 1, dueDate: 1 },
      { userId: 1, amount: -1 }
    ]
    
    for (const index of debtIndexes) {
      try {
        await Debt.collection.createIndex(index)
        console.log(`✅ Created Debt index: ${JSON.stringify(index)}`)
      } catch (error) {
        if (error.code === 85) {
          console.log(`⚠️  Index already exists: ${JSON.stringify(index)}`)
        } else {
          console.error(`❌ Failed to create Debt index ${JSON.stringify(index)}:`, error.message)
        }
      }
    }
    
    // Create text indexes for search functionality
    console.log('\nCreating text search indexes...')
    
    try {
      await User.collection.createIndex({
        name: 'text',
        email: 'text',
        'profile.bio': 'text',
        'profile.occupation': 'text'
      }, {
        name: 'user_text_search',
        default_language: 'english',
        language_override: 'language'
      })
      console.log('✅ Created User text search index')
    } catch (error) {
      if (error.code === 85) {
        console.log('⚠️  User text search index already exists')
      } else {
        console.error('❌ Failed to create User text search index:', error.message)
      }
    }
    
    try {
      await Transaction.collection.createIndex({
        description: 'text',
        category: 'text',
        subcategory: 'text'
      }, {
        name: 'transaction_text_search',
        default_language: 'english'
      })
      console.log('✅ Created Transaction text search index')
    } catch (error) {
      if (error.code === 85) {
        console.log('⚠️  Transaction text search index already exists')
      } else {
        console.error('❌ Failed to create Transaction text search index:', error.message)
      }
    }
    
    // Create TTL indexes for cleanup
    console.log('\nCreating TTL indexes for data cleanup...')
    
    try {
      // Clean up inactive users after 2 years
      await User.collection.createIndex(
        { 'activity.lastActiveAt': 1 },
        { 
          expireAfterSeconds: 63072000, // 2 years
          partialFilterExpression: { status: 'inactive' },
          name: 'inactive_user_cleanup'
        }
      )
      console.log('✅ Created inactive user cleanup TTL index')
    } catch (error) {
      if (error.code === 85) {
        console.log('⚠️  Inactive user cleanup TTL index already exists')
      } else {
        console.error('❌ Failed to create inactive user cleanup TTL index:', error.message)
      }
    }
    
    console.log('\n🎉 Database indexes setup completed successfully!')
    
    // Display index statistics
    console.log('\n📈 Index Statistics:')
    const userIndexStats = await User.collection.listIndexes().toArray()
    const userProfileIndexStats = await UserProfile.collection.listIndexes().toArray()
    const transactionIndexStats = await Transaction.collection.listIndexes().toArray()
    const debtIndexStats = await Debt.collection.listIndexes().toArray()
    
    console.log(`User model: ${userIndexStats.length} indexes`)
    console.log(`UserProfile model: ${userProfileIndexStats.length} indexes`)
    console.log(`Transaction model: ${transactionIndexStats.length} indexes`)
    console.log(`Debt model: ${debtIndexStats.length} indexes`)
    
    console.log('\n💡 Recommendations:')
    console.log('1. Monitor query performance using MongoDB Compass or db.collection.explain()')
    console.log('2. Review and optimize indexes based on actual query patterns')
    console.log('3. Consider creating additional indexes for specific use cases')
    console.log('4. Regularly analyze index usage with db.collection.aggregate([{$indexStats: {}}])')
    
  } catch (error) {
    console.error('❌ Error setting up database indexes:', error)
    throw error
  } finally {
    // Close the connection
    await mongoose.connection.close()
    console.log('\n🔌 Database connection closed')
  }
}

// Export the function for use in other scripts
export default setupDatabaseIndexes

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  setupDatabaseIndexes()
    .then(() => {
      console.log('✅ Index setup completed successfully')
      process.exit(0)
    })
    .catch((error) => {
      console.error('❌ Index setup failed:', error)
      process.exit(1)
    })
}