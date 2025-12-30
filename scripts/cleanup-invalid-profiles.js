// Script to cleanup invalid profiles with null userId
// Run this once to clean up the database

const dbConnect = require('../lib/dbConnect').default
const UserProfile = require('../models/UserProfile').default

async function cleanupInvalidProfiles() {
  try {
    console.log('🔄 Connecting to database...')
    await dbConnect()

    console.log('🔍 Finding profiles with null userId...')
    const invalidProfiles = await UserProfile.find({ userId: null })

    console.log(`📊 Found ${invalidProfiles.length} invalid profiles`)

    if (invalidProfiles.length > 0) {
      console.log('\n🗑️  Invalid profiles:')
      invalidProfiles.forEach((profile, index) => {
        console.log(`  ${index + 1}. Email: ${profile.email || 'N/A'}, ID: ${profile._id}`)
      })

      console.log('\n⚠️  These profiles will be deleted because they have null userId')
      console.log('   This usually happens when profiles are created incorrectly.')

      const result = await UserProfile.deleteMany({ userId: null })
      console.log(`\n✅ Deleted ${result.deletedCount} invalid profiles`)
    } else {
      console.log('✨ No invalid profiles found! Database is clean.')
    }

    console.log('\n✅ Cleanup complete!')
    process.exit(0)
  } catch (error) {
    console.error('❌ Error during cleanup:', error)
    process.exit(1)
  }
}

cleanupInvalidProfiles()
