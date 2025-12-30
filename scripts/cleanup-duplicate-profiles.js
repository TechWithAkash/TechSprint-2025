// Script to clean up duplicate UserProfile entries
const mongoose = require('mongoose')
const fs = require('fs')
const path = require('path')

// Load .env.local manually
const envPath = path.join(__dirname, '..', '.env.local')
if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8')
    envContent.split('\n').forEach(line => {
        const match = line.match(/^([^=]+)=(.*)$/)
        if (match) {
            const key = match[1].trim()
            const value = match[2].trim()
            if (!process.env[key]) {
                process.env[key] = value
            }
        }
    })
}

const UserProfile = require('../models/UserProfile')

async function cleanupDuplicateProfiles() {
    try {
        console.log('🔌 Connecting to MongoDB...')
        await mongoose.connect(process.env.MONGODB_URI)
        console.log('✅ Connected to MongoDB\n')

        // Find all UserProfiles grouped by userId
        const duplicates = await UserProfile.aggregate([
            {
                $group: {
                    _id: '$userId',
                    count: { $sum: 1 },
                    profiles: { $push: { id: '$_id', email: '$email', hasOnboarding: '$onboardingCompleted' } }
                }
            },
            {
                $match: {
                    count: { $gt: 1 }
                }
            }
        ])

        if (duplicates.length === 0) {
            console.log('✅ No duplicate profiles found!')
            await mongoose.disconnect()
            return
        }

        console.log(`⚠️  Found ${duplicates.length} userId(s) with duplicate profiles:\n`)

        for (const dup of duplicates) {
            console.log(`📍 UserId: ${dup._id}`)
            console.log(`   Total profiles: ${dup.count}`)

            // Find the best profile to keep
            const profiles = await UserProfile.find({ userId: dup._id }).sort({ onboardingCompleted: -1, updatedAt: -1 })

            console.log('\n   Profiles:')
            profiles.forEach((profile, index) => {
                console.log(`   ${index + 1}. ID: ${profile._id}`)
                console.log(`      Email: ${profile.email}`)
                console.log(`      Onboarding: ${profile.onboardingCompleted ? '✅ Complete' : '❌ Incomplete'}`)
                console.log(`      Updated: ${profile.updatedAt}`)
                console.log(`      Has Data: ${profile.monthlyIncome ? 'Yes' : 'No'}`)
            })

            // Keep the first one (most complete), delete the rest
            const toKeep = profiles[0]
            const toDelete = profiles.slice(1)

            console.log(`\n   ✅ Keeping: ${toKeep._id} (${toKeep.onboardingCompleted ? 'Complete' : 'Incomplete'})`)
            console.log(`   ❌ Deleting ${toDelete.length} duplicate(s)...`)

            for (const profile of toDelete) {
                await UserProfile.deleteOne({ _id: profile._id })
                console.log(`      Deleted: ${profile._id}`)
            }

            console.log('\n' + '─'.repeat(60) + '\n')
        }

        console.log('✅ Cleanup complete!')
        await mongoose.disconnect()
        console.log('🔌 Disconnected from MongoDB')

    } catch (error) {
        console.error('❌ Error:', error.message)
        await mongoose.disconnect()
        process.exit(1)
    }
}

// Also check for profiles with null userId
async function cleanupNullUserIds() {
    try {
        console.log('\n🔍 Checking for profiles with null userId...')

        await mongoose.connect(process.env.MONGODB_URI)

        const nullProfiles = await UserProfile.find({ userId: null })

        if (nullProfiles.length === 0) {
            console.log('✅ No profiles with null userId found!')
            return
        }

        console.log(`⚠️  Found ${nullProfiles.length} profile(s) with null userId`)

        for (const profile of nullProfiles) {
            console.log(`   Email: ${profile.email}`)
            console.log(`   ID: ${profile._id}`)
        }

        console.log('\n❌ Deleting profiles with null userId...')
        const result = await UserProfile.deleteMany({ userId: null })
        console.log(`✅ Deleted ${result.deletedCount} profile(s) with null userId`)

    } catch (error) {
        console.error('❌ Error:', error.message)
    } finally {
        await mongoose.disconnect()
    }
}

// Run both cleanups
async function runCleanup() {
    await cleanupNullUserIds()
    await cleanupDuplicateProfiles()
}

runCleanup()
