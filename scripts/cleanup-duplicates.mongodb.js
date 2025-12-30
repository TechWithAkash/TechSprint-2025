// MongoDB Shell Script to Clean Up Duplicate Profiles
// Run this in MongoDB Compass or mongosh

// ===================================================
// STEP 1: Find and display duplicate profiles
// ===================================================

print("\n🔍 Searching for duplicate profiles...\n")

db.userprofiles.aggregate([
    {
        $group: {
            _id: '$userId',
            count: { $sum: 1 },
            profiles: {
                $push: {
                    id: '$_id',
                    email: '$email',
                    onboarding: '$onboardingCompleted',
                    updated: '$updatedAt',
                    income: '$monthlyIncome'
                }
            }
        }
    },
    {
        $match: { count: { $gt: 1 } }
    }
]).forEach(function (dup) {
    print(`\n📍 UserId: ${dup._id}`)
    print(`   Total profiles: ${dup.count}`)

    // Get full profile details
    const profiles = db.userprofiles.find({ userId: dup._id }).sort({ onboardingCompleted: -1, updatedAt: -1 }).toArray()

    print("\n   Profiles:")
    profiles.forEach((profile, index) => {
        print(`   ${index + 1}. ID: ${profile._id}`)
        print(`      Email: ${profile.email}`)
        print(`      Onboarding: ${profile.onboardingCompleted ? '✅ Complete' : '❌ Incomplete'}`)
        print(`      Updated: ${profile.updatedAt}`)
        print(`      Has Income: ${profile.monthlyIncome ? 'Yes (' + profile.monthlyIncome + ')' : 'No'}`)
    })

    // Keep the first one (most complete), delete the rest
    const toKeep = profiles[0]
    const toDelete = profiles.slice(1)

    print(`\n   ✅ Keeping: ${toKeep._id}`)
    print(`   ❌ Deleting ${toDelete.length} duplicate(s)...`)

    toDelete.forEach(profile => {
        db.userprofiles.deleteOne({ _id: profile._id })
        print(`      Deleted: ${profile._id}`)
    })

    print("\n" + "─".repeat(60))
})

// ===================================================
// STEP 2: Clean up profiles with null userId
// ===================================================

print("\n\n🔍 Checking for profiles with null userId...\n")

const nullProfiles = db.userprofiles.find({ userId: null }).toArray()

if (nullProfiles.length === 0) {
    print("✅ No profiles with null userId found!")
} else {
    print(`⚠️  Found ${nullProfiles.length} profile(s) with null userId:\n`)

    nullProfiles.forEach(profile => {
        print(`   Email: ${profile.email}`)
        print(`   ID: ${profile._id}`)
    })

    print("\n❌ Deleting profiles with null userId...")
    const result = db.userprofiles.deleteMany({ userId: null })
    print(`✅ Deleted ${result.deletedCount} profile(s)`)
}

print("\n\n✅ Cleanup complete!\n")

// ===================================================
// VERIFICATION: Show remaining profiles
// ===================================================

print("📊 Verification - Remaining profiles:\n")

db.userprofiles.find().forEach(profile => {
    print(`   UserId: ${profile.userId} | Email: ${profile.email} | Onboarding: ${profile.onboardingCompleted ? '✅' : '❌'}`)
})

print("\n")
