const { MongoClient } = require('mongodb')

const uri = 'mongodb+srv://vishwakarmaakashav17:AkashPython123@pythoncluster0.t9pop.mongodb.net/smart-financial-planner?retryWrites=true&w=majority'

async function testConnection() {
    console.log('🔍 Testing MongoDB Connection...\n')
    console.log('URI:', uri.replace(/:[^:@]+@/, ':****@'), '\n')

    const client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 60000,
        socketTimeoutMS: 75000,
        connectTimeoutMS: 60000,
        tls: true,
        tlsAllowInvalidCertificates: false,
        maxPoolSize: 10,
        minPoolSize: 2,
    })

    try {
        console.log('⏳ Attempting to connect...')
        await client.connect()
        console.log('✅ Successfully connected to MongoDB!')

        const db = client.db('smart-financial-planner')
        console.log('\n📊 Database:', db.databaseName)

        const collections = await db.listCollections().toArray()
        console.log('\n📁 Collections:')
        collections.forEach((col) => console.log(`   - ${col.name}`))

        const serverStatus = await db.admin().serverStatus()
        console.log('\n🌐 Server Info:')
        console.log(`   Host: ${serverStatus.host}`)
        console.log(`   Version: ${serverStatus.version}`)
        console.log(`   Uptime: ${Math.floor(serverStatus.uptime / 60)} minutes`)

        console.log('\n✅ MongoDB connection is working perfectly!')
    } catch (error) {
        console.error('\n❌ MongoDB Connection Failed!')
        console.error('\nError Details:')
        console.error('   Name:', error.name)
        console.error('   Message:', error.message)
        console.error('   Code:', error.code)

        if (error.cause) {
            console.error('\nCause:')
            console.error('   ', error.cause)
        }

        console.error('\n🔧 Troubleshooting Steps:')
        console.error('   1. Check MongoDB Atlas Network Access (IP Whitelist)')
        console.error('      → Go to: https://cloud.mongodb.com/v2#/org/YOUR_ORG/projects')
        console.error('      → Network Access → Add IP Address → Allow Access from Anywhere (0.0.0.0/0)')
        console.error('')
        console.error('   2. Verify MongoDB Cluster is Active')
        console.error('      → Go to: Database Deployments')
        console.error('      → Check if cluster status is "Active"')
        console.error('')
        console.error('   3. Check Database User Credentials')
        console.error('      → Database Access → Verify username/password')
        console.error('')
        console.error('   4. Test DNS Resolution')
        console.error('      → Run: nslookup pythoncluster0.t9pop.mongodb.net')
        console.error('')
        console.error('   5. Check Firewall/Antivirus Settings')
        console.error('      → Temporarily disable to test')
    } finally {
        await client.close()
        console.log('\n🔒 Connection closed.')
    }
}

testConnection()
