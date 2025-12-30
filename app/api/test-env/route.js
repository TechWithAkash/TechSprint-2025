// app/api/test-env/route.js
export async function GET() {
  return Response.json({
    hasGoogleClientId: !!process.env.GOOGLE_CLIENT_ID,
    hasGoogleClientSecret: !!process.env.GOOGLE_CLIENT_SECRET,
    nextAuthUrl: process.env.NEXTAUTH_URL,
    hasSecret: !!process.env.NEXTAUTH_SECRET
  })
}