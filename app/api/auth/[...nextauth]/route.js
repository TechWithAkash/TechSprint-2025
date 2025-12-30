// // app/api/auth/[...nextauth]/route.js

// export const runtime = 'nodejs'  // ✅ Force Node.js

// import { handlers } from "@/lib/auth"

// export const { GET, POST } = handlers


// // app/api/auth/[...nextauth]/route.js

// export const runtime = 'nodejs'

// import { handlers } from "@/lib/auth"

// export const { GET, POST } = handlers

// // Add OPTIONS handler for CORS
// export async function OPTIONS(request) {
//   return new Response(null, {
//     status: 200,
//     headers: {
//       'Access-Control-Allow-Origin': process.env.NEXTAUTH_URL || 'https://wealthwise-cyan.vercel.app',
//       'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
//       'Access-Control-Allow-Headers': 'Content-Type, Authorization',
//       'Access-Control-Allow-Credentials': 'true',
//     },
//   })
// }




// app/api/auth/[...nextauth]/route.js

export const runtime = 'nodejs'

import { handlers } from "@/lib/auth"

export const { GET, POST } = handlers

// Enhanced OPTIONS handler for CORS with proper origin handling
export async function OPTIONS(request) {
  const origin = request.headers.get('origin')
  const allowedOrigins = [
    'https://www.mywealthwise.tech',
    'https://mywealthwise.tech',
    process.env.NEXTAUTH_URL
  ].filter(Boolean)

  const responseHeaders = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400', // 24 hours
  }

  // Set origin if it's in allowed list
  if (origin && allowedOrigins.includes(origin)) {
    responseHeaders['Access-Control-Allow-Origin'] = origin
  } else {
    responseHeaders['Access-Control-Allow-Origin'] = process.env.NEXTAUTH_URL || 'https://www.mywealthwise.tech'
  }

  return new Response(null, {
    status: 204,
    headers: responseHeaders,
  })
}