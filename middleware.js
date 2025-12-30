
// middleware.js
import { NextResponse } from "next/server"

export default async function middleware(request) {
  const { pathname } = request.nextUrl
  
  // Public routes that don't require authentication
  const publicRoutes = [
    "/",
    "/auth/signin",
    "/auth/signup", 
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/verify-email",
    "/auth/error",
    "/about",
    "/contact",
    "/privacy",
    "/terms"
  ]

  // API routes that don't require authentication
  const publicApiRoutes = [
    "/api/auth",
    "/api/health"
  ]

  // Check if current path is public
  const isPublicRoute = publicRoutes.some(route => pathname === route || pathname.startsWith(route))
  const isPublicApiRoute = publicApiRoutes.some(route => pathname.startsWith(route))

  // Allow public routes
  if (isPublicRoute || isPublicApiRoute) {
    return NextResponse.next()
  }

  // For protected routes, check if user has session cookie
  const sessionToken = request.cookies.get('next-auth.session-token') || request.cookies.get('__Secure-next-auth.session-token')
  
  if (!sessionToken) {
    // Redirect to signin for protected routes
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    const signInUrl = new URL("/auth/signin", request.url)
    signInUrl.searchParams.set("callbackUrl", pathname)
    return NextResponse.redirect(signInUrl)
  }

  // Redirect authenticated users away from auth pages to onboarding
  if (sessionToken && pathname.startsWith("/auth/") && !pathname.includes("/signout") && !pathname.includes("/verify")) {
    return NextResponse.redirect(new URL("/onboarding", request.url))
  }

  // For dashboard routes, redirect to onboarding first (let client-side handle completion check)
  if (sessionToken && (pathname === "/dashboard" || pathname.startsWith("/dashboard/"))) {
    // Simple redirect to onboarding - let client-side OnboardingGuard handle the completion check
    // This prevents users from directly accessing dashboard and ensures they go through onboarding flow
    const response = NextResponse.redirect(new URL("/onboarding", request.url))
    // Add a header to indicate this was a middleware redirect
    response.headers.set('x-middleware-redirect', 'onboarding')
    return response
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    "/((?!_next/static|_next/image|favicon.ico|public).*)",
  ]
}
