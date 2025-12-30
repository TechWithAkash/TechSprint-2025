// Loading state for dashboard
export default function Loading() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center">
      <div className="text-center space-y-6">
        {/* Animated Logo */}
        <div className="relative">
          <div className="w-20 h-20 bg-gradient-to-r from-emerald-600 to-blue-600 rounded-2xl mx-auto animate-pulse shadow-2xl"></div>
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-400 to-blue-400 rounded-2xl blur-xl opacity-50 animate-pulse"></div>
        </div>

        {/* Loading Text */}
        <div className="space-y-2">
          <h2 className="text-2xl font-bold text-slate-800">Loading WealthWise</h2>
          <p className="text-slate-600">Preparing your financial dashboard...</p>
        </div>

        {/* Loading Spinner */}
        <div className="flex justify-center gap-2">
          <div className="w-3 h-3 bg-emerald-600 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
          <div className="w-3 h-3 bg-blue-600 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
          <div className="w-3 h-3 bg-purple-600 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
        </div>
      </div>
    </div>
  )
}
