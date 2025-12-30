export default function Loading() {
  return (
    <div className="min-h-screen bg-white flex items-center justify-center">
      <div className="text-center space-y-6">
        <div className="relative">
          <div className="w-24 h-24 bg-gradient-to-r from-emerald-600 via-teal-600 to-blue-600 rounded-3xl mx-auto animate-pulse shadow-2xl"></div>
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-400 to-blue-400 rounded-3xl blur-2xl opacity-40 animate-pulse"></div>
        </div>

        <div className="space-y-2">
          <h2 className="text-3xl font-bold bg-gradient-to-r from-emerald-600 to-blue-600 bg-clip-text text-transparent">
            WealthWise
          </h2>
          <p className="text-slate-600">Loading...</p>
        </div>

        <div className="flex justify-center gap-2">
          <div className="w-2.5 h-2.5 bg-emerald-600 rounded-full animate-bounce"></div>
          <div className="w-2.5 h-2.5 bg-teal-600 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
          <div className="w-2.5 h-2.5 bg-blue-600 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
        </div>
      </div>
    </div>
  )
}
