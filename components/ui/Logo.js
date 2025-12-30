// components/ui/Logo.js

import { TrendingUp } from 'lucide-react'

const Logo = ({ 
  size = 'medium', 
  showText = true, 
  iconOnly = false,
  className = '',
  textClassName = '',
  iconClassName = ''
}) => {
  // Size configurations
  const sizeConfig = {
    small: {
      container: 'w-6 h-6',
      icon: 'w-4 h-4',
      text: 'text-sm',
      spacing: 'space-x-2'
    },
    medium: {
      container: 'w-8 h-8',
      icon: 'w-5 h-5',
      text: 'text-lg',
      spacing: 'space-x-3'
    },
    large: {
      container: 'w-10 h-10',
      icon: 'w-6 h-6',
      text: 'text-xl',
      spacing: 'space-x-3'
    },
    xlarge: {
      container: 'w-12 h-12',
      icon: 'w-7 h-7',
      text: 'text-2xl',
      spacing: 'space-x-4'
    }
  }

  const config = sizeConfig[size] || sizeConfig.medium

  if (iconOnly) {
    return (
      <div className={`${config.container} bg-gradient-to-r from-emerald-500 to-teal-500 rounded-lg flex items-center justify-center ${className}`}>
        <TrendingUp className={`${config.icon} text-white ${iconClassName}`} />
      </div>
    )
  }

  return (
    <div className={`flex items-center ${config.spacing} ${className}`}>
      <div className={`${config.container} bg-gradient-to-r from-emerald-500 to-teal-500 rounded-lg flex items-center justify-center`}>
        <TrendingUp className={`${config.icon} text-white ${iconClassName}`} />
      </div>
      {showText && (
        <div>
          <h1 className={`${config.text} font-bold ${textClassName}`}>
            <span className="text-slate-800">Wealth</span>
            <span className="bg-gradient-to-r from-emerald-500 to-teal-500 bg-clip-text text-transparent">Wise</span>
          </h1>
        </div>
      )}
    </div>
  )
}

export default Logo
