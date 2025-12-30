import { Poppins } from "next/font/google";
import "./globals.css";
import ClientProviders from '@/components/providers/ClientProviders'
import PWARegister from '@/components/PWARegister'
import PWAInstallPrompt from '@/components/PWAInstallPrompt'
// import  VAPIVoiceAgent  from "@/components/vapi";
// import { VAPIVoiceAgent } from '@/components/vapi'


// Poppins font - clean, modern, highly readable for financial apps
const poppins = Poppins({
  variable: "--font-poppins",
  subsets: ["latin"],
  weight: ['300', '400', '500', '600', '700', '800', '900'],
  display: 'swap',
});


export const metadata = {
  metadataBase: new URL('https://www.mywealthwise.tech'),
  title: {
    default: 'WealthWise - Smart Financial Planner | Track Expenses, Set Goals & Manage Budget',
    template: '%s | WealthWise'
  },
  description: 'Take control of your finances with WealthWise. Track expenses, set financial goals, create budgets, and get AI-powered insights. Your personal finance companion for smarter money management.',
  keywords: [
    'financial planner',
    'expense tracker',
    'budget manager',
    'money management',
    'personal finance',
    'savings goals',
    'expense management',
    'financial goals',
    'budget planner',
    'smart budgeting',
    'AI financial advisor',
    'wealth management',
    'finance app',
    'budget tracking'
  ],
  authors: [{ name: 'WealthWise Team' }],
  creator: 'WealthWise',
  publisher: 'WealthWise',
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://www.mywealthwise.tech',
    siteName: 'WealthWise',
    title: 'WealthWise - Smart Financial Planner',
    description: 'Take control of your finances with WealthWise. Track expenses, set financial goals, create budgets, and get AI-powered insights.',
    images: [
      {
        url: '/icons/icon-512x512.png',
        width: 512,
        height: 512,
        alt: 'WealthWise - Smart Financial Planner',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'WealthWise - Smart Financial Planner',
    description: 'Take control of your finances with WealthWise. Track expenses, set financial goals, create budgets, and get AI-powered insights.',
    images: ['/icons/icon-512x512.png'],
    creator: '@wealthwise',
  },
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'default',
    title: 'WealthWise'
  },
  formatDetection: {
    telephone: false
  },
  icons: {
    icon: [
      { url: '/icons/icon-192x192.png', sizes: '192x192', type: 'image/png' },
      { url: '/icons/icon-512x512.png', sizes: '512x512', type: 'image/png' }
    ],
    apple: [
      { url: '/icons/icon-152x152.png', sizes: '152x152', type: 'image/png' }
    ],
    shortcut: ['/favicon.ico']
  },
  verification: {
    // Add your Google Search Console verification token here when you get it
    // google: 'your-verification-token',
  },
};


export const viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  userScalable: true,
  viewportFit: 'cover',
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#10b981' },
    { media: '(prefers-color-scheme: dark)', color: '#059669' }
  ]
};


export default function RootLayout({ children }) {
  return (
    <html lang="en" className={poppins.variable}>
      <head>
        {/* PWA Support */}
        <link rel="manifest" href="/manifest.json" />
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="default" />
        <meta name="apple-mobile-web-app-title" content="WealthWise" />


        {/* Prevent auto-zoom on iOS when focusing inputs */}
        <meta name="format-detection" content="telephone=no" />


        {/* Safe area insets for notched devices */}
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />


        {/* Clear Google Translate cookies on first load - Default to English */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                if (typeof document !== 'undefined') {
                  var lang = localStorage.getItem('wealthwise-language');
                  if (!lang || lang === 'en') {
                    document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                    document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=' + window.location.hostname + ';';
                    document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.' + window.location.hostname + ';';
                  }
                }
              })();
            `
          }}
        />

        {/* Structured Data for SEO */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              '@context': 'https://schema.org',
              '@type': 'WebApplication',
              name: 'WealthWise',
              applicationCategory: 'FinanceApplication',
              description: 'Smart financial planning and expense tracking application with AI-powered insights',
              url: 'https://www.mywealthwise.tech',
              operatingSystem: 'All',
              offers: {
                '@type': 'Offer',
                price: '0',
                priceCurrency: 'USD',
              },
              aggregateRating: {
                '@type': 'AggregateRating',
                ratingValue: '4.8',
                ratingCount: '150',
              },
              featureList: [
                'Expense Tracking',
                'Budget Management',
                'Financial Goals',
                'AI-Powered Insights',
                'Multi-language Support',
                'Investment Tracking',
              ],
            }),
          }}
        />
      </head>
      <body
        className="font-poppins antialiased touch-manipulation"
        style={{ fontFeatureSettings: "'kern' 1, 'liga' 1, 'calt' 1" }}
      >
        <PWARegister />
        <ClientProviders>
          {children}
          <PWAInstallPrompt />
          {/* <VAPIVoiceAgent position="bottom-right" showTranscript={true} /> */}
        </ClientProviders>
      </body>
    </html>
  );
}

