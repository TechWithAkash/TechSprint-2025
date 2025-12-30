<p align="center">
  <img src="public/logo.png" alt="WealthWise Logo" width="120" height="120" />
</p>

<h1 align="center">WealthWise</h1>

<p align="center">
  <strong>AI-Powered Smart Financial Planner for India</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#project-structure">Project Structure</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-15.5-black?logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/React-19.1-blue?logo=react" alt="React" />
  <img src="https://img.shields.io/badge/Firebase-Firestore-orange?logo=firebase" alt="Firebase" />
  <img src="https://img.shields.io/badge/Gemini_AI-Powered-4285F4?logo=google" alt="Gemini AI" />
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License" />
</p>

---

## Overview

**WealthWise** is an AI-powered personal finance management application designed specifically for Indian users. It helps users create personalized budgets, track expenses through voice commands in multiple languages, and achieve their financial goals with smart insights.

### Why WealthWise?

- **76% of Indians** lack formal financial literacy
- Existing tools ignore **Indian cultural context** (festivals, EMIs, family expenses)
- No support for **regional languages** like Hindi and Hinglish

WealthWise solves these problems with AI-driven personalization and voice-first design.

---

## Features

### Core Functionality

| Feature | Description |
|---------|-------------|
| **AI Budget Generator** | Creates personalized budgets based on income, city, family size & lifestyle |
| **Voice Expense Tracking** | Log expenses by speaking in Hindi, English, or Hinglish |
| **Smart Analytics** | Visual charts showing spending trends and budget comparisons |
| **Goal Tracking** | Set and monitor savings goals with progress visualization |
| **Debt Manager** | Track loans, EMIs, and payment schedules with alerts |

### India-Specific Features

| Feature | Description |
|---------|-------------|
| **Seasonal Planner** | Auto-plan savings for Diwali, Holi, school fees & more |
| **Multi-Language UI** | Full support for English, Hindi, and Hinglish |
| **Indian Currency** | Optimized for INR with lakhs/crores formatting |
| **City-Based Budgets** | Cost-of-living adjustments for Indian cities |

### Engagement & Retention

| Feature | Description |
|---------|-------------|
| **Achievement System** | Earn badges for consistent tracking and savings milestones |
| **Daily Pulse** | Quick daily mood and spending check-ins |
| **Smart Nudges** | Contextual reminders to stay on track |
| **Daily Tips** | Personalized financial tips based on your profile |

---

## Tech Stack

### Frontend
```
Next.js 15.5      → React framework with App Router
React 19.1        → UI library with hooks
Tailwind CSS 4    → Utility-first styling
Radix UI          → Accessible component primitives
Recharts          → Data visualization
i18next           → Internationalization
```

### Backend
```
Next.js API Routes → Serverless API endpoints
Firebase Firestore → NoSQL cloud database
Firebase Auth      → Authentication service
NextAuth.js v5     → Session management
```

### AI & Services
```
Google Gemini AI   → Budget generation & insights
Google OAuth 2.0   → Social authentication
Google Translate   → Real-time translation
Google reCAPTCHA   → Bot protection
Gmail SMTP         → Email notifications
```

---

## Getting Started

### Prerequisites

- **Node.js** 18.17 or higher
- **npm** 9+ or **yarn** 1.22+
- **Firebase Project** with Firestore enabled
- **Google Cloud Console** account for APIs

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/yourusername/wealthwise.git
cd wealthwise
```

**2. Install dependencies**

```bash
npm install
```

**3. Set up environment variables**

```bash
cp .env.example .env.local
```

Edit `.env.local` with your credentials (see [Environment Variables](#environment-variables) section).

**4. Initialize Firebase**

- Create a project at [Firebase Console](https://console.firebase.google.com/)
- Enable **Firestore Database** in production mode
- Enable **Authentication** with Email/Password and Google providers
- Download your service account key

**5. Run the development server**

```bash
npm run dev
```

**6. Open the application**

Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## Environment Variables

Create a `.env.local` file in the root directory. See `.env.example` for all required variables.

### Required Variables

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_FIREBASE_*` | Firebase client configuration |
| `FIREBASE_SERVICE_ACCOUNT_*` | Firebase Admin SDK credentials |
| `NEXTAUTH_SECRET` | Random string for session encryption |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GEMINI_API_KEY` | Google Gemini AI API key |

### Optional Variables

| Variable | Description |
|----------|-------------|
| `SMTP_*` | Email configuration for notifications |
| `RECAPTCHA_SECRET_KEY` | reCAPTCHA verification |
| `REDIS_URL` | Optional caching layer |

---

## Project Structure

```
wealthwise/
├── app/                    # Next.js App Router
│   ├── api/               # API routes
│   │   ├── auth/         # Authentication endpoints
│   │   ├── budget/       # Budget generation & management
│   │   ├── expenses/     # Expense CRUD & insights
│   │   ├── debt/         # Debt tracking
│   │   ├── goals/        # Goal management
│   │   ├── retention/    # Achievements & engagement
│   │   └── voice/        # Voice processing
│   ├── auth/             # Authentication pages
│   ├── dashboard/        # Protected dashboard pages
│   ├── onboarding/       # User onboarding flow
│   └── page.js           # Landing page
│
├── components/            # React components
│   ├── analytics/        # Charts & visualizations
│   ├── budget/           # Budget display & management
│   ├── expenses/         # Expense entry & list
│   ├── onboarding/       # Onboarding flow components
│   ├── retention/        # Engagement widgets
│   └── ui/               # Reusable UI primitives
│
├── lib/                   # Core business logic
│   ├── budgetGenerator.js    # AI budget algorithm
│   ├── voiceProcessor.js     # Voice-to-expense parsing
│   ├── retentionEngine.js    # Achievement system
│   ├── notificationService.js # Alert management
│   ├── seasonalPlanner.js    # Festival planning
│   └── firebase.js           # Firebase configuration
│
├── models/               # Data models (Firestore schemas)
│   ├── User.js          # User account model
│   ├── UserProfile.js   # Profile & preferences
│   ├── Transaction.js   # Expense/income records
│   └── Debt.js          # Debt tracking
│
├── contexts/            # React Context providers
├── public/              # Static assets
└── scripts/             # Utility scripts
```

---

## Application Workflow

### User Journey

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Sign Up   │────▶│  Onboarding │────▶│  Dashboard  │
│  (Email/    │     │  (4 steps)  │     │  (Main App) │
│   Google)   │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │   Income    │ │ Demographics│ │  Financial  │
    │   Setup     │ │   & City    │ │   Pulse     │
    └─────────────┘ └─────────────┘ └─────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  AI Generates   │
                  │ Personal Budget │
                  └─────────────────┘
```

### Onboarding Steps

1. **Income Setup** → Enter monthly income and sources
2. **Demographics** → City, family size, age, occupation
3. **Financial Pulse** → Debt status, savings level, spending style
4. **Budget Review** → AI generates and user approves budget

### Dashboard Features

```
┌────────────────────────────────────────────────────┐
│                    DASHBOARD                        │
├──────────────┬──────────────┬──────────────────────┤
│   Budget     │   Expenses   │     Analytics        │
│   Overview   │   Quick Add  │     Charts           │
├──────────────┼──────────────┼──────────────────────┤
│    Goals     │    Debt      │    Notifications     │
│   Tracker    │   Manager    │      Center          │
├──────────────┴──────────────┴──────────────────────┤
│           Seasonal Planner & Achievements          │
└────────────────────────────────────────────────────┘
```

---

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user with OTP |
| `/api/auth/send-otp` | POST | Send OTP to email |
| `/api/auth/verify-otp` | POST | Verify OTP code |
| `/api/auth/[...nextauth]` | * | NextAuth.js handler |

### Budget

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/budget/generate` | POST | Generate AI budget |
| `/api/budget/save` | POST | Save/update budget |

### Expenses

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/expenses` | GET | List all expenses |
| `/api/expenses` | POST | Create expense |
| `/api/expenses/insights` | POST | Get AI insights |
| `/api/voice/process` | POST | Process voice input |

### Debt & Goals

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/debt` | GET/POST | Debt CRUD |
| `/api/debt/[id]` | PUT/DELETE | Update/delete debt |
| `/api/goals` | GET/POST | Goal management |

---

## Scripts

```bash
# Development
npm run dev          # Start dev server with Turbopack

# Production
npm run build        # Build for production
npm start            # Start production server

# Utilities
npm run lint         # Run ESLint
```

---

## Firebase Data Structure

### Collections

```
firestore/
├── users/                 # User accounts
│   └── {userId}/
│       ├── email
│       ├── name
│       ├── preferences
│       └── onboarding
│
├── profiles/              # User financial profiles
│   └── {profileId}/
│       ├── userId
│       ├── monthlyIncome
│       ├── incomeSources[]
│       ├── demographics
│       ├── generatedBudget
│       ├── seasonalEvents[]
│       └── achievements[]
│
├── transactions/          # Expenses & income
│   └── {transactionId}/
│       ├── userId
│       ├── amount
│       ├── category
│       ├── date
│       └── source (manual/voice/import)
│
└── debts/                 # Debt records
    └── {debtId}/
        ├── userId
        ├── type (taken/given)
        ├── amount
        ├── interestRate
        └── payments[]
```

---

## Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow existing code style and patterns
- Write meaningful commit messages
- Test your changes thoroughly
- Update documentation as needed

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Google** for Gemini AI, Firebase, and Cloud APIs
- **Vercel** for Next.js and hosting platform
- **Radix UI** for accessible component primitives
- **TechSprint** hackathon for the opportunity

---

<p align="center">
  Made with care for Indian families
</p>
