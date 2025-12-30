// Modern validation schemas with comprehensive rules
import { z } from 'zod'

// Password validation with reasonable requirements
const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password must be less than 128 characters')

// Email validation
const emailSchema = z
  .string()
  .email('Invalid email address')
  .max(254, 'Email address too long')
  .transform(email => email.toLowerCase().trim())

// Name validation
const nameSchema = z
  .string()
  .min(1, 'Name is required')
  .max(100, 'Name must be less than 100 characters')
  .regex(/^[a-zA-Z\s'-]+$/, 'Name can only contain letters, spaces, hyphens, and apostrophes')
  .transform(name => name.trim())

// Phone validation
const phoneSchema = z
  .string()
  .regex(/^\+?[\d\s\-\(\)]+$/, 'Invalid phone number format')
  .min(10, 'Phone number must be at least 10 digits')
  .max(20, 'Phone number must be less than 20 characters')
  .optional()

// Age validation
const ageRangeSchema = z.enum([
  '18-25',
  '26-35',
  '36-45',
  '46-55',
  '56-65',
  '65+'
], {
  errorMap: () => ({ message: 'Please select a valid age range' })
})

// Currency validation
const currencySchema = z.enum([
  'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'CHF', 'CNY', 'INR'
], {
  errorMap: () => ({ message: 'Please select a valid currency' })
})

// Financial experience validation
const financialExperienceSchema = z.enum([
  'beginner',
  'intermediate',
  'advanced',
  'expert'
], {
  errorMap: () => ({ message: 'Please select a valid experience level' })
})

// User registration schema
// OTP validation schemas
export const sendOtpSchema = z.object({
  email: emailSchema,
  type: z.enum(['registration', 'login', 'password_reset'], {
    errorMap: () => ({ message: 'Invalid OTP type' })
  }),
  name: z.string().min(1).max(100).optional() // Optional name for personalized emails
})

export const verifyOtpSchema = z.object({
  email: emailSchema,
  otp: z
    .string()
    .length(6, 'OTP must be exactly 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only numbers'),
  type: z.enum(['registration', 'login', 'password_reset'], {
    errorMap: () => ({ message: 'Invalid OTP type' })
  })
})

// Updated registration schema (OTP-based)
export const registerSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name must be less than 50 characters')
    .trim(),
  email: emailSchema,
  password: passwordSchema,
  otp: z
    .string()
    .length(6, 'OTP must be exactly 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only numbers')
})

// OTP-based login schema
export const otpLoginSchema = z.object({
  email: emailSchema,
  otp: z
    .string()
    .length(6, 'OTP must be exactly 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only numbers')
})

// Traditional login schema (for password-based login)
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
})

// Password change schema
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
  confirmPassword: z.string()
}).refine(data => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// Password reset request schema
export const forgotPasswordSchema = z.object({
  email: emailSchema,
})

// Password reset schema
export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: passwordSchema,
  confirmPassword: z.string()
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// Email verification schema
export const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
})

// User profile update schema
export const updateProfileSchema = z.object({
  name: nameSchema.optional(),
  phone: phoneSchema.optional(),
  avatar: z.string().refine(
    (value) => {
      // Allow URLs or base64 data URLs
      return /^(https?:\/\/|data:image\/)/.test(value)
    },
    { message: 'Invalid avatar URL or image data' }
  ).optional(),
  preferences: z.object({
    currency: currencySchema,
    language: z.enum(['en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja']).default('en'),
    timezone: z.string().default('UTC'),
    notifications: z.object({
      email: z.boolean().default(true),
      push: z.boolean().default(true),
      budgetAlerts: z.boolean().default(true),
      goalReminders: z.boolean().default(true),
    }).default({}),
    privacy: z.object({
      shareData: z.boolean().default(false),
      analytics: z.boolean().default(true),
    }).default({}),
  }).optional(),
  profile: z.object({
    city: z.string().max(100).optional(),
    country: z.string().max(100).optional(),
    location: z.string().max(200).optional(),
    bio: z.string().max(500).optional(),
    dateOfBirth: z.string().optional(),
    familySize: z.number().int().min(1).max(20).default(1),
    ageRange: ageRangeSchema.optional(),
    occupation: z.string().max(100).optional(),
    financialExperience: financialExperienceSchema.default('beginner'),
  }).optional(),
})

// Budget schema
export const budgetSchema = z.object({
  name: z.string().min(1, 'Budget name is required').max(100),
  description: z.string().max(500).optional(),
  totalAmount: z.number().positive('Budget amount must be positive'),
  currency: currencySchema,
  period: z.enum(['weekly', 'monthly', 'yearly']),
  startDate: z.string().datetime('Invalid start date'),
  endDate: z.string().datetime('Invalid end date'),
  categories: z.array(z.object({
    name: z.string().min(1).max(50),
    allocatedAmount: z.number().positive(),
    color: z.string().regex(/^#[0-9A-F]{6}$/i, 'Invalid color format'),
  })).min(1, 'At least one category is required'),
}).refine(data => new Date(data.endDate) > new Date(data.startDate), {
  message: "End date must be after start date",
  path: ["endDate"],
})

// Expense schema
export const expenseSchema = z.object({
  amount: z.number().positive('Amount must be positive'),
  description: z.string().min(1, 'Description is required').max(200),
  category: z.string().min(1, 'Category is required'),
  date: z.string().datetime('Invalid date'),
  paymentMethod: z.enum(['cash', 'card', 'transfer', 'other']),
  tags: z.array(z.string().max(30)).max(10).optional(),
  receipt: z.string().url('Invalid receipt URL').optional(),
})

// Financial goal schema
export const goalSchema = z.object({
  name: z.string().min(1, 'Goal name is required').max(100),
  description: z.string().max(500).optional(),
  targetAmount: z.number().positive('Target amount must be positive'),
  currentAmount: z.number().min(0, 'Current amount cannot be negative').default(0),
  currency: currencySchema,
  targetDate: z.string().datetime('Invalid target date'),
  category: z.enum(['emergency', 'vacation', 'home', 'car', 'education', 'retirement', 'other']),
  priority: z.enum(['low', 'medium', 'high']).default('medium'),
})

// Contact form schema
export const contactSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  subject: z.string().min(1, 'Subject is required').max(200),
  message: z.string().min(10, 'Message must be at least 10 characters').max(2000),
})

// Newsletter subscription schema
export const newsletterSchema = z.object({
  email: emailSchema,
})

// Search schema
export const searchSchema = z.object({
  query: z.string().min(1, 'Search query is required').max(100),
  category: z.enum(['expenses', 'budgets', 'goals', 'all']).default('all'),
  limit: z.number().int().min(1).max(100).default(20),
  offset: z.number().int().min(0).default(0),
})

// Rate limiting schemas
export const rateLimitSchema = z.object({
  identifier: z.string().min(1),
  windowMs: z.number().positive(),
  maxRequests: z.number().positive(),
})

const validationSchemas = {
  // OTP schemas
  sendOtpSchema,
  verifyOtpSchema,
  otpLoginSchema,

  // Traditional schemas
  registerSchema,
  loginSchema,
  changePasswordSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  updateProfileSchema,
  budgetSchema,
  expenseSchema,
  goalSchema,
  contactSchema,
  newsletterSchema,
  searchSchema,
  rateLimitSchema,
}

export default validationSchemas
