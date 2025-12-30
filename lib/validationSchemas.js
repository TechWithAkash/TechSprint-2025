import { z } from 'zod'

// User Registration Schema
export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  name: z.string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name must be less than 50 characters'),
  confirmPassword: z.string(),
  terms: z.boolean().refine(val => val === true, 'You must accept the terms and conditions')
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// User Login Schema
export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional()
})

// Forgot Password Schema
export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address')
})

// Reset Password Schema
export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// Update Profile Schema
export const updateProfileSchema = z.object({
  name: z.string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name must be less than 50 characters')
    .optional(),
  email: z.string().email('Invalid email address').optional(),
  avatar: z.string().url('Invalid avatar URL').optional(),
  preferences: z.object({
    currency: z.enum(['USD', 'EUR', 'GBP', 'INR', 'JPY', 'CAD', 'AUD']).optional(),
    language: z.string().optional(),
    timezone: z.string().optional(),
    notifications: z.object({
      email: z.boolean().optional(),
      push: z.boolean().optional(),
      budgetAlerts: z.boolean().optional(),
      goalReminders: z.boolean().optional()
    }).optional(),
    privacy: z.object({
      shareData: z.boolean().optional(),
      analytics: z.boolean().optional()
    }).optional()
  }).optional(),
  profile: z.object({
    city: z.string().optional(),
    country: z.string().optional(),
    familySize: z.number().min(1).max(20).optional(),
    ageRange: z.enum(['18-25', '26-35', '36-45', '46-55', '56-65', '65+']).optional(),
    occupation: z.string().optional(),
    financialExperience: z.enum(['beginner', 'intermediate', 'advanced']).optional()
  }).optional()
})

// Change Password Schema
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  confirmPassword: z.string()
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// Email Verification Schema
export const emailVerificationSchema = z.object({
  token: z.string().min(1, 'Verification token is required')
})
