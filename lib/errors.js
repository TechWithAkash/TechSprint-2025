// Modern error handling utilities
import { ZodError } from 'zod'
import { NextResponse } from 'next/server'

// Custom error classes
export class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = null) {
    super(message)
    this.name = 'AppError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
    this.isOperational = true
    
    Error.captureStackTrace(this, this.constructor)
  }
}

export class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, 400, 'VALIDATION_ERROR', details)
    this.name = 'ValidationError'
  }
}

export class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR')
    this.name = 'AuthenticationError'
  }
}

export class AuthorizationError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR')
    this.name = 'AuthorizationError'
  }
}

export class NotFoundError extends AppError {
  constructor(resource = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND')
    this.name = 'NotFoundError'
  }
}

export class ConflictError extends AppError {
  constructor(message) {
    super(message, 409, 'CONFLICT_ERROR')
    this.name = 'ConflictError'
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Too many requests') {
    super(message, 429, 'RATE_LIMIT_ERROR')
    this.name = 'RateLimitError'
  }
}

// Error formatters
export const formatZodError = (error) => {
  if (!error?.errors || !Array.isArray(error.errors)) {
    return {
      type: 'validation',
      message: 'Validation failed',
      errors: [{
        field: 'unknown',
        message: 'Validation error occurred',
        code: 'validation_error'
      }]
    }
  }
  
  const formatted = error.errors.map(err => ({
    field: err.path?.join?.('.') || 'unknown',
    message: err.message || 'Validation error',
    code: err.code || 'validation_error',
  }))
  
  return {
    type: 'validation',
    message: 'Validation failed',
    errors: formatted,
  }
}

export const formatDatabaseError = (error) => {
  // MongoDB specific errors
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue || {})[0] || 'field'
    return new ConflictError(`${field} already exists`)
  }
  
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors || {}).map(err => ({
      field: err.path,
      message: err.message,
    }))
    return new ValidationError('Database validation failed', errors)
  }
  
  return new AppError('Database operation failed', 500, 'DATABASE_ERROR')
}

// Error response formatter
export const formatErrorResponse = (error) => {
  const isDevelopment = process.env.NODE_ENV === 'development'
  
  // Handle different error types
  if (error instanceof ZodError) {
    const formatted = formatZodError(error)
    return NextResponse.json(formatted, { status: 400 })
  }
  
  if (error instanceof AppError) {
    return NextResponse.json({
      type: 'error',
      message: error.message,
      code: error.code,
      ...(error.details && { details: error.details }),
      ...(isDevelopment && { stack: error.stack }),
    }, { status: error.statusCode })
  }
  
  // Database errors
  if (error.name === 'MongoError' || error.name === 'MongoServerError') {
    const formatted = formatDatabaseError(error)
    return formatErrorResponse(formatted)
  }
  
  // Default error
  return NextResponse.json({
    type: 'error',
    message: isDevelopment ? error.message : 'Internal server error',
    code: 'INTERNAL_ERROR',
    ...(isDevelopment && { stack: error.stack }),
  }, { status: 500 })
}

// Async handler wrapper for API routes
export const asyncHandler = (handler) => {
  return async (req, ...args) => {
    try {
      const result = await handler(req, ...args)
      
      // Ensure we always return a Response object
      if (!result || (typeof result.json !== 'function' && typeof result.text !== 'function')) {
        console.warn('Handler did not return a proper Response object')
        return NextResponse.json({ success: true })
      }
      
      return result
    } catch (error) {
      console.error('API Error:', error)
      return formatErrorResponse(error)
    }
  }
}

// Success response helper
export const createSuccessResponse = (data = null, message = 'Success', status = 200) => {
  return NextResponse.json({
    success: true,
    message,
    ...(data && { data }),
  }, { status })
}

// Validation helper
export const validateRequest = (schema, data) => {
  try {
    return schema.parse(data)
  } catch (error) {
    if (error instanceof ZodError) {
      throw error
    }
    throw new ValidationError('Invalid request data')
  }
}

const errorUtils = {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  formatErrorResponse,
  asyncHandler,
  createSuccessResponse,
  validateRequest,
}

export default errorUtils
