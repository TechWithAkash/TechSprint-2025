export class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message)
    this.statusCode = statusCode
    this.code = code
    this.isOperational = true
    
    Error.captureStackTrace(this, this.constructor)
  }
}

export const errorHandler = (error, req, res) => {
  let { statusCode = 500, message = 'Something went wrong', code } = error

  // MongoDB duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0]
    message = `${field} already exists`
    statusCode = 400
    code = 'DUPLICATE_KEY'
  }

  // MongoDB validation error
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map(err => err.message)
    message = errors.join(', ')
    statusCode = 400
    code = 'VALIDATION_ERROR'
  }

  // Zod validation error
  if (error.name === 'ZodError') {
    const errors = error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
    message = errors.join(', ')
    statusCode = 400
    code = 'VALIDATION_ERROR'
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    message = 'Invalid token'
    statusCode = 401
    code = 'INVALID_TOKEN'
  }

  if (error.name === 'TokenExpiredError') {
    message = 'Token expired'
    statusCode = 401
    code = 'TOKEN_EXPIRED'
  }

  // Log error for monitoring
  console.error('Error:', {
    message: error.message,
    stack: error.stack,
    statusCode,
    code,
    url: req?.url,
    method: req?.method,
    user: req?.user?.id
  })

  // Send error response
  res.status(statusCode).json({
    error: true,
    message,
    code,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: error.stack,
      details: error 
    })
  })
}

export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}

// Common error responses
export const commonErrors = {
  UNAUTHORIZED: new AppError('Unauthorized access', 401, 'UNAUTHORIZED'),
  FORBIDDEN: new AppError('Access forbidden', 403, 'FORBIDDEN'),
  NOT_FOUND: new AppError('Resource not found', 404, 'NOT_FOUND'),
  VALIDATION_ERROR: new AppError('Validation failed', 400, 'VALIDATION_ERROR'),
  DUPLICATE_EMAIL: new AppError('Email already exists', 400, 'DUPLICATE_EMAIL'),
  INVALID_CREDENTIALS: new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS'),
  EMAIL_NOT_VERIFIED: new AppError('Please verify your email address', 401, 'EMAIL_NOT_VERIFIED'),
  INVALID_TOKEN: new AppError('Invalid or expired token', 400, 'INVALID_TOKEN'),
  PASSWORD_MISMATCH: new AppError('Current password is incorrect', 400, 'PASSWORD_MISMATCH'),
  RATE_LIMIT_EXCEEDED: new AppError('Too many requests. Please try again later.', 429, 'RATE_LIMIT_EXCEEDED')
}
