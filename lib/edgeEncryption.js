// Edge Runtime compatible encryption service
// Uses Web Crypto API instead of Node.js crypto module

export class EdgeEncryptionService {
  constructor() {
    this.algorithm = 'AES-GCM'
  }

  // Generate secure random bytes using Web Crypto API
  generateRandomBytes(length = 32) {
    const array = new Uint8Array(length)
    crypto.getRandomValues(array)
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  // Generate secure tokens
  generateToken(length = 32) {
    return this.generateRandomBytes(length)
  }

  // Hash sensitive identifiers using Web Crypto API
  async hashIdentifier(identifier) {
    const encoder = new TextEncoder()
    const data = encoder.encode(identifier)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  // Generate password reset token
  generatePasswordResetToken() {
    return {
      token: this.generateToken(32),
      expires: new Date(Date.now() + 3600000) // 1 hour
    }
  }

  // Generate email verification token
  generateEmailVerificationToken() {
    return this.generateToken(32)
  }

  // Note: Password hashing should be done in API routes (Node.js runtime)
  // bcrypt is not compatible with Edge Runtime
}

export const edgeEncryptionService = new EdgeEncryptionService()
