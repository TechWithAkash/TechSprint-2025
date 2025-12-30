// Modern encryption service with proper error handling
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import config from './config.js'

export class EncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm'
    this.saltRounds = config.security.bcryptRounds
    this.secretKey = this.#initializeSecretKey()
  }

  /**
   * Initialize encryption secret key
   */
  #initializeSecretKey() {
    if (process.env.ENCRYPTION_SECRET) {
      const key = Buffer.from(process.env.ENCRYPTION_SECRET, 'hex')
      if (key.length !== 32) {
        throw new Error('ENCRYPTION_SECRET must be exactly 32 bytes (64 hex characters)')
      }
      return key
    }
    
    // For development - generate and warn
    const key = crypto.randomBytes(32)
    console.warn('⚠️ ENCRYPTION_SECRET not set - using random key (data will not persist across restarts)')
    console.log(`Generated key: ${key.toString('hex')}`)
    return key
  }

  /**
   * Encrypt sensitive data with AES-256-GCM
   */
  encrypt(text) {
    if (!text || typeof text !== 'string') {
      throw new Error('Text must be a non-empty string')
    }

    try {
      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipherGCM(this.algorithm, this.secretKey, iv)
      
      let encrypted = cipher.update(text, 'utf8', 'hex')
      encrypted += cipher.final('hex')
      
      const authTag = cipher.getAuthTag()
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      }
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`)
    }
  }

  /**
   * Decrypt sensitive data
   */
  decrypt(encryptedData) {
    if (!encryptedData || typeof encryptedData !== 'object') {
      throw new Error('Encrypted data must be an object with encrypted, iv, and authTag properties')
    }

    const { encrypted, iv, authTag } = encryptedData
    
    if (!encrypted || !iv || !authTag) {
      throw new Error('Missing required encryption properties')
    }

    try {
      const decipher = crypto.createDecipherGCM(this.algorithm, this.secretKey, Buffer.from(iv, 'hex'))
      decipher.setAuthTag(Buffer.from(authTag, 'hex'))
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8')
      decrypted += decipher.final('utf8')
      
      return decrypted
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`)
    }
  }

  /**
   * Hash a password using bcrypt
   */
  async hashPassword(password) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string')
    }

    try {
      const salt = await bcrypt.genSalt(this.saltRounds)
      return await bcrypt.hash(password, salt)
    } catch (error) {
      throw new Error(`Password hashing failed: ${error.message}`)
    }
  }

  /**
   * Verify a password against its hash
   */
  async verifyPassword(password, hash) {
    if (!password || !hash) {
      return false
    }

    try {
      return await bcrypt.compare(password, hash)
    } catch (error) {
      console.error('Password verification error:', error)
      return false
    }
  }

  /**
   * Generate a secure random token
   */
  generateSecureToken(length = 32) {
    try {
      return crypto.randomBytes(length).toString('hex')
    } catch (error) {
      throw new Error(`Token generation failed: ${error.message}`)
    }
  }

  /**
   * Hash sensitive identifiers with SHA-256
   */
  hashIdentifier(identifier) {
    if (!identifier || typeof identifier !== 'string') {
      throw new Error('Identifier must be a non-empty string')
    }

    try {
      return crypto.createHash('sha256').update(identifier).digest('hex')
    } catch (error) {
      throw new Error(`Identifier hashing failed: ${error.message}`)
    }
  }

  /**
   * Generate email verification token with expiry
   */
  generateEmailVerificationToken() {
    const token = this.generateSecureToken(32)
    const expiresAt = new Date(Date.now() + config.security.tokenExpiry.emailVerification)
    
    return { token, expiresAt }
  }

  /**
   * Generate password reset token with expiry
   */
  generatePasswordResetToken() {
    const token = this.generateSecureToken(32)
    const expiresAt = new Date(Date.now() + config.security.tokenExpiry.passwordReset)
    
    return { token, expiresAt }
  }

  /**
   * Validate token format
   */
  isValidToken(token) {
    if (!token || typeof token !== 'string') {
      return false
    }
    
    // Check if token is hexadecimal and has appropriate length
    return /^[a-f0-9]{32,}$/i.test(token)
  }

  /**
   * Generate session token
   */
  generateSessionToken() {
    const token = this.generateSecureToken(48)
    const expiresAt = new Date(Date.now() + config.security.tokenExpiry.session)
    
    return { token, expiresAt }
  }
}

// Create singleton instance
export const encryptionService = new EncryptionService()
export default encryptionService
