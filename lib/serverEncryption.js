// Server-side encryption service for API routes (Node.js runtime)
import crypto from 'crypto'
import bcrypt from 'bcryptjs'

export class ServerEncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm'
    this.secretKey = process.env.ENCRYPTION_SECRET 
      ? Buffer.from(process.env.ENCRYPTION_SECRET, 'hex')
      : crypto.randomBytes(32)
  }

  // Hash passwords
  async hashPassword(password) {
    const saltRounds = 12
    return await bcrypt.hash(password, saltRounds)
  }

  // Verify passwords
  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash)
  }

  // Generate secure tokens
  generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex')
  }

  // Hash sensitive identifiers
  hashIdentifier(identifier) {
    return crypto.createHash('sha256').update(identifier).digest('hex')
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

  // Encrypt sensitive data
  encrypt(text) {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipher(this.algorithm, this.secretKey)
    
    let encrypted = cipher.update(text, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    
    return {
      encrypted,
      iv: iv.toString('hex')
    }
  }

  // Decrypt sensitive data
  decrypt(encryptedData) {
    const { encrypted, iv } = encryptedData
    const decipher = crypto.createDecipher(this.algorithm, this.secretKey)
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    
    return decrypted
  }
}

export const serverEncryptionService = new ServerEncryptionService()
