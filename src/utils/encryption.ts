import crypto from 'crypto';
import config from '../config/config';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 64;

/**
 * Encrypts sensitive data using AES-256-GCM
 * @param text - The text to encrypt
 * @returns Encrypted data with IV, authTag, and salt in format: iv:authTag:salt:encryptedData
 */
export const encrypt = (text: string): string => {
  try {
    // Generate random IV and salt
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);
    
    // Derive key from encryption key
    const key = Buffer.from(config.encryptionKey, 'hex');
    
    // Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Encrypt the data
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    // Combine IV, authTag, salt, and encrypted data
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${salt.toString('hex')}:${encrypted}`;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
};

/**
 * Decrypts data encrypted with AES-256-GCM
 * @param encryptedData - The encrypted data in format: iv:authTag:salt:encryptedData
 * @returns Decrypted text
 */
export const decrypt = (encryptedData: string): string => {
  try {
    // Split the encrypted data
    const parts = encryptedData.split(':');
    if (parts.length !== 4) {
      throw new Error('Invalid encrypted data format');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[3];
    
    // Derive key from encryption key
    const key = Buffer.from(config.encryptionKey, 'hex');
    
    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
};

/**
 * Generates a secure random token
 * @param length - The length of the token in bytes (default: 32)
 * @returns Hex string token
 */
export const generateToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};
