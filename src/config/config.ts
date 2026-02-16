import dotenv from 'dotenv';

dotenv.config();

interface Config {
  port: number;
  nodeEnv: string;
  mongodbUri: string;
  jwtSecret: string;
  jwtExpiration: string;
  encryptionKey: string;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  corsOrigin: string;
}

const config: Config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  mongodbUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/safevault',
  jwtSecret: process.env.JWT_SECRET || '',
  jwtExpiration: process.env.JWT_EXPIRATION || '24h',
  encryptionKey: process.env.ENCRYPTION_KEY || '',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
};

// Validate critical configuration
if (!config.jwtSecret || config.jwtSecret.length < 32) {
  console.error('ERROR: JWT_SECRET must be at least 32 characters long');
  process.exit(1);
}

if (!config.encryptionKey || config.encryptionKey.length < 64) {
  console.error('ERROR: ENCRYPTION_KEY must be a 64-character hexadecimal string (32 bytes)');
  process.exit(1);
}

export default config;
