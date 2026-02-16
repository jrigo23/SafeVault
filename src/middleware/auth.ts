import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config/config';
import { User } from '../models/User';

export interface AuthRequest extends Request {
  userId?: string;
  user?: any;
}

export interface JWTPayload {
  userId: string;
  iat?: number;
  exp?: number;
}

/**
 * Middleware to verify JWT token and authenticate user
 */
export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        message: 'No token provided. Please authenticate.',
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    try {
      // Verify token
      const decoded = jwt.verify(token, config.jwtSecret) as JWTPayload;
      
      // Attach user ID to request
      req.userId = decoded.userId;
      
      // Optionally verify user still exists and is active
      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive) {
        res.status(401).json({
          success: false,
          message: 'Invalid token or user is inactive.',
        });
        return;
      }
      
      req.user = user;
      next();
    } catch (jwtError) {
      if (jwtError instanceof jwt.TokenExpiredError) {
        res.status(401).json({
          success: false,
          message: 'Token has expired. Please login again.',
        });
        return;
      }
      
      res.status(401).json({
        success: false,
        message: 'Invalid token.',
      });
      return;
    }
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication failed.',
    });
  }
};

/**
 * Generate JWT token for user
 */
export const generateAuthToken = (userId: string): string => {
  const payload: JWTPayload = { userId };
  
  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiration,
  });
};
