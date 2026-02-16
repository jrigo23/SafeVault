import { Request, Response, NextFunction } from 'express';
import { User } from '../models/User';
import { generateAuthToken } from '../middleware/auth';
import { createError } from '../middleware/errorHandler';

/**
 * Register a new user
 */
export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      throw createError('User with this email or username already exists', 409);
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
    });

    await user.save();

    // Generate token
    const token = generateAuthToken(user._id.toString());

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        userId: user._id,
        username: user.username,
        email: user.email,
        token,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Login user
 */
export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Find user and include password field
    const user = await User.findOne({ email }).select('+password');

    if (!user || !user.isActive) {
      throw createError('Invalid email or password', 401);
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      throw createError('Invalid email or password', 401);
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateAuthToken(user._id.toString());

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        userId: user._id,
        username: user.username,
        email: user.email,
        token,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get current user profile
 */
export const getProfile = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = (req as any).userId;
    const user = await User.findById(userId);

    if (!user) {
      throw createError('User not found', 404);
    }

    res.json({
      success: true,
      data: {
        userId: user._id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      },
    });
  } catch (error) {
    next(error);
  }
};
