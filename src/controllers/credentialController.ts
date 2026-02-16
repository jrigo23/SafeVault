import { Response, NextFunction } from 'express';
import { Credential } from '../models/Credential';
import { AuthRequest } from '../middleware/auth';
import { createError } from '../middleware/errorHandler';

/**
 * Create a new credential
 */
export const createCredential = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { serviceName, username, password, url, notes, category } = req.body;

    const credential = new Credential({
      userId,
      serviceName,
      username,
      url,
      notes,
      category,
    });

    // Set encrypted password
    credential.setPassword(password);
    await credential.save();

    res.status(201).json({
      success: true,
      message: 'Credential created successfully',
      data: {
        id: credential._id,
        serviceName: credential.serviceName,
        username: credential.username,
        url: credential.url,
        category: credential.category,
        createdAt: credential.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all credentials for the authenticated user
 */
export const getCredentials = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const credentials = await Credential.find({ userId }).select('-encryptedPassword');

    res.json({
      success: true,
      data: credentials,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get a specific credential by ID
 */
export const getCredentialById = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;

    const credential = await Credential.findOne({ _id: id, userId });

    if (!credential) {
      throw createError('Credential not found', 404);
    }

    // Include decrypted password for this specific request
    res.json({
      success: true,
      data: {
        id: credential._id,
        serviceName: credential.serviceName,
        username: credential.username,
        password: credential.getDecryptedPassword(),
        url: credential.url,
        notes: credential.notes,
        category: credential.category,
        createdAt: credential.createdAt,
        updatedAt: credential.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a credential
 */
export const updateCredential = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;
    const { serviceName, username, password, url, notes, category } = req.body;

    const credential = await Credential.findOne({ _id: id, userId });

    if (!credential) {
      throw createError('Credential not found', 404);
    }

    // Update fields
    if (serviceName !== undefined) credential.serviceName = serviceName;
    if (username !== undefined) credential.username = username;
    if (password !== undefined) credential.setPassword(password);
    if (url !== undefined) credential.url = url;
    if (notes !== undefined) credential.notes = notes;
    if (category !== undefined) credential.category = category;

    await credential.save();

    res.json({
      success: true,
      message: 'Credential updated successfully',
      data: {
        id: credential._id,
        serviceName: credential.serviceName,
        username: credential.username,
        url: credential.url,
        category: credential.category,
        updatedAt: credential.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete a credential
 */
export const deleteCredential = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;

    const credential = await Credential.findOneAndDelete({ _id: id, userId });

    if (!credential) {
      throw createError('Credential not found', 404);
    }

    res.json({
      success: true,
      message: 'Credential deleted successfully',
    });
  } catch (error) {
    next(error);
  }
};
