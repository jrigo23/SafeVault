import { Response, NextFunction } from 'express';
import { FinancialRecord } from '../models/FinancialRecord';
import { AuthRequest } from '../middleware/auth';
import { createError } from '../middleware/errorHandler';

/**
 * Create a new financial record
 */
export const createFinancialRecord = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const {
      recordType,
      institutionName,
      accountName,
      accountNumber,
      routingNumber,
      cvv,
      expirationDate,
      balance,
      currency,
      notes,
    } = req.body;

    const record = new FinancialRecord({
      userId,
      recordType,
      institutionName,
      accountName,
      expirationDate,
      balance,
      currency,
      notes,
    });

    // Set encrypted fields
    record.setAccountNumber(accountNumber);
    if (routingNumber) record.setRoutingNumber(routingNumber);
    if (cvv) record.setCvv(cvv);

    await record.save();

    res.status(201).json({
      success: true,
      message: 'Financial record created successfully',
      data: {
        id: record._id,
        recordType: record.recordType,
        institutionName: record.institutionName,
        accountName: record.accountName,
        balance: record.balance,
        currency: record.currency,
        createdAt: record.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all financial records for the authenticated user
 */
export const getFinancialRecords = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { recordType } = req.query;

    const filter: any = { userId };
    if (recordType) {
      filter.recordType = recordType;
    }

    const records = await FinancialRecord.find(filter).select(
      '-encryptedAccountNumber -encryptedRoutingNumber -encryptedCvv'
    );

    res.json({
      success: true,
      data: records,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get a specific financial record by ID
 */
export const getFinancialRecordById = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;

    const record = await FinancialRecord.findOne({ _id: id, userId });

    if (!record) {
      throw createError('Financial record not found', 404);
    }

    // Include decrypted sensitive data for this specific request
    res.json({
      success: true,
      data: {
        id: record._id,
        recordType: record.recordType,
        institutionName: record.institutionName,
        accountName: record.accountName,
        accountNumber: record.getDecryptedAccountNumber(),
        routingNumber: record.getDecryptedRoutingNumber(),
        cvv: record.getDecryptedCvv(),
        expirationDate: record.expirationDate,
        balance: record.balance,
        currency: record.currency,
        notes: record.notes,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a financial record
 */
export const updateFinancialRecord = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;
    const {
      recordType,
      institutionName,
      accountName,
      accountNumber,
      routingNumber,
      cvv,
      expirationDate,
      balance,
      currency,
      notes,
    } = req.body;

    const record = await FinancialRecord.findOne({ _id: id, userId });

    if (!record) {
      throw createError('Financial record not found', 404);
    }

    // Update fields
    if (recordType !== undefined) record.recordType = recordType;
    if (institutionName !== undefined) record.institutionName = institutionName;
    if (accountName !== undefined) record.accountName = accountName;
    if (accountNumber !== undefined) record.setAccountNumber(accountNumber);
    if (routingNumber !== undefined) record.setRoutingNumber(routingNumber);
    if (cvv !== undefined) record.setCvv(cvv);
    if (expirationDate !== undefined) record.expirationDate = expirationDate;
    if (balance !== undefined) record.balance = balance;
    if (currency !== undefined) record.currency = currency;
    if (notes !== undefined) record.notes = notes;

    await record.save();

    res.json({
      success: true,
      message: 'Financial record updated successfully',
      data: {
        id: record._id,
        recordType: record.recordType,
        institutionName: record.institutionName,
        accountName: record.accountName,
        balance: record.balance,
        currency: record.currency,
        updatedAt: record.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete a financial record
 */
export const deleteFinancialRecord = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const userId = req.userId!;
    const { id } = req.params;

    const record = await FinancialRecord.findOneAndDelete({ _id: id, userId });

    if (!record) {
      throw createError('Financial record not found', 404);
    }

    res.json({
      success: true,
      message: 'Financial record deleted successfully',
    });
  } catch (error) {
    next(error);
  }
};
