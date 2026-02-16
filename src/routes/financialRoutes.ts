import { Router } from 'express';
import { body, param, query } from 'express-validator';
import {
  createFinancialRecord,
  getFinancialRecords,
  getFinancialRecordById,
  updateFinancialRecord,
  deleteFinancialRecord,
} from '../controllers/financialController';
import { authenticate } from '../middleware/auth';
import { validate } from '../middleware/validation';

const router = Router();

// All routes require authentication
router.use(authenticate);

// Validation rules
const createFinancialRecordValidation = [
  body('recordType')
    .isIn(['bank_account', 'credit_card', 'investment', 'other'])
    .withMessage('Invalid record type'),
  body('institutionName')
    .trim()
    .notEmpty()
    .withMessage('Institution name is required')
    .isLength({ max: 100 })
    .withMessage('Institution name must not exceed 100 characters'),
  body('accountName')
    .trim()
    .notEmpty()
    .withMessage('Account name is required')
    .isLength({ max: 100 })
    .withMessage('Account name must not exceed 100 characters'),
  body('accountNumber')
    .notEmpty()
    .withMessage('Account number is required'),
  body('routingNumber')
    .optional(),
  body('cvv')
    .optional(),
  body('expirationDate')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date'),
  body('balance')
    .optional()
    .isNumeric()
    .withMessage('Balance must be a number'),
  body('currency')
    .optional()
    .trim()
    .isLength({ min: 3, max: 3 })
    .withMessage('Currency code must be 3 characters'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes must not exceed 1000 characters'),
];

const updateFinancialRecordValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid financial record ID'),
  body('recordType')
    .optional()
    .isIn(['bank_account', 'credit_card', 'investment', 'other'])
    .withMessage('Invalid record type'),
  body('institutionName')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Institution name cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Institution name must not exceed 100 characters'),
  body('accountName')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Account name cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Account name must not exceed 100 characters'),
  body('accountNumber')
    .optional()
    .notEmpty()
    .withMessage('Account number cannot be empty'),
  body('routingNumber')
    .optional(),
  body('cvv')
    .optional(),
  body('expirationDate')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date'),
  body('balance')
    .optional()
    .isNumeric()
    .withMessage('Balance must be a number'),
  body('currency')
    .optional()
    .trim()
    .isLength({ min: 3, max: 3 })
    .withMessage('Currency code must be 3 characters'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes must not exceed 1000 characters'),
];

const idValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid financial record ID'),
];

const listValidation = [
  query('recordType')
    .optional()
    .isIn(['bank_account', 'credit_card', 'investment', 'other'])
    .withMessage('Invalid record type'),
];

// Routes
router.post('/', validate(createFinancialRecordValidation), createFinancialRecord);
router.get('/', validate(listValidation), getFinancialRecords);
router.get('/:id', validate(idValidation), getFinancialRecordById);
router.put('/:id', validate(updateFinancialRecordValidation), updateFinancialRecord);
router.delete('/:id', validate(idValidation), deleteFinancialRecord);

export default router;
