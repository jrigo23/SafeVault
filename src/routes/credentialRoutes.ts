import { Router } from 'express';
import { body, param } from 'express-validator';
import {
  createCredential,
  getCredentials,
  getCredentialById,
  updateCredential,
  deleteCredential,
} from '../controllers/credentialController';
import { authenticate } from '../middleware/auth';
import { validate } from '../middleware/validation';

const router = Router();

// All routes require authentication
router.use(authenticate);

// Validation rules
const createCredentialValidation = [
  body('serviceName')
    .trim()
    .notEmpty()
    .withMessage('Service name is required')
    .isLength({ max: 100 })
    .withMessage('Service name must not exceed 100 characters'),
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required')
    .isLength({ max: 100 })
    .withMessage('Username must not exceed 100 characters'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('url')
    .optional()
    .trim()
    .isURL()
    .withMessage('Please provide a valid URL')
    .isLength({ max: 500 })
    .withMessage('URL must not exceed 500 characters'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes must not exceed 1000 characters'),
  body('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Category must not exceed 50 characters'),
];

const updateCredentialValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid credential ID'),
  body('serviceName')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Service name cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Service name must not exceed 100 characters'),
  body('username')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Username cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Username must not exceed 100 characters'),
  body('password')
    .optional()
    .notEmpty()
    .withMessage('Password cannot be empty'),
  body('url')
    .optional()
    .trim()
    .isURL()
    .withMessage('Please provide a valid URL')
    .isLength({ max: 500 })
    .withMessage('URL must not exceed 500 characters'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes must not exceed 1000 characters'),
  body('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Category must not exceed 50 characters'),
];

const idValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid credential ID'),
];

// Routes
router.post('/', validate(createCredentialValidation), createCredential);
router.get('/', getCredentials);
router.get('/:id', validate(idValidation), getCredentialById);
router.put('/:id', validate(updateCredentialValidation), updateCredential);
router.delete('/:id', validate(idValidation), deleteCredential);

export default router;
