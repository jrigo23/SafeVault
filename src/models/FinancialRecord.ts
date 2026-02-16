import mongoose, { Document, Schema } from 'mongoose';
import { encrypt, decrypt } from '../utils/encryption';

export interface IFinancialRecord extends Document {
  userId: mongoose.Types.ObjectId;
  recordType: 'bank_account' | 'credit_card' | 'investment' | 'other';
  institutionName: string;
  accountName: string;
  encryptedAccountNumber: string;
  encryptedRoutingNumber?: string;
  encryptedCvv?: string;
  expirationDate?: Date;
  balance?: number;
  currency?: string;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
  getDecryptedAccountNumber(): string;
  setAccountNumber(accountNumber: string): void;
  getDecryptedRoutingNumber(): string | undefined;
  setRoutingNumber(routingNumber: string): void;
  getDecryptedCvv(): string | undefined;
  setCvv(cvv: string): void;
}

const financialRecordSchema = new Schema<IFinancialRecord>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true,
    },
    recordType: {
      type: String,
      required: [true, 'Record type is required'],
      enum: {
        values: ['bank_account', 'credit_card', 'investment', 'other'],
        message: 'Invalid record type',
      },
    },
    institutionName: {
      type: String,
      required: [true, 'Institution name is required'],
      trim: true,
      maxlength: [100, 'Institution name must not exceed 100 characters'],
    },
    accountName: {
      type: String,
      required: [true, 'Account name is required'],
      trim: true,
      maxlength: [100, 'Account name must not exceed 100 characters'],
    },
    encryptedAccountNumber: {
      type: String,
      required: [true, 'Account number is required'],
    },
    encryptedRoutingNumber: {
      type: String,
    },
    encryptedCvv: {
      type: String,
    },
    expirationDate: {
      type: Date,
    },
    balance: {
      type: Number,
    },
    currency: {
      type: String,
      default: 'USD',
      maxlength: [3, 'Currency code must be 3 characters'],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [1000, 'Notes must not exceed 1000 characters'],
    },
  },
  {
    timestamps: true,
  }
);

// Methods to decrypt sensitive fields
financialRecordSchema.methods.getDecryptedAccountNumber = function (): string {
  return decrypt(this.encryptedAccountNumber);
};

financialRecordSchema.methods.setAccountNumber = function (accountNumber: string): void {
  this.encryptedAccountNumber = encrypt(accountNumber);
};

financialRecordSchema.methods.getDecryptedRoutingNumber = function (): string | undefined {
  return this.encryptedRoutingNumber ? decrypt(this.encryptedRoutingNumber) : undefined;
};

financialRecordSchema.methods.setRoutingNumber = function (routingNumber: string): void {
  this.encryptedRoutingNumber = encrypt(routingNumber);
};

financialRecordSchema.methods.getDecryptedCvv = function (): string | undefined {
  return this.encryptedCvv ? decrypt(this.encryptedCvv) : undefined;
};

financialRecordSchema.methods.setCvv = function (cvv: string): void {
  this.encryptedCvv = encrypt(cvv);
};

// Remove encrypted fields from JSON output
financialRecordSchema.set('toJSON', {
  transform: function (doc, ret) {
    delete ret.encryptedAccountNumber;
    delete ret.encryptedRoutingNumber;
    delete ret.encryptedCvv;
    return ret;
  },
});

// Index for user financial records lookup
financialRecordSchema.index({ userId: 1, recordType: 1 });
financialRecordSchema.index({ userId: 1, institutionName: 1 });

export const FinancialRecord = mongoose.model<IFinancialRecord>('FinancialRecord', financialRecordSchema);
