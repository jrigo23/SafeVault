import mongoose, { Document, Schema } from 'mongoose';
import { encrypt, decrypt } from '../utils/encryption';

export interface ICredential extends Document {
  userId: mongoose.Types.ObjectId;
  serviceName: string;
  username: string;
  encryptedPassword: string;
  url?: string;
  notes?: string;
  category?: string;
  createdAt: Date;
  updatedAt: Date;
  getDecryptedPassword(): string;
  setPassword(password: string): void;
}

const credentialSchema = new Schema<ICredential>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true,
    },
    serviceName: {
      type: String,
      required: [true, 'Service name is required'],
      trim: true,
      maxlength: [100, 'Service name must not exceed 100 characters'],
    },
    username: {
      type: String,
      required: [true, 'Username is required'],
      trim: true,
      maxlength: [100, 'Username must not exceed 100 characters'],
    },
    encryptedPassword: {
      type: String,
      required: [true, 'Password is required'],
    },
    url: {
      type: String,
      trim: true,
      maxlength: [500, 'URL must not exceed 500 characters'],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [1000, 'Notes must not exceed 1000 characters'],
    },
    category: {
      type: String,
      trim: true,
      maxlength: [50, 'Category must not exceed 50 characters'],
    },
  },
  {
    timestamps: true,
  }
);

// Method to decrypt password
credentialSchema.methods.getDecryptedPassword = function (): string {
  return decrypt(this.encryptedPassword);
};

// Method to set encrypted password
credentialSchema.methods.setPassword = function (password: string): void {
  this.encryptedPassword = encrypt(password);
};

// Virtual for password (for convenience in API)
credentialSchema.virtual('password')
  .get(function () {
    return this.getDecryptedPassword();
  })
  .set(function (password: string) {
    this.setPassword(password);
  });

// Ensure virtuals are included in JSON
credentialSchema.set('toJSON', {
  virtuals: false, // Don't include password in JSON for security
  transform: function (doc, ret) {
    delete ret.encryptedPassword; // Remove encrypted password from output
    return ret;
  },
});

// Index for user credentials lookup
credentialSchema.index({ userId: 1, serviceName: 1 });

export const Credential = mongoose.model<ICredential>('Credential', credentialSchema);
