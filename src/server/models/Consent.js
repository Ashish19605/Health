import mongoose from 'mongoose';

const consentSchema = new mongoose.Schema({
  // Core Consent Information
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  // Who is being granted access
  grantedTo: {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    organizationId: String, // For healthcare organizations
    role: {
      type: String,
      enum: ['provider', 'researcher', 'emergency', 'family', 'organization']
    },
    name: String, // Name of person/organization
    email: String,
    verificationStatus: {
      type: String,
      enum: ['pending', 'verified', 'denied'],
      default: 'pending'
    }
  },
  
  // Consent Type and Scope
  consentType: {
    type: String,
    enum: [
      'general-access',     // General health record access
      'emergency-access',   // Emergency access
      'research-participation', // Research studies
      'data-sharing',       // Share with other providers
      'family-access',      // Family member access
      'specific-record',    // Access to specific records only
      'telemedicine',       // Telemedicine consultations
      'analytics'           // Anonymized analytics
    ],
    required: true
  },
  
  // Data Categories Covered
  dataCategories: [{
    type: String,
    enum: [
      'all-records',
      'vital-signs',
      'laboratory-results',
      'imaging-studies',
      'medications',
      'diagnoses',
      'procedures',
      'allergies',
      'immunizations',
      'progress-notes',
      'discharge-summaries',
      'mental-health',
      'substance-abuse',
      'genetics',
      'reproductive-health'
    ]
  }],
  
  // Specific Records (if consentType is 'specific-record')
  specificRecords: [{
    recordId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'HealthRecord'
    },
    recordTitle: String,
    category: String
  }],
  
  // Purpose and Context
  purpose: {
    type: String,
    required: true,
    maxlength: 500
  },
  clinicalJustification: String,
  
  // Permissions Granted
  permissions: {
    read: { type: Boolean, default: true },
    write: { type: Boolean, default: false },
    share: { type: Boolean, default: false },
    download: { type: Boolean, default: false },
    print: { type: Boolean, default: false },
    comment: { type: Boolean, default: false }
  },
  
  // Temporal Constraints
  effectiveDate: {
    type: Date,
    default: Date.now
  },
  expirationDate: {
    type: Date,
    required: true
  },
  
  // Consent Status
  status: {
    type: String,
    enum: ['active', 'expired', 'revoked', 'pending', 'denied'],
    default: 'pending'
  },
  
  // Legal and Regulatory
  legalBasis: {
    type: String,
    enum: [
      'explicit-consent',
      'legitimate-interest',
      'vital-interest',
      'public-task',
      'legal-obligation',
      'contract'
    ],
    default: 'explicit-consent'
  },
  
  // Consent Capture Details
  consentMethod: {
    type: String,
    enum: ['digital-signature', 'verbal', 'written', 'implied', 'opt-in'],
    required: true
  },
  consentEvidence: {
    digitalSignature: String,
    ipAddress: String,
    userAgent: String,
    timestamp: Date,
    witnessId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    documentHash: String // Hash of consent form/document
  },
  
  // Withdrawal and Revocation
  withdrawalAllowed: {
    type: Boolean,
    default: true
  },
  withdrawalMethod: {
    type: String,
    enum: ['online', 'written-request', 'verbal', 'any-time'],
    default: 'online'
  },
  withdrawalInstructions: String,
  
  // Revocation Details (if revoked)
  revocationDate: Date,
  revocationReason: String,
  revokedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Granular Preferences
  preferences: {
    allowEmergencyOverride: {
      type: Boolean,
      default: true
    },
    allowResearchUse: {
      type: Boolean,
      default: false
    },
    allowCommercialUse: {
      type: Boolean,
      default: false
    },
    allowInternationalTransfer: {
      type: Boolean,
      default: false
    },
    requireReconfirmation: {
      type: Boolean,
      default: false
    },
    reconfirmationFrequency: Number // days
  },
  
  // Access Constraints
  accessConstraints: {
    timeBasedAccess: {
      allowedHours: {
        start: String, // HH:MM format
        end: String    // HH:MM format
      },
      allowedDays: [{
        type: String,
        enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
      }],
      timezone: String
    },
    locationBasedAccess: {
      allowedCountries: [String],
      allowedRegions: [String],
      restrictedLocations: [String]
    },
    deviceRestrictions: {
      allowedDeviceTypes: [{
        type: String,
        enum: ['desktop', 'mobile', 'tablet', 'kiosk']
      }],
      requireSecureConnection: {
        type: Boolean,
        default: true
      }
    }
  },
  
  // Usage Tracking
  usageTracking: {
    trackAccess: {
      type: Boolean,
      default: true
    },
    maxAccessCount: Number,
    currentAccessCount: {
      type: Number,
      default: 0
    },
    lastAccessDate: Date,
    accessHistory: [{
      accessDate: Date,
      accessedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      ipAddress: String,
      action: String,
      recordsAccessed: [String]
    }]
  },
  
  // Compliance and Audit
  complianceFlags: {
    hipaaCompliant: { type: Boolean, default: true },
    gdprCompliant: { type: Boolean, default: true },
    localRegulationCompliant: { type: Boolean, default: true }
  },
  
  // Blockchain Integration
  blockchainTxHash: String, // For immutable consent logging
  blockchainProof: String,  // Cryptographic proof of consent
  
  // Notifications
  notifications: {
    notifyOnAccess: {
      type: Boolean,
      default: false
    },
    notifyOnExpiry: {
      type: Boolean,
      default: true
    },
    notificationEmail: String,
    reminderSent: {
      type: Boolean,
      default: false
    }
  },
  
  // Delegation (for minors or incapacitated patients)
  delegation: {
    isDelegated: {
      type: Boolean,
      default: false
    },
    delegatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    relationship: String, // parent, guardian, power-of-attorney
    delegationDocument: String,
    delegationExpiry: Date
  },
  
  // Audit Trail
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
consentSchema.index({ patientId: 1, status: 1 });
consentSchema.index({ 'grantedTo.userId': 1 });
consentSchema.index({ consentType: 1 });
consentSchema.index({ status: 1, expirationDate: 1 });
consentSchema.index({ effectiveDate: 1, expirationDate: 1 });
consentSchema.index({ createdAt: -1 });
consentSchema.index({ blockchainTxHash: 1 });

// Compound indexes
consentSchema.index({ patientId: 1, 'grantedTo.userId': 1, status: 1 });
consentSchema.index({ patientId: 1, consentType: 1, status: 1 });

// Virtual for checking if consent is currently valid
consentSchema.virtual('isValid').get(function() {
  const now = new Date();
  return this.status === 'active' && 
         this.effectiveDate <= now && 
         this.expirationDate > now;
});

// Virtual for checking if consent is expired
consentSchema.virtual('isExpired').get(function() {
  return this.expirationDate <= new Date() && this.status !== 'revoked';
});

// Virtual for time remaining until expiry
consentSchema.virtual('timeUntilExpiry').get(function() {
  const now = new Date();
  return Math.max(0, this.expirationDate - now);
});

// Method to revoke consent
consentSchema.methods.revoke = function(revokedBy, reason) {
  this.status = 'revoked';
  this.revocationDate = new Date();
  this.revocationReason = reason;
  this.revokedBy = revokedBy;
  return this.save();
};

// Method to check if specific permission is granted
consentSchema.methods.hasPermission = function(permission) {
  return this.isValid && this.permissions[permission] === true;
};

// Method to record access
consentSchema.methods.recordAccess = function(accessedBy, action, recordsAccessed = []) {
  if (!this.usageTracking.trackAccess) return;
  
  this.usageTracking.currentAccessCount += 1;
  this.usageTracking.lastAccessDate = new Date();
  
  this.usageTracking.accessHistory.push({
    accessDate: new Date(),
    accessedBy,
    action,
    recordsAccessed
  });
  
  // Keep only last 100 access records for performance
  if (this.usageTracking.accessHistory.length > 100) {
    this.usageTracking.accessHistory = this.usageTracking.accessHistory.slice(-100);
  }
  
  return this.save();
};

// Method to check access constraints
consentSchema.methods.checkAccessConstraints = function(request = {}) {
  const constraints = this.accessConstraints;
  const now = new Date();
  
  // Check usage limits
  if (constraints.maxAccessCount && 
      this.usageTracking.currentAccessCount >= constraints.maxAccessCount) {
    return { allowed: false, reason: 'Access limit exceeded' };
  }
  
  // Check time-based constraints
  if (constraints.timeBasedAccess) {
    const currentTime = now.toTimeString().slice(0, 5); // HH:MM format
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'lowercase' });
    
    if (constraints.timeBasedAccess.allowedHours) {
      const { start, end } = constraints.timeBasedAccess.allowedHours;
      if (currentTime < start || currentTime > end) {
        return { allowed: false, reason: 'Outside allowed hours' };
      }
    }
    
    if (constraints.timeBasedAccess.allowedDays?.length > 0 &&
        !constraints.timeBasedAccess.allowedDays.includes(currentDay)) {
      return { allowed: false, reason: 'Outside allowed days' };
    }
  }
  
  // Check location-based constraints
  if (constraints.locationBasedAccess && request.location) {
    if (constraints.locationBasedAccess.allowedCountries?.length > 0 &&
        !constraints.locationBasedAccess.allowedCountries.includes(request.location.country)) {
      return { allowed: false, reason: 'Location not allowed' };
    }
  }
  
  return { allowed: true };
};

// Static method to find active consents for a user
consentSchema.statics.findActiveConsents = function(patientId, grantedToUserId) {
  const now = new Date();
  return this.find({
    patientId,
    'grantedTo.userId': grantedToUserId,
    status: 'active',
    effectiveDate: { $lte: now },
    expirationDate: { $gt: now }
  });
};

// Static method to find expiring consents
consentSchema.statics.findExpiringConsents = function(days = 30) {
  const now = new Date();
  const futureDate = new Date(now.getTime() + (days * 24 * 60 * 60 * 1000));
  
  return this.find({
    status: 'active',
    expirationDate: {
      $gte: now,
      $lte: futureDate
    },
    'notifications.notifyOnExpiry': true,
    'notifications.reminderSent': false
  });
};

// Pre-save middleware to handle status changes
consentSchema.pre('save', function(next) {
  const now = new Date();
  
  // Auto-expire consents
  if (this.status === 'active' && this.expirationDate <= now) {
    this.status = 'expired';
  }
  
  // Auto-activate pending consents
  if (this.status === 'pending' && this.effectiveDate <= now && this.expirationDate > now) {
    // Note: This would typically require additional verification
    // this.status = 'active';
  }
  
  next();
});

export default mongoose.model('Consent', consentSchema);