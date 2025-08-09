import mongoose from 'mongoose';

const healthRecordSchema = new mongoose.Schema({
  // Patient Information
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  // FHIR Resource Information
  fhirResourceType: {
    type: String,
    enum: [
      'Patient', 'Observation', 'Condition', 'MedicationRequest', 
      'MedicationAdministration', 'Procedure', 'DiagnosticReport',
      'ImagingStudy', 'AllergyIntolerance', 'Immunization',
      'Encounter', 'DocumentReference', 'CarePlan', 'Goal'
    ],
    required: true
  },
  fhirId: {
    type: String,
    unique: true,
    sparse: true
  },
  
  // Record Metadata
  title: {
    type: String,
    required: true,
    maxlength: 200
  },
  description: {
    type: String,
    maxlength: 1000
  },
  category: {
    type: String,
    enum: [
      'vital-signs', 'laboratory', 'imaging', 'medication', 
      'procedure', 'diagnosis', 'allergy', 'immunization',
      'assessment', 'plan', 'progress-note', 'discharge-summary'
    ],
    required: true
  },
  
  // Healthcare Provider Information
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  providerName: String,
  organization: String,
  facility: String,
  
  // Temporal Information
  recordDate: {
    type: Date,
    required: true,
    default: Date.now
  },
  effectiveDate: Date, // When the observation/procedure actually occurred
  
  // Encrypted Health Data (FHIR-compliant structure)
  encryptedData: {
    type: String, // Encrypted JSON string of FHIR resource
    required: true
  },
  dataHash: {
    type: String, // Hash for integrity verification
    required: true
  },
  
  // Metadata (stored unencrypted for searching/filtering)
  metadata: {
    // Vital Signs
    vitalSigns: {
      bloodPressure: {
        systolic: Number,
        diastolic: Number,
        unit: { type: String, default: 'mmHg' }
      },
      heartRate: {
        value: Number,
        unit: { type: String, default: 'bpm' }
      },
      temperature: {
        value: Number,
        unit: { type: String, default: 'celsius' }
      },
      weight: {
        value: Number,
        unit: { type: String, default: 'kg' }
      },
      height: {
        value: Number,
        unit: { type: String, default: 'cm' }
      },
      bmi: Number,
      oxygenSaturation: {
        value: Number,
        unit: { type: String, default: '%' }
      }
    },
    
    // Laboratory Results
    laboratory: {
      testName: String,
      result: String,
      referenceRange: String,
      unit: String,
      abnormalFlag: {
        type: String,
        enum: ['normal', 'high', 'low', 'critical-high', 'critical-low']
      }
    },
    
    // Medications
    medication: {
      name: String,
      dosage: String,
      frequency: String,
      route: String,
      duration: String,
      indication: String
    },
    
    // Diagnoses/Conditions
    condition: {
      code: String, // ICD-10 or SNOMED CT
      display: String,
      severity: {
        type: String,
        enum: ['mild', 'moderate', 'severe']
      },
      status: {
        type: String,
        enum: ['active', 'resolved', 'inactive']
      }
    },
    
    // Procedures
    procedure: {
      code: String, // CPT or SNOMED CT
      display: String,
      outcome: String,
      complications: [String]
    },
    
    // Allergies
    allergy: {
      substance: String,
      reaction: [String],
      severity: {
        type: String,
        enum: ['mild', 'moderate', 'severe', 'life-threatening']
      }
    }
  },
  
  // File Attachments (encrypted)
  attachments: [{
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number,
    encryptedPath: String,
    fileHash: String,
    uploadDate: { type: Date, default: Date.now }
  }],
  
  // DICOM Information (for medical imaging)
  dicomInfo: {
    studyInstanceUID: String,
    seriesInstanceUID: String,
    sopInstanceUID: String,
    modality: String, // CT, MRI, X-RAY, etc.
    bodyPart: String,
    studyDescription: String,
    seriesDescription: String
  },
  
  // Tags for easy categorization and search
  tags: [{
    type: String,
    trim: true
  }],
  
  // Priority and Urgency
  priority: {
    type: String,
    enum: ['routine', 'urgent', 'stat', 'emergency'],
    default: 'routine'
  },
  
  // Status and Workflow
  status: {
    type: String,
    enum: ['draft', 'active', 'amended', 'corrected', 'cancelled', 'archived'],
    default: 'active'
  },
  
  // Version Control
  version: {
    type: Number,
    default: 1
  },
  parentRecordId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'HealthRecord'
  },
  amendments: [{
    amendedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    amendmentDate: { type: Date, default: Date.now },
    reason: String,
    changes: String
  }],
  
  // Access Control
  visibility: {
    type: String,
    enum: ['private', 'shared', 'emergency'],
    default: 'private'
  },
  sharedWith: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permissions: [{
      type: String,
      enum: ['read', 'write', 'comment']
    }],
    sharedDate: { type: Date, default: Date.now },
    expiryDate: Date
  }],
  
  // Compliance and Audit
  complianceFlags: {
    hipaaCompliant: { type: Boolean, default: true },
    gdprCompliant: { type: Boolean, default: true },
    retentionPeriod: { type: Number, default: 2555 }, // days (7 years)
  },
  
  // Blockchain Integration
  blockchainTxHash: String, // Transaction hash for immutable logging
  
  // Quality and Validation
  qualityScore: {
    type: Number,
    min: 0,
    max: 100
  },
  validationStatus: {
    type: String,
    enum: ['pending', 'validated', 'rejected'],
    default: 'pending'
  },
  validatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  validationDate: Date,
  
  // AI Analysis Results
  aiInsights: {
    riskAssessment: {
      score: Number,
      category: String,
      recommendations: [String]
    },
    abnormalFindings: [String],
    drugInteractions: [String],
    followUpRecommendations: [String]
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
    ref: 'User',
    required: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance and querying
healthRecordSchema.index({ patientId: 1, recordDate: -1 });
healthRecordSchema.index({ fhirResourceType: 1 });
healthRecordSchema.index({ category: 1 });
healthRecordSchema.index({ providerId: 1 });
healthRecordSchema.index({ tags: 1 });
healthRecordSchema.index({ status: 1 });
healthRecordSchema.index({ 'metadata.condition.code': 1 });
healthRecordSchema.index({ 'metadata.medication.name': 1 });
healthRecordSchema.index({ recordDate: -1 });
healthRecordSchema.index({ createdAt: -1 });

// Compound indexes for common queries
healthRecordSchema.index({ patientId: 1, category: 1, recordDate: -1 });
healthRecordSchema.index({ patientId: 1, fhirResourceType: 1 });
healthRecordSchema.index({ patientId: 1, status: 1 });

// Text index for searching
healthRecordSchema.index({
  title: 'text',
  description: 'text',
  tags: 'text',
  'metadata.condition.display': 'text',
  'metadata.medication.name': 'text'
});

// Virtual for record age
healthRecordSchema.virtual('ageInDays').get(function() {
  return Math.floor((Date.now() - this.recordDate) / (1000 * 60 * 60 * 24));
});

// Method to check if record is expired based on retention policy
healthRecordSchema.methods.isExpired = function() {
  const retentionDays = this.complianceFlags.retentionPeriod || 2555;
  return this.ageInDays > retentionDays;
};

// Method to generate FHIR-compliant resource
healthRecordSchema.methods.toFHIR = function() {
  // This would contain logic to convert the stored data to FHIR format
  // Implementation would depend on the specific FHIR resource type
  return {
    resourceType: this.fhirResourceType,
    id: this.fhirId || this._id.toString(),
    meta: {
      versionId: this.version.toString(),
      lastUpdated: this.updatedAt.toISOString()
    },
    // Additional FHIR-specific fields would be added here
  };
};

// Static method to find records by patient and date range
healthRecordSchema.statics.findByPatientAndDateRange = function(patientId, startDate, endDate) {
  return this.find({
    patientId,
    recordDate: {
      $gte: startDate,
      $lte: endDate
    },
    status: { $ne: 'cancelled' }
  }).sort({ recordDate: -1 });
};

// Static method to find records by category
healthRecordSchema.statics.findByCategory = function(patientId, category) {
  return this.find({
    patientId,
    category,
    status: { $ne: 'cancelled' }
  }).sort({ recordDate: -1 });
};

// Pre-save middleware to update version and lastModifiedBy
healthRecordSchema.pre('save', function(next) {
  if (this.isModified() && !this.isNew) {
    this.version += 1;
    this.updatedAt = new Date();
  }
  next();
});

export default mongoose.model('HealthRecord', healthRecordSchema);