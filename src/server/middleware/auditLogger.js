import mongoose from 'mongoose';

// Audit Log Schema for compliance tracking
const auditLogSchema = new mongoose.Schema({
  // Request Information
  requestId: {
    type: String,
    required: true,
    unique: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  // User Information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  userEmail: String,
  userRole: String,
  sessionId: String,
  
  // Request Details
  method: {
    type: String,
    required: true
  },
  endpoint: {
    type: String,
    required: true,
    index: true
  },
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  userAgent: String,
  
  // Security Context
  isAuthenticated: {
    type: Boolean,
    default: false
  },
  authMethod: String, // 'jwt', 'api-key', 'emergency'
  
  // Data Access Information
  dataAccessed: {
    patientIds: [String],
    recordIds: [String],
    dataTypes: [String], // 'vital-signs', 'lab-results', etc.
    sensitiveData: Boolean
  },
  
  // Consent Information
  consentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Consent'
  },
  emergencyAccess: {
    type: Boolean,
    default: false
  },
  emergencyJustification: String,
  
  // Response Information
  statusCode: Number,
  responseTime: Number, // milliseconds
  
  // Privacy and Security
  dataExported: {
    type: Boolean,
    default: false
  },
  fileDownloaded: {
    type: Boolean,
    default: false
  },
  dataModified: {
    type: Boolean,
    default: false
  },
  
  // Compliance Flags
  hipaaRelevant: {
    type: Boolean,
    default: false
  },
  gdprRelevant: {
    type: Boolean,
    default: false
  },
  
  // Risk Assessment
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  suspiciousActivity: {
    type: Boolean,
    default: false
  },
  
  // Additional Context
  requestSize: Number, // bytes
  responseSize: Number, // bytes
  errors: [String],
  warnings: [String]
}, {
  timestamps: false // We use our own timestamp field
});

// Indexes for performance and compliance queries
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ endpoint: 1, timestamp: -1 });
auditLogSchema.index({ emergencyAccess: 1, timestamp: -1 });
auditLogSchema.index({ suspiciousActivity: 1, timestamp: -1 });
auditLogSchema.index({ riskLevel: 1, timestamp: -1 });

// TTL index for automatic cleanup (7 years for healthcare compliance)
auditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 220752000 }); // 7 years

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

/**
 * Generate unique request ID
 */
const generateRequestId = () => {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Assess risk level based on request characteristics
 */
const assessRiskLevel = (req, auditData) => {
  let riskScore = 0;
  
  // High-risk endpoints
  const highRiskEndpoints = [
    '/api/health-records/emergency',
    '/api/users/admin',
    '/api/consent/revoke',
    '/api/auth/admin'
  ];
  
  // Medium-risk endpoints
  const mediumRiskEndpoints = [
    '/api/health-records',
    '/api/consent',
    '/api/users'
  ];
  
  // Check endpoint risk
  if (highRiskEndpoints.some(pattern => req.originalUrl.includes(pattern))) {
    riskScore += 3;
  } else if (mediumRiskEndpoints.some(pattern => req.originalUrl.includes(pattern))) {
    riskScore += 2;
  }
  
  // Check for emergency access
  if (auditData.emergencyAccess) {
    riskScore += 2;
  }
  
  // Check for bulk operations
  if (req.body && Array.isArray(req.body) && req.body.length > 10) {
    riskScore += 1;
  }
  
  // Check for non-business hours access
  const hour = new Date().getHours();
  if (hour < 6 || hour > 22) {
    riskScore += 1;
  }
  
  // Check for unusual IP patterns
  if (req.ip && (req.ip.includes('tor') || req.ip.includes('proxy'))) {
    riskScore += 2;
  }
  
  // Determine risk level
  if (riskScore >= 5) return 'critical';
  if (riskScore >= 3) return 'high';
  if (riskScore >= 2) return 'medium';
  return 'low';
};

/**
 * Detect suspicious activity patterns
 */
const detectSuspiciousActivity = async (req, auditData) => {
  if (!req.user) return false;
  
  const userId = req.user._id;
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  
  try {
    // Check for rapid successive requests
    const recentRequests = await AuditLog.countDocuments({
      userId,
      timestamp: { $gte: oneHourAgo }
    });
    
    if (recentRequests > 100) return true; // More than 100 requests in an hour
    
    // Check for access to many different patients in short time
    const recentPatientAccess = await AuditLog.distinct('dataAccessed.patientIds', {
      userId,
      timestamp: { $gte: oneHourAgo }
    });
    
    if (recentPatientAccess.length > 20) return true; // Access to more than 20 patients in an hour
    
    // Check for multiple failed authentication attempts
    if (req.originalUrl.includes('/auth/') && auditData.statusCode >= 400) {
      const failedAttempts = await AuditLog.countDocuments({
        userId,
        endpoint: { $regex: '/auth/' },
        statusCode: { $gte: 400 },
        timestamp: { $gte: oneHourAgo }
      });
      
      if (failedAttempts > 5) return true;
    }
    
    return false;
  } catch (error) {
    console.error('Error detecting suspicious activity:', error);
    return false;
  }
};

/**
 * Extract data access information from request
 */
const extractDataAccess = (req, res) => {
  const dataAccess = {
    patientIds: [],
    recordIds: [],
    dataTypes: [],
    sensitiveData: false
  };
  
  // Extract patient IDs from various sources
  if (req.params.patientId) {
    dataAccess.patientIds.push(req.params.patientId);
  }
  
  if (req.body.patientId) {
    dataAccess.patientIds.push(req.body.patientId);
  }
  
  if (req.query.patientId) {
    dataAccess.patientIds.push(req.query.patientId);
  }
  
  // Extract record IDs
  if (req.params.recordId) {
    dataAccess.recordIds.push(req.params.recordId);
  }
  
  if (req.body.recordIds && Array.isArray(req.body.recordIds)) {
    dataAccess.recordIds.push(...req.body.recordIds);
  }
  
  // Determine data types based on endpoint
  const endpoint = req.originalUrl.toLowerCase();
  if (endpoint.includes('vital-signs')) dataAccess.dataTypes.push('vital-signs');
  if (endpoint.includes('lab')) dataAccess.dataTypes.push('lab-results');
  if (endpoint.includes('medication')) dataAccess.dataTypes.push('medications');
  if (endpoint.includes('imaging')) dataAccess.dataTypes.push('imaging');
  if (endpoint.includes('mental-health')) {
    dataAccess.dataTypes.push('mental-health');
    dataAccess.sensitiveData = true;
  }
  if (endpoint.includes('genetics')) {
    dataAccess.dataTypes.push('genetics');
    dataAccess.sensitiveData = true;
  }
  
  return dataAccess;
};

/**
 * Main audit logging middleware
 */
export const auditLogger = async (req, res, next) => {
  const startTime = Date.now();
  const requestId = generateRequestId();
  
  // Add request ID to request for correlation
  req.requestId = requestId;
  
  // Override res.json to capture response data
  const originalJson = res.json;
  let responseData = null;
  
  res.json = function(data) {
    responseData = data;
    return originalJson.call(this, data);
  };
  
  // Continue with request processing
  next();
  
  // Log after response is sent
  res.on('finish', async () => {
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    try {
      // Extract data access information
      const dataAccessed = extractDataAccess(req, res);
      
      // Prepare audit log entry
      const auditData = {
        requestId,
        timestamp: new Date(startTime),
        
        // User information
        userId: req.user?._id,
        userEmail: req.user?.email,
        userRole: req.user?.role,
        
        // Request details
        method: req.method,
        endpoint: req.originalUrl,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        
        // Security context
        isAuthenticated: !!req.user,
        authMethod: req.apiAccess ? 'api-key' : (req.user ? 'jwt' : null),
        
        // Data access
        dataAccessed,
        
        // Consent information
        consentId: req.activeConsents?.[0]?._id,
        emergencyAccess: !!req.isEmergencyAccess,
        emergencyJustification: req.emergencyJustification,
        
        // Response information
        statusCode: res.statusCode,
        responseTime,
        
        // Privacy flags
        dataExported: req.method === 'GET' && res.statusCode === 200,
        fileDownloaded: req.originalUrl.includes('/download'),
        dataModified: ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && res.statusCode < 400,
        
        // Compliance flags
        hipaaRelevant: dataAccessed.patientIds.length > 0 || dataAccessed.sensitiveData,
        gdprRelevant: !!req.user,
        
        // Request/response sizes
        requestSize: req.get('Content-Length') ? parseInt(req.get('Content-Length')) : 0,
        responseSize: res.get('Content-Length') ? parseInt(res.get('Content-Length')) : 0
      };
      
      // Assess risk level
      auditData.riskLevel = assessRiskLevel(req, auditData);
      
      // Detect suspicious activity
      auditData.suspiciousActivity = await detectSuspiciousActivity(req, auditData);
      
      // Save audit log
      const auditLog = new AuditLog(auditData);
      await auditLog.save();
      
      // Alert on suspicious activity or high-risk operations
      if (auditData.suspiciousActivity || auditData.riskLevel === 'critical') {
        console.warn('SECURITY ALERT:', {
          type: auditData.suspiciousActivity ? 'SUSPICIOUS_ACTIVITY' : 'HIGH_RISK_OPERATION',
          requestId,
          userId: auditData.userId,
          endpoint: auditData.endpoint,
          riskLevel: auditData.riskLevel,
          timestamp: auditData.timestamp
        });
      }
      
    } catch (error) {
      console.error('Audit logging error:', error);
      // Don't fail the request if audit logging fails
    }
  });
};

/**
 * Get audit logs for compliance reporting
 */
export const getAuditLogs = async (filters = {}) => {
  try {
    const query = {};
    
    // Date range filter
    if (filters.startDate || filters.endDate) {
      query.timestamp = {};
      if (filters.startDate) query.timestamp.$gte = new Date(filters.startDate);
      if (filters.endDate) query.timestamp.$lte = new Date(filters.endDate);
    }
    
    // User filter
    if (filters.userId) {
      query.userId = filters.userId;
    }
    
    // Risk level filter
    if (filters.riskLevel) {
      query.riskLevel = filters.riskLevel;
    }
    
    // Patient access filter
    if (filters.patientId) {
      query['dataAccessed.patientIds'] = filters.patientId;
    }
    
    // Emergency access filter
    if (filters.emergencyAccess !== undefined) {
      query.emergencyAccess = filters.emergencyAccess;
    }
    
    const logs = await AuditLog.find(query)
      .populate('userId', 'firstName lastName email role')
      .sort({ timestamp: -1 })
      .limit(filters.limit || 1000);
    
    return logs;
  } catch (error) {
    console.error('Error retrieving audit logs:', error);
    throw error;
  }
};

/**
 * Generate compliance report
 */
export const generateComplianceReport = async (startDate, endDate) => {
  try {
    const dateFilter = {
      timestamp: {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      }
    };
    
    const [
      totalRequests,
      authenticatedRequests,
      emergencyAccess,
      suspiciousActivity,
      highRiskOperations,
      dataAccess,
      userActivity
    ] = await Promise.all([
      AuditLog.countDocuments(dateFilter),
      AuditLog.countDocuments({ ...dateFilter, isAuthenticated: true }),
      AuditLog.countDocuments({ ...dateFilter, emergencyAccess: true }),
      AuditLog.countDocuments({ ...dateFilter, suspiciousActivity: true }),
      AuditLog.countDocuments({ ...dateFilter, riskLevel: { $in: ['high', 'critical'] } }),
      AuditLog.aggregate([
        { $match: dateFilter },
        { $group: { _id: null, totalPatients: { $addToSet: '$dataAccessed.patientIds' } } }
      ]),
      AuditLog.aggregate([
        { $match: { ...dateFilter, isAuthenticated: true } },
        { $group: { _id: '$userId', requestCount: { $sum: 1 } } },
        { $sort: { requestCount: -1 } },
        { $limit: 10 }
      ])
    ]);
    
    return {
      period: { startDate, endDate },
      summary: {
        totalRequests,
        authenticatedRequests,
        emergencyAccessCount: emergencyAccess,
        suspiciousActivityCount: suspiciousActivity,
        highRiskOperations,
        uniquePatientsAccessed: dataAccess[0]?.totalPatients?.flat().filter(id => id).length || 0
      },
      topUsers: userActivity,
      generatedAt: new Date()
    };
  } catch (error) {
    console.error('Error generating compliance report:', error);
    throw error;
  }
};