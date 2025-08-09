import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// Generate JWT token
export const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      issuer: 'health-vault',
      audience: 'health-vault-users'
    }
  );
};

// Verify JWT token and authenticate user
export const authenticateToken = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user and check if account is active
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token - user not found'
      });
    }

    // Check if account is locked or suspended
    if (user.accountLocked || user.isLocked) {
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked due to security reasons'
      });
    }

    if (user.accountStatus !== 'active') {
      return res.status(403).json({
        success: false,
        message: 'Account is not active'
      });
    }

    // Add user to request object
    req.user = user;
    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    console.error('Authentication error:', error);
    return res.status(500).json({
      success: false,
      message: 'Authentication error'
    });
  }
};

// Role-based access control middleware
export const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

// Middleware to check if user is a verified healthcare provider
export const requireVerifiedProvider = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (req.user.role !== 'provider') {
      return res.status(403).json({
        success: false,
        message: 'Healthcare provider access required'
      });
    }

    if (!req.user.providerInfo || 
        req.user.providerInfo.verificationStatus !== 'verified') {
      return res.status(403).json({
        success: false,
        message: 'Verified healthcare provider status required'
      });
    }

    next();
  } catch (error) {
    console.error('Provider verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Provider verification error'
    });
  }
};

// Middleware to check if user can access patient data
export const checkPatientAccess = async (req, res, next) => {
  try {
    const patientId = req.params.patientId || req.body.patientId;
    
    if (!patientId) {
      return res.status(400).json({
        success: false,
        message: 'Patient ID required'
      });
    }

    // If user is accessing their own data
    if (req.user._id.toString() === patientId) {
      req.isOwnData = true;
      return next();
    }

    // If user is admin, allow access
    if (req.user.role === 'admin') {
      req.isOwnData = false;
      return next();
    }

    // For healthcare providers, check consent
    if (req.user.role === 'provider') {
      const Consent = (await import('../models/Consent.js')).default;
      
      const activeConsents = await Consent.findActiveConsents(
        patientId, 
        req.user._id
      );

      if (activeConsents.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'No active consent found for accessing this patient data'
        });
      }

      // Check if consent allows the requested action
      const hasReadPermission = activeConsents.some(consent => 
        consent.hasPermission('read')
      );

      if (!hasReadPermission) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to access patient data'
        });
      }

      req.isOwnData = false;
      req.activeConsents = activeConsents;
      return next();
    }

    // For other roles, deny access
    return res.status(403).json({
      success: false,
      message: 'Unauthorized access to patient data'
    });

  } catch (error) {
    console.error('Patient access check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Access verification error'
    });
  }
};

// Middleware for emergency access (overrides normal consent requirements)
export const emergencyAccess = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Only healthcare providers can request emergency access
    if (req.user.role !== 'provider' || 
        req.user.providerInfo?.verificationStatus !== 'verified') {
      return res.status(403).json({
        success: false,
        message: 'Verified healthcare provider required for emergency access'
      });
    }

    // Emergency access should be logged and require justification
    const justification = req.body.emergencyJustification || req.headers['x-emergency-justification'];
    
    if (!justification) {
      return res.status(400).json({
        success: false,
        message: 'Emergency justification required'
      });
    }

    // Log emergency access attempt
    console.log('EMERGENCY ACCESS ATTEMPT:', {
      providerId: req.user._id,
      providerName: req.user.fullName,
      patientId: req.params.patientId,
      justification,
      timestamp: new Date(),
      ipAddress: req.ip
    });

    req.isEmergencyAccess = true;
    req.emergencyJustification = justification;
    next();

  } catch (error) {
    console.error('Emergency access error:', error);
    return res.status(500).json({
      success: false,
      message: 'Emergency access verification error'
    });
  }
};

// Middleware to check API rate limits per user
export const userRateLimit = (maxRequests = 1000, windowMinutes = 60) => {
  const userRequestCounts = new Map();

  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userId = req.user._id.toString();
    const now = Date.now();
    const windowMs = windowMinutes * 60 * 1000;

    // Clean up old entries
    for (const [id, data] of userRequestCounts.entries()) {
      if (now - data.resetTime > windowMs) {
        userRequestCounts.delete(id);
      }
    }

    // Check current user's rate
    const userRequests = userRequestCounts.get(userId) || {
      count: 0,
      resetTime: now
    };

    if (now - userRequests.resetTime > windowMs) {
      userRequests.count = 0;
      userRequests.resetTime = now;
    }

    if (userRequests.count >= maxRequests) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please try again later.',
        retryAfter: Math.ceil((windowMs - (now - userRequests.resetTime)) / 1000)
      });
    }

    userRequests.count++;
    userRequestCounts.set(userId, userRequests);

    next();
  };
};

// Middleware to validate API key for third-party integrations
export const validateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required'
      });
    }

    // In a real implementation, you would validate the API key
    // against a database of registered applications
    // For now, we'll use a simple check
    const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
    
    if (!validApiKeys.includes(apiKey)) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    req.apiAccess = true;
    next();

  } catch (error) {
    console.error('API key validation error:', error);
    return res.status(500).json({
      success: false,
      message: 'API key validation error'
    });
  }
};

// Middleware to log security events
export const logSecurityEvent = (eventType) => {
  return (req, res, next) => {
    const securityEvent = {
      type: eventType,
      userId: req.user?._id,
      userEmail: req.user?.email,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date(),
      endpoint: req.originalUrl,
      method: req.method
    };

    // Log to console (in production, this would go to a security monitoring system)
    console.log('SECURITY EVENT:', securityEvent);

    // In production, you might want to store critical security events
    // in a separate security audit log database

    next();
  };
};