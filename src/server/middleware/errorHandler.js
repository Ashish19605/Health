/**
 * Comprehensive error handling middleware for the Health Vault API
 */

export const errorHandler = (error, req, res, next) => {
  let statusCode = error.statusCode || 500;
  let message = error.message || 'Internal Server Error';
  let details = null;

  // Log error for monitoring (in production, this would go to a logging service)
  console.error('API Error:', {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    userId: req.user?._id,
    userEmail: req.user?.email,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    error: {
      name: error.name,
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    }
  });

  // Handle specific error types
  switch (error.name) {
    case 'ValidationError':
      statusCode = 400;
      message = 'Validation Error';
      details = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message,
        value: err.value
      }));
      break;

    case 'MongoServerError':
      if (error.code === 11000) {
        statusCode = 409;
        message = 'Duplicate field error';
        const field = Object.keys(error.keyPattern)[0];
        details = {
          field,
          message: `${field} already exists`
        };
      }
      break;

    case 'CastError':
      statusCode = 400;
      message = 'Invalid ID format';
      details = {
        field: error.path,
        value: error.value,
        message: 'Invalid ObjectId format'
      };
      break;

    case 'JsonWebTokenError':
      statusCode = 401;
      message = 'Invalid authentication token';
      break;

    case 'TokenExpiredError':
      statusCode = 401;
      message = 'Authentication token expired';
      break;

    case 'MulterError':
      statusCode = 400;
      if (error.code === 'LIMIT_FILE_SIZE') {
        message = 'File too large';
        details = {
          limit: error.limit,
          message: 'File size exceeds maximum allowed limit'
        };
      } else if (error.code === 'LIMIT_FILE_COUNT') {
        message = 'Too many files';
        details = {
          limit: error.limit,
          message: 'Number of files exceeds maximum allowed limit'
        };
      } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        message = 'Unexpected file field';
        details = {
          field: error.field,
          message: 'File uploaded to unexpected field'
        };
      }
      break;

    case 'EncryptionError':
      statusCode = 500;
      message = 'Data encryption/decryption failed';
      details = {
        message: 'Unable to process encrypted health data'
      };
      break;

    case 'ConsentError':
      statusCode = 403;
      message = 'Consent validation failed';
      details = {
        message: 'Required consent not found or expired'
      };
      break;

    case 'FHIRValidationError':
      statusCode = 400;
      message = 'FHIR resource validation failed';
      details = {
        resourceType: error.resourceType,
        validationErrors: error.validationErrors
      };
      break;

    case 'BlockchainError':
      statusCode = 503;
      message = 'Blockchain service unavailable';
      details = {
        message: 'Unable to record transaction on blockchain'
      };
      break;

    case 'RateLimitError':
      statusCode = 429;
      message = 'Rate limit exceeded';
      details = {
        retryAfter: error.retryAfter,
        limit: error.limit,
        window: error.window
      };
      break;

    default:
      // Handle HTTP errors
      if (error.status) {
        statusCode = error.status;
      }
      
      // Security: Don't expose internal errors in production
      if (process.env.NODE_ENV === 'production' && statusCode === 500) {
        message = 'Internal Server Error';
        details = null;
      }
  }

  // Create standardized error response
  const errorResponse = {
    success: false,
    error: {
      type: error.name || 'UnknownError',
      message,
      statusCode,
      timestamp: new Date().toISOString(),
      ...(details && { details }),
      ...(process.env.NODE_ENV === 'development' && { 
        stack: error.stack,
        originalError: error.message 
      })
    }
  };

  // Add request ID for tracking
  if (req.requestId) {
    errorResponse.error.requestId = req.requestId;
  }

  // Send error response
  res.status(statusCode).json(errorResponse);
};

/**
 * Handle 404 errors for undefined routes
 */
export const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      type: 'NotFoundError',
      message: 'Route not found',
      statusCode: 404,
      timestamp: new Date().toISOString(),
      details: {
        method: req.method,
        url: req.originalUrl,
        message: `Cannot ${req.method} ${req.originalUrl}`
      }
    }
  });
};

/**
 * Async error wrapper to catch promise rejections
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Custom error classes for specific scenarios
 */
export class HealthVaultError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = 'HealthVaultError';
    this.statusCode = statusCode;
  }
}

export class ConsentError extends Error {
  constructor(message, consentType, patientId) {
    super(message);
    this.name = 'ConsentError';
    this.statusCode = 403;
    this.consentType = consentType;
    this.patientId = patientId;
  }
}

export class EncryptionError extends Error {
  constructor(message, operation) {
    super(message);
    this.name = 'EncryptionError';
    this.statusCode = 500;
    this.operation = operation;
  }
}

export class FHIRValidationError extends Error {
  constructor(message, resourceType, validationErrors) {
    super(message);
    this.name = 'FHIRValidationError';
    this.statusCode = 400;
    this.resourceType = resourceType;
    this.validationErrors = validationErrors;
  }
}

export class BlockchainError extends Error {
  constructor(message, operation, txHash) {
    super(message);
    this.name = 'BlockchainError';
    this.statusCode = 503;
    this.operation = operation;
    this.txHash = txHash;
  }
}

export class RateLimitError extends Error {
  constructor(message, limit, window, retryAfter) {
    super(message);
    this.name = 'RateLimitError';
    this.statusCode = 429;
    this.limit = limit;
    this.window = window;
    this.retryAfter = retryAfter;
  }
}