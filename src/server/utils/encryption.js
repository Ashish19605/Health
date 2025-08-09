import crypto from 'crypto';
import forge from 'node-forge';

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16;  // 128 bits
const TAG_LENGTH = 16; // 128 bits

/**
 * Generate a secure encryption key
 */
export const generateEncryptionKey = () => {
  return crypto.randomBytes(KEY_LENGTH);
};

/**
 * Generate a secure initialization vector
 */
export const generateIV = () => {
  return crypto.randomBytes(IV_LENGTH);
};

/**
 * Derive encryption key from password using PBKDF2
 */
export const deriveKeyFromPassword = (password, salt) => {
  const saltBuffer = salt || crypto.randomBytes(32);
  const key = crypto.pbkdf2Sync(password, saltBuffer, 100000, KEY_LENGTH, 'sha256');
  return { key, salt: saltBuffer };
};

/**
 * Encrypt sensitive health data
 */
export const encryptHealthData = (data, encryptionKey) => {
  try {
    const iv = generateIV();
    const cipher = crypto.createCipher(ALGORITHM, encryptionKey, { authTagLength: TAG_LENGTH });
    cipher.setAAD(Buffer.from('health-data', 'utf8'));
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Combine IV, auth tag, and encrypted data
    const result = {
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      encrypted: encrypted,
      algorithm: ALGORITHM
    };
    
    return Buffer.from(JSON.stringify(result)).toString('base64');
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt health data');
  }
};

/**
 * Decrypt sensitive health data
 */
export const decryptHealthData = (encryptedData, encryptionKey) => {
  try {
    const dataBuffer = Buffer.from(encryptedData, 'base64');
    const { iv, authTag, encrypted, algorithm } = JSON.parse(dataBuffer.toString('utf8'));
    
    if (algorithm !== ALGORITHM) {
      throw new Error('Unsupported encryption algorithm');
    }
    
    const decipher = crypto.createDecipher(algorithm, encryptionKey, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    decipher.setAAD(Buffer.from('health-data', 'utf8'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt health data');
  }
};

/**
 * Generate hash for data integrity verification
 */
export const generateDataHash = (data) => {
  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify(data));
  return hash.digest('hex');
};

/**
 * Verify data integrity using hash
 */
export const verifyDataIntegrity = (data, expectedHash) => {
  const actualHash = generateDataHash(data);
  return actualHash === expectedHash;
};

/**
 * Encrypt file data (for medical images, documents)
 */
export const encryptFile = async (fileBuffer, encryptionKey) => {
  try {
    const iv = generateIV();
    const cipher = crypto.createCipher(ALGORITHM, encryptionKey, { authTagLength: TAG_LENGTH });
    
    const encrypted = Buffer.concat([
      cipher.update(fileBuffer),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Combine IV, auth tag, and encrypted file
    const result = Buffer.concat([
      iv,
      authTag,
      encrypted
    ]);
    
    return result;
  } catch (error) {
    console.error('File encryption error:', error);
    throw new Error('Failed to encrypt file');
  }
};

/**
 * Decrypt file data
 */
export const decryptFile = async (encryptedBuffer, encryptionKey) => {
  try {
    const iv = encryptedBuffer.slice(0, IV_LENGTH);
    const authTag = encryptedBuffer.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = encryptedBuffer.slice(IV_LENGTH + TAG_LENGTH);
    
    const decipher = crypto.createDecipher(ALGORITHM, encryptionKey, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
    
    return decrypted;
  } catch (error) {
    console.error('File decryption error:', error);
    throw new Error('Failed to decrypt file');
  }
};

/**
 * Generate secure hash for passwords
 */
export const hashPassword = async (password, saltRounds = 12) => {
  const bcrypt = await import('bcryptjs');
  return bcrypt.hash(password, saltRounds);
};

/**
 * Verify password against hash
 */
export const verifyPassword = async (password, hash) => {
  const bcrypt = await import('bcryptjs');
  return bcrypt.compare(password, hash);
};

/**
 * Generate cryptographically secure random string
 */
export const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Create digital signature for documents
 */
export const createDigitalSignature = (data, privateKey) => {
  try {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(JSON.stringify(data));
    return sign.sign(privateKey, 'hex');
  } catch (error) {
    console.error('Digital signature error:', error);
    throw new Error('Failed to create digital signature');
  }
};

/**
 * Verify digital signature
 */
export const verifyDigitalSignature = (data, signature, publicKey) => {
  try {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(JSON.stringify(data));
    return verify.verify(publicKey, signature, 'hex');
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
};

/**
 * Generate RSA key pair for digital signatures
 */
export const generateKeyPair = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  return { publicKey, privateKey };
};

/**
 * Encrypt data for blockchain storage (smaller payloads)
 */
export const encryptForBlockchain = (data, key) => {
  try {
    const compressed = JSON.stringify(data);
    const iv = generateIV();
    const cipher = crypto.createCipher('aes-256-cbc', key);
    
    let encrypted = cipher.update(compressed, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Blockchain encryption error:', error);
    throw new Error('Failed to encrypt for blockchain');
  }
};

/**
 * Decrypt data from blockchain
 */
export const decryptFromBlockchain = (encryptedData, key) => {
  try {
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Blockchain decryption error:', error);
    throw new Error('Failed to decrypt from blockchain');
  }
};

/**
 * Create tamper-evident seal for health records
 */
export const createTamperSeal = (record) => {
  const timestamp = Date.now();
  const recordHash = generateDataHash(record);
  const sealData = {
    timestamp,
    recordHash,
    version: record.version || 1
  };
  
  const seal = generateDataHash(sealData);
  return { seal, timestamp, recordHash };
};

/**
 * Verify tamper-evident seal
 */
export const verifyTamperSeal = (record, seal, timestamp, originalHash) => {
  const currentHash = generateDataHash(record);
  const sealData = {
    timestamp,
    recordHash: originalHash,
    version: record.version || 1
  };
  
  const expectedSeal = generateDataHash(sealData);
  const hashMatch = currentHash === originalHash;
  const sealMatch = seal === expectedSeal;
  
  return {
    isValid: hashMatch && sealMatch,
    currentHash,
    originalHash,
    hashMatch,
    sealMatch
  };
};

/**
 * Anonymize sensitive data for research
 */
export const anonymizeData = (data, fields = []) => {
  const anonymized = JSON.parse(JSON.stringify(data)); // Deep copy
  
  // Default fields to anonymize
  const defaultFields = [
    'email', 'firstName', 'lastName', 'phoneNumber', 
    'address', 'emergencyContact', 'socialSecurityNumber'
  ];
  
  const fieldsToAnonymize = fields.length > 0 ? fields : defaultFields;
  
  const anonymizeField = (obj, fieldPath) => {
    const keys = fieldPath.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (current[keys[i]]) {
        current = current[keys[i]];
      } else {
        return;
      }
    }
    
    const lastKey = keys[keys.length - 1];
    if (current[lastKey]) {
      current[lastKey] = '*'.repeat(8);
    }
  };
  
  fieldsToAnonymize.forEach(field => {
    anonymizeField(anonymized, field);
  });
  
  // Generate anonymous ID
  anonymized.anonymousId = crypto.createHash('sha256')
    .update(data._id ? data._id.toString() : JSON.stringify(data))
    .digest('hex').substring(0, 16);
  
  return anonymized;
};