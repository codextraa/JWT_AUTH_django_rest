import crypto from 'crypto';


const SECRET_KEY = process.env.AUTH_SECRET_KEY;
const ALGORITHM = 'aes-256-gcm';

export function validateSessionData(data) {
  // Check that the data is an object
  if (typeof data !== 'object' || data === null) {
    return null;
  };

  // Validate user_id (should be a non-empty string or number)
  if (typeof data.user_id !== 'string' && typeof data.user_id !== 'number') {
    return null;
  };
  data.user_id = String(data.user_id).trim(); // Convert to string and remove extra spaces

  // Validate user_role (should be a non-empty string)
  if (typeof data.user_role !== 'string' || data.user_role.trim() === '') {
    return null;
  };
  data.user_role = data.user_role.trim();

  // Validate access_token (should be a non-empty string)
  if (typeof data.access_token !== 'string' || data.access_token.trim() === '') {
    return null;
  };
  data.access_token = data.access_token.trim();

  // Validate refresh_token (should be a non-empty string)
  if (typeof data.refresh_token !== 'string' || data.refresh_token.trim() === '') {
    return null;
  };
  data.refresh_token = data.refresh_token.trim();

  // Return sanitized and valid data
  return {
    user_id: data.user_id,
    user_role: data.user_role,
    access_token: data.access_token,
    refresh_token: data.refresh_token,
  };
};

/**
 * Encrypts the session data
 * @param {Object} data - The session data to encrypt
 * @returns {string} - Encrypted data in base64 format
 */
export function encrypt(data) {
  const iv = crypto.randomBytes(16); // 16 bytes IV for AES-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY), iv);

  const jsonData = JSON.stringify(data);
  let encrypted = cipher.update(jsonData, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const authTag = cipher.getAuthTag(); // Get authentication tag

  return `${iv.toString('base64')}.${encrypted}.${authTag.toString('base64')}`;
};

/**
 * Decrypts the encrypted session data
 * @param {string} encryptedData - The encrypted data in base64 format
 * @returns {Object} - The decrypted session data
 */
export function decrypt(encryptedData) {
  const [ivBase64, encryptedBase64, authTagBase64] = encryptedData.split('.');
  if (!ivBase64 || !encryptedBase64 || !authTagBase64) {
    throw new Error('Invalid encrypted data format');
  };

  const iv = Buffer.from(ivBase64, 'base64');
  const encrypted = Buffer.from(encryptedBase64, 'base64');
  const authTag = Buffer.from(authTagBase64, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(SECRET_KEY), iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
};