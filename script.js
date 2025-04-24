// script.js
require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 bytes
const ENCRYPTION_IV = process.env.ENCRYPTION_IV;   // Must be 16 bytes

const encrypt = (payload) => {
  // Create JWT token from payload
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  // Encrypt the token
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), ENCRYPTION_IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

const decrypt = (encryptedToken) => {
  try {
    // Decrypt the token
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), ENCRYPTION_IV);
    let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Verify and decode JWT token
    return jwt.verify(decrypted, JWT_SECRET);
  } catch (err) {
    console.error("Decryption or verification failed:", err.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt
};
