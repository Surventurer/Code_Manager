const crypto = require('crypto');

// Server-side encryption using AES-256-GCM (much more secure than XOR)
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;

// Derive a secure key from password using PBKDF2
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

// Encrypt content with password
function encryptContent(text, password) {
    try {
        const salt = crypto.randomBytes(SALT_LENGTH);
        const iv = crypto.randomBytes(IV_LENGTH);
        const key = deriveKey(password, salt);
        
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        
        const tag = cipher.getAuthTag();
        
        // Combine salt + iv + tag + encrypted data
        const combined = Buffer.concat([
            salt,
            iv,
            tag,
            Buffer.from(encrypted, 'base64')
        ]);
        
        return combined.toString('base64');
    } catch (e) {
        console.error('Encryption error:', e);
        return null;
    }
}

// Decrypt content with password
function decryptContent(encryptedText, password) {
    try {
        const combined = Buffer.from(encryptedText, 'base64');
        
        // Extract components
        const salt = combined.subarray(0, SALT_LENGTH);
        const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const tag = combined.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
        const encrypted = combined.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
        
        const key = deriveKey(password, salt);
        
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    } catch (e) {
        // Decryption failed (wrong password or corrupted data)
        return null;
    }
}

exports.handler = async function(event, context) {
    context.callbackWaitsForEmptyEventLoop = false;
    
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        const { action, content, password } = JSON.parse(event.body);
        
        if (!action || !password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Missing required fields: action, password' })
            };
        }

        if (action === 'encrypt') {
            if (!content) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Missing content to encrypt' })
                };
            }
            
            const encrypted = encryptContent(content, password);
            
            if (encrypted === null) {
                return {
                    statusCode: 500,
                    headers,
                    body: JSON.stringify({ error: 'Encryption failed' })
                };
            }
            
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ success: true, encrypted })
            };
        } 
        else if (action === 'decrypt') {
            if (!content) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Missing content to decrypt' })
                };
            }
            
            const decrypted = decryptContent(content, password);
            
            if (decrypted === null) {
                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({ error: 'Decryption failed - invalid password or corrupted data' })
                };
            }
            
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ success: true, decrypted })
            };
        }
        else {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Invalid action. Use "encrypt" or "decrypt"' })
            };
        }
    } catch (error) {
        console.error('Crypto API error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Server error', details: error.message })
        };
    }
};

// Export functions for use in other modules
module.exports.encryptContent = encryptContent;
module.exports.decryptContent = decryptContent;
