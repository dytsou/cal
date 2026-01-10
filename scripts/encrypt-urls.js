#!/usr/bin/env node

/**
 * Helper script to encrypt calendar URLs
 * Usage: node encrypt-urls.js <url1> <url2> ...
 * Or set CALENDAR_URL in .env and run: node encrypt-urls.js
 */

const fs = require('fs');
const path = require('path');
const Fernet = require('fernet');

// Read .env file
const envPath = path.join(__dirname, '..', '.env');
let encryptionKey = '';
let calendarUrls = [];

if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf-8');
  const envLines = envContent.split('\n');

  for (const line of envLines) {
    if (line.startsWith('ENCRYPTION_KEY=')) {
      encryptionKey = line.substring('ENCRYPTION_KEY='.length).trim();
    } else if (line.startsWith('CALENDAR_URL=')) {
      const value = line.substring('CALENDAR_URL='.length).trim();
      calendarUrls = value
        .split(',')
        .map(s => s.trim())
        .filter(s => s);
    }
  }
}

// Get URLs from command line arguments if provided
const args = process.argv.slice(2);
if (args.length > 0) {
  calendarUrls = args;
}

if (calendarUrls.length === 0) {
  console.error('Error: No calendar URLs provided');
  console.error('Usage: node encrypt-urls.js <url1> <url2> ...');
  console.error('Or set CALENDAR_URL in .env file');
  process.exit(1);
}

if (!encryptionKey) {
  console.error('Error: ENCRYPTION_KEY not found in .env file');
  console.error('Please set ENCRYPTION_KEY in .env file');
  process.exit(1);
}

try {
  const secret = new Fernet.Secret(encryptionKey);
  const token = new Fernet.Token({
    secret: secret,
    ttl: 0, // No expiration
  });

  const encryptedUrls = calendarUrls.map(url => {
    return token.encode(url);
  });

  console.log('\n📋 Encrypted URLs:\n');
  console.log('CALENDAR_URL_ENCRYPTED=' + encryptedUrls.join(','));
  console.log('\nOr individually:');
  encryptedUrls.forEach((encrypted, index) => {
    console.log(`# URL ${index + 1}: ${encrypted}`);
  });
  console.log('\n✅ Copy the encrypted URLs to your .env file\n');
} catch (error) {
  console.error('Error encrypting URLs:', error.message);
  process.exit(1);
}
