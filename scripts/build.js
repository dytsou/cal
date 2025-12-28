#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const Fernet = require('fernet');
const { execSync } = require('child_process');

// Read template HTML
const templatePath = path.join(__dirname, '..', 'index.html.template');
if (!fs.existsSync(templatePath)) {
  console.error('Error: index.html.template not found');
  process.exit(1);
}

let html = fs.readFileSync(templatePath, 'utf-8');

// Always check for placeholders that need replacement
const hasPlaceholders = html.includes('{{CALENDAR_SOURCES}}') || html.includes('{{CALENDAR_URLS}}');
const needsWorkerUrl = html.includes('{{WORKER_URL}}');
let workerUrl = '';

// Always read .env for WORKER_URL if needed
if (needsWorkerUrl || hasPlaceholders) {
  const envPath = path.join(__dirname, '..', '.env');
  if (hasPlaceholders && !fs.existsSync(envPath)) {
    console.error('Error: .env file not found (required for placeholders)');
    process.exit(1);
  }
  
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf-8');
    const envLines = envContent.split('\n');

    // Parse environment variables
    let calendarSources = [];
    let calendarUrls = [];

    for (const line of envLines) {
      if (line.startsWith('CALENDAR_SOURCES=')) {
        const value = line.substring('CALENDAR_SOURCES='.length).trim();
        calendarSources = value
          .split(',')
          .map(s => s.trim())
          .filter(s => s);
      } else if (line.startsWith('CALENDAR_URL=')) {
        const value = line.substring('CALENDAR_URL='.length).trim();
        // Support both single URL and comma-separated multiple URLs
        const urls = value
          .split(',')
          .map(s => s.trim())
          .filter(s => s);
        calendarUrls.push(...urls);
      } else if (line.startsWith('WORKER_URL=')) {
        workerUrl = line.substring('WORKER_URL='.length).trim();
      }
    }
  }
}

if (hasPlaceholders) {

  // Replace CALENDAR_SOURCES placeholder
  if (html.includes('{{CALENDAR_SOURCES}}')) {
    if (calendarSources.length === 0) {
      console.error('Error: No calendar sources found in .env file');
      process.exit(1);
    }

    const calendarArrayCode =
      '[\n' + calendarSources.map(cal => `            "${cal}"`).join(',\n') + '\n        ]';

    html = html.replace('{{CALENDAR_SOURCES}}', calendarArrayCode);
    console.log(
      `✓ Replaced {{CALENDAR_SOURCES}} with ${calendarSources.length} calendar source(s)`
    );
  }

  // Replace CALENDAR_URLS placeholder
  if (html.includes('{{CALENDAR_URLS}}')) {
    if (calendarUrls.length === 0) {
      console.error('Error: CALENDAR_URL not found in .env file');
      process.exit(1);
    }

    // Get encryption settings from .env
    let encryptionMethod = '';
    let encryptionKey = '';

    for (const line of envLines) {
      if (line.startsWith('ENCRYPTION_METHOD=')) {
        encryptionMethod = line.substring('ENCRYPTION_METHOD='.length).trim().toLowerCase();
      } else if (line.startsWith('ENCRYPTION_KEY=')) {
        encryptionKey = line.substring('ENCRYPTION_KEY='.length).trim();
      }
    }

    let calendarUrlsArrayCode;

    if (encryptionMethod === 'fernet' && encryptionKey) {
      // Use Fernet encryption
      try {
        const secret = new Fernet.Secret(encryptionKey);
        const token = new Fernet.Token({
          secret: secret,
          ttl: 0, // No expiration
        });

        const encryptedUrls = calendarUrls.map(url => {
          const encrypted = token.encode(url);
          // Format as fernet:// protocol URL
          return `fernet://${encrypted}`;
        });

        calendarUrlsArrayCode =
          '[\n' + encryptedUrls.map(url => `            "${url}"`).join(',\n') + '\n        ]';

        html = html.replace('{{ENCRYPTION_METHOD}}', 'fernet');
        html = html.replace('{{ENCRYPTION_KEY}}', encryptionKey);
        console.log(
          `✓ Replaced {{CALENDAR_URLS}} with ${encryptedUrls.length} Fernet-encrypted calendar URL(s)`
        );
        
        // Output encrypted URLs for copying to .env
        console.log('\n📋 Encrypted URLs (for .env file):');
        console.log('CALENDAR_URL_ENCRYPTED=' + encryptedUrls.join(','));
        console.log('\nOr individually:');
        encryptedUrls.forEach((encrypted, index) => {
          console.log(`# URL ${index + 1}: ${encrypted}`);
        });
      } catch (error) {
        console.error('Error encrypting with Fernet:', error.message);
        process.exit(1);
      }
    } else {
      // No encryption - plain URLs
      calendarUrlsArrayCode =
        '[\n' + calendarUrls.map(url => `            "${url}"`).join(',\n') + '\n        ]';
      html = html.replace('{{ENCRYPTION_METHOD}}', 'none');
      html = html.replace('{{ENCRYPTION_KEY}}', '');
      html = html.replace('{{WORKER_URL}}', 'https://open-web-calendar.hosted.quelltext.eu/calendar.html');
      console.log(
        `✓ Replaced {{CALENDAR_URLS}} with ${calendarUrls.length} calendar URL(s) (no encryption)`
      );
    }

    html = html.replace('{{CALENDAR_URLS}}', calendarUrlsArrayCode);
    
    // Remove encryption key placeholder (not needed with Worker)
    html = html.replace('{{ENCRYPTION_KEY}}', '');
    
    // Clean up fernet-bundle.js if it exists (no longer needed with Worker)
    const bundleFile = path.join(__dirname, '..', 'fernet-bundle.js');
    if (fs.existsSync(bundleFile)) {
      fs.unlinkSync(bundleFile);
      console.log('✓ Removed fernet-bundle.js (using Cloudflare Worker instead)');
    }
  }
}

// Always replace WORKER_URL placeholder if it exists (regardless of other placeholders)
if (html.includes('{{WORKER_URL}}')) {
  const finalWorkerUrl = workerUrl || process.env.WORKER_URL || 'https://open-web-calendar.hosted.quelltext.eu';
  html = html.replace('{{WORKER_URL}}', finalWorkerUrl);
  if (finalWorkerUrl !== 'https://open-web-calendar.hosted.quelltext.eu') {
    console.log(`✓ Using Cloudflare Worker: ${finalWorkerUrl}`);
  } else {
    console.log('✓ Replaced {{WORKER_URL}} with default open-web-calendar URL');
  }
}

// Get current year for placeholders
const currentYear = new Date().getFullYear().toString();

// Replace {{YEAR}} placeholder in HTML template
if (html.includes('{{YEAR}}')) {
  html = html.replace(/\{\{YEAR\}\}/g, currentYear);
}

// Write built HTML
const outputPath = path.join(__dirname, '..', 'index.html');
fs.writeFileSync(outputPath, html, 'utf-8');

// Update LICENSE file with current year
const licensePath = path.join(__dirname, '..', 'LICENSE');
if (fs.existsSync(licensePath)) {
  let licenseContent = fs.readFileSync(licensePath, 'utf-8');
  if (licenseContent.includes('{{YEAR}}')) {
    licenseContent = licenseContent.replace(/\{\{YEAR\}\}/g, currentYear);
    fs.writeFileSync(licensePath, licenseContent, 'utf-8');
    console.log(`✓ Updated LICENSE with year ${currentYear}`);
  }
}
