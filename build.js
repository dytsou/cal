#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Read template HTML
const templatePath = path.join(__dirname, 'index.html.template');
if (!fs.existsSync(templatePath)) {
  console.error('Error: index.html.template not found');
  process.exit(1);
}

let html = fs.readFileSync(templatePath, 'utf-8');

// Read .env file if template has placeholders
const hasPlaceholders = html.includes('{{CALENDAR_SOURCES}}') || html.includes('{{CALENDAR_URLS}}');
if (hasPlaceholders) {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) {
    console.error('Error: .env file not found (required for placeholders)');
    process.exit(1);
  }

  const envContent = fs.readFileSync(envPath, 'utf-8');
  const envLines = envContent.split('\n');

  // Parse environment variables
  let calendarSources = [];
  let calendarUrls = [];

  for (const line of envLines) {
    if (line.startsWith('CALENDAR_SOURCES=')) {
      const value = line.substring('CALENDAR_SOURCES='.length).trim();
      calendarSources = value.split(',').map(s => s.trim()).filter(s => s);
    } else if (line.startsWith('CALENDAR_URL=')) {
      const value = line.substring('CALENDAR_URL='.length).trim();
      // Support both single URL and comma-separated multiple URLs
      const urls = value.split(',').map(s => s.trim()).filter(s => s);
      calendarUrls.push(...urls);
    }
  }

  // Replace CALENDAR_SOURCES placeholder
  if (html.includes('{{CALENDAR_SOURCES}}')) {
    if (calendarSources.length === 0) {
      console.error('Error: No calendar sources found in .env file');
      process.exit(1);
    }

    const calendarArrayCode = '[\n' + calendarSources
      .map(cal => `            "${cal}"`)
      .join(',\n') + '\n        ]';

    html = html.replace('{{CALENDAR_SOURCES}}', calendarArrayCode);
    console.log(`✓ Replaced {{CALENDAR_SOURCES}} with ${calendarSources.length} calendar source(s)`);
  }

  // Replace CALENDAR_URLS placeholder
  if (html.includes('{{CALENDAR_URLS}}')) {
    if (calendarUrls.length === 0) {
      console.error('Error: CALENDAR_URL not found in .env file');
      process.exit(1);
    }

    const calendarUrlsArrayCode = '[\n' + calendarUrls
      .map(url => `            "${url}"`)
      .join(',\n') + '\n        ]';

    html = html.replace('{{CALENDAR_URLS}}', calendarUrlsArrayCode);
    console.log(`✓ Replaced {{CALENDAR_URLS}} with ${calendarUrls.length} calendar URL(s)`);
  }
} else {
  console.log('✓ Built index.html from template (no placeholders to replace)');
}

// Write built HTML
const outputPath = path.join(__dirname, 'index.html');
fs.writeFileSync(outputPath, html, 'utf-8');

