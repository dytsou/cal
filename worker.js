/**
 * Cloudflare Worker to decrypt fernet:// URLs and proxy to open-web-calendar
 * 
 * This worker:
 * 1. Reads CALENDAR_URL from Cloudflare Worker secrets (comma-separated)
 * 2. Decrypts fernet:// URLs using Fernet encryption (ENCRYPTION_METHOD is hardcoded to 'fernet')
 * 3. Forwards the request to open-web-calendar with decrypted URLs
 * 4. Returns the calendar HTML
 * 
 * Configuration:
 * - ENCRYPTION_METHOD: Hardcoded to 'fernet' (not configurable)
 * - ENCRYPTION_KEY: Required Cloudflare Worker secret (for decrypting fernet:// URLs)
 * - CALENDAR_URL: Required Cloudflare Worker secret (comma-separated, can be plain or fernet:// encrypted)
 * 
 * Usage:
 * 1. Set CALENDAR_URL secret: wrangler secret put CALENDAR_URL
 * 2. Set ENCRYPTION_KEY secret: wrangler secret put ENCRYPTION_KEY
 * 3. Deploy: wrangler deploy
 */

// Import Fernet library - we'll need to bundle this for Workers
// For now, we'll implement a basic Fernet decoder using Web Crypto API

/**
 * Decode base64url string
 */
function base64UrlDecode(str) {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }
  // Decode
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decode Fernet token
 * Fernet token format: Version (1 byte) + Timestamp (8 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
 */
async function decryptFernetToken(token, secretKey) {
  try {
    // Decode the token
    const tokenBytes = base64UrlDecode(token);
    
    if (tokenBytes.length < 57) { // Minimum: 1 + 8 + 16 + 0 + 32 = 57 bytes
      throw new Error('Invalid Fernet token: too short');
    }
    
    // Extract components
    const version = tokenBytes[0];
    if (version !== 0x80) {
      throw new Error('Invalid Fernet token: unsupported version');
    }
    
    const timestamp = tokenBytes.slice(1, 9);
    const iv = tokenBytes.slice(9, 25);
    const hmac = tokenBytes.slice(-32);
    const ciphertext = tokenBytes.slice(25, -32);
    
    // Derive signing key and encryption key from secret
    // Fernet secret is base64url-encoded 32-byte key
    // The library splits it directly: first 16 bytes = signing key, last 16 bytes = encryption key
    // NO SHA256 hashing is used!
    let secretBytes;
    try {
      secretBytes = base64UrlDecode(secretKey);
      if (secretBytes.length !== 32) {
        throw new Error(`Invalid secret key length: ${secretBytes.length}, expected 32`);
      }
    } catch (error) {
      throw new Error(`Failed to decode secret key: ${error.message}`);
    }
    
    // Fernet splits the 32-byte secret directly:
    // Signing key: first 16 bytes (128 bits)
    // Encryption key: last 16 bytes (128 bits)
    const signingKey = secretBytes.slice(0, 16);
    const encryptionKey = secretBytes.slice(16, 32);
    
    // Verify HMAC
    // HMAC message is: version (1 byte) + timestamp (8 bytes) + IV (16 bytes) + ciphertext
    const message = tokenBytes.slice(0, -32);
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      signingKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
    
    const computedHmac = await crypto.subtle.sign('HMAC', hmacKey, message);
    const computedHmacBytes = new Uint8Array(computedHmac);
    
    // Constant-time comparison
    let hmacValid = true;
    if (computedHmacBytes.length !== hmac.length) {
      hmacValid = false;
    } else {
      for (let i = 0; i < 32; i++) {
        if (computedHmacBytes[i] !== hmac[i]) {
          hmacValid = false;
        }
      }
    }
    
    if (!hmacValid) {
      throw new Error('Invalid Fernet token: HMAC verification failed');
    }
    
    // Decrypt using AES-128-CBC
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: iv },
      cryptoKey,
      ciphertext
    );
    
    // Decode the decrypted message (PKCS7 padding will be removed automatically)
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    throw new Error(`Fernet decryption failed: ${error.message}`);
  }
}

/**
 * Decrypt a fernet:// URL
 */
async function decryptFernetUrl(fernetUrl, secretKey) {
  // Remove fernet:// prefix
  const token = fernetUrl.startsWith('fernet://') 
    ? fernetUrl.substring(9) 
    : fernetUrl;
  
  return await decryptFernetToken(token, secretKey);
}

/**
 * Inject console filtering script into HTML to block calendar info logs
 */
function injectConsoleFilter(html) {
  const consoleFilterScript = `
<script>
(function() {
  const originalLog = console.log;
  const originalInfo = console.info;
  
  function containsCalendarInfo(args) {
    const message = args.map(arg => {
      if (typeof arg === 'string') {
        return arg;
      } else if (arg && typeof arg === 'object') {
        try {
          return JSON.stringify(arg);
        } catch (e) {
          return String(arg);
        }
      }
      return String(arg);
    }).join(' ');
    
    if (message.includes('Calendar Info:') || 
        message.includes('calendars:') ||
        message.includes('calendar_index:') ||
        message.includes('url_index:')) {
      return true;
    }
    
    for (const arg of args) {
      if (arg && typeof arg === 'object') {
        const keys = Object.keys(arg);
        if (keys.includes('calendars') || 
            keys.includes('calendar_index') ||
            keys.includes('url_index') ||
            (arg.calendars && Array.isArray(arg.calendars))) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  console.log = function(...args) {
    if (containsCalendarInfo(args)) {
      return; // Don't log calendar info
    }
    originalLog.apply(console, args);
  };
  
  console.info = function(...args) {
    if (containsCalendarInfo(args)) {
      return; // Don't log calendar info
    }
    originalInfo.apply(console, args);
  };
})();
</script>`;
  
  // Inject the script right after <head> or at the beginning of <body>
  if (html.includes('</head>')) {
    return html.replace('</head>', consoleFilterScript + '</head>');
  } else if (html.includes('<body')) {
    const bodyMatch = html.match(/<body[^>]*>/);
    if (bodyMatch) {
      return html.replace(bodyMatch[0], bodyMatch[0] + consoleFilterScript);
    }
  }
  
  // Fallback: inject at the very beginning
  return consoleFilterScript + html;
}

/**
 * Normalize date to ISO string for comparison
 */
function normalizeDate(dateValue) {
  if (!dateValue) return null;
  if (typeof dateValue === 'string') {
    // Parse and return ISO string
    const date = new Date(dateValue);
    return isNaN(date.getTime()) ? null : date.toISOString();
  }
  if (dateValue instanceof Date) {
    return dateValue.toISOString();
  }
  // Try to convert to date
  const date = new Date(dateValue);
  return isNaN(date.getTime()) ? null : date.toISOString();
}

/**
 * Extract event time fields (handles various field name formats)
 */
function getEventTime(event, field) {
  // Try common field name variations (including iCal and calendar.js formats)
  const variations = {
    start: ['start', 'startDate', 'start_time', 'startTime', 'dtstart', 'start_date', 'dateStart', 'date_start'],
    end: ['end', 'endDate', 'end_time', 'endTime', 'dtend', 'end_date', 'dateEnd', 'date_end']
  };
  
  const fieldNames = variations[field] || [field];
  for (const name of fieldNames) {
    if (event[name] !== undefined && event[name] !== null) {
      return event[name];
    }
  }
  return null;
}

/**
 * Extract event title (handles various field name formats)
 */
function getEventTitle(event) {
  return event.title || event.summary || event.name || '';
}

/**
 * Extract event description (handles various field name formats)
 */
function getEventDescription(event) {
  return event.description || event.desc || '';
}

/**
 * Extract calendar identifier (handles various field name formats)
 */
function getCalendarId(event) {
  return event.calendar || event.calendarId || event.calendar_id || event.source || 'default';
}

/**
 * Merge consecutive events within the same calendar
 * Events are consecutive if event1.end === event2.start (exact match)
 */
function mergeConsecutiveEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return events;
  }
  
  // Group events by calendar identifier
  const eventsByCalendar = {};
  for (const event of events) {
    const calendarId = getCalendarId(event);
    if (!eventsByCalendar[calendarId]) {
      eventsByCalendar[calendarId] = [];
    }
    eventsByCalendar[calendarId].push(event);
  }
  
  const mergedEvents = [];
  
  // Process each calendar group separately
  for (const calendarId in eventsByCalendar) {
    const calendarEvents = eventsByCalendar[calendarId];
    
    // Sort events by start time
    calendarEvents.sort((a, b) => {
      const startA = getEventTime(a, 'start');
      const startB = getEventTime(b, 'start');
      if (!startA || !startB) return 0;
      return new Date(startA) - new Date(startB);
    });
    
    // Merge consecutive events
    let currentMerge = null;
    
    for (let i = 0; i < calendarEvents.length; i++) {
      const event = calendarEvents[i];
      const startTime = getEventTime(event, 'start');
      const endTime = getEventTime(event, 'end');
      
      if (!startTime || !endTime) {
        // If event is missing time info, add as-is
        if (currentMerge) {
          mergedEvents.push(currentMerge);
          currentMerge = null;
        }
        mergedEvents.push(event);
        continue;
      }
      
      if (currentMerge === null) {
        // Start a new merge group
        currentMerge = { ...event };
      } else {
        // Check if this event is consecutive to the current merge
        const currentEndTime = getEventTime(currentMerge, 'end');
        // Normalize dates for comparison (handle different date formats)
        const normalizedEndTime = normalizeDate(currentEndTime);
        const normalizedStartTime = normalizeDate(startTime);
        
        if (normalizedEndTime && normalizedStartTime && normalizedEndTime === normalizedStartTime) {
          // Merge: combine titles and extend end time
          const currentTitle = getEventTitle(currentMerge);
          const eventTitle = getEventTitle(event);
          const combinedTitle = currentTitle && eventTitle 
            ? `${currentTitle} + ${eventTitle}`
            : currentTitle || eventTitle;
          
          // Update title field (try common variations)
          if (currentMerge.title !== undefined) currentMerge.title = combinedTitle;
          if (currentMerge.summary !== undefined) currentMerge.summary = combinedTitle;
          if (currentMerge.name !== undefined) currentMerge.name = combinedTitle;
          if (!currentMerge.title && !currentMerge.summary && !currentMerge.name) {
            currentMerge.title = combinedTitle;
          }
          
          // Combine descriptions
          const currentDesc = getEventDescription(currentMerge);
          const eventDesc = getEventDescription(event);
          if (currentDesc || eventDesc) {
            const combinedDesc = currentDesc && eventDesc
              ? `${currentDesc}\n\n${eventDesc}`
              : currentDesc || eventDesc;
            
            if (currentMerge.description !== undefined) currentMerge.description = combinedDesc;
            if (currentMerge.desc !== undefined) currentMerge.desc = combinedDesc;
            if (!currentMerge.description && !currentMerge.desc) {
              currentMerge.description = combinedDesc;
            }
          }
          
          // Update end time - preserve original field name format
          const originalEndField = getEventTime(currentMerge, 'end') !== null 
            ? (currentMerge.end !== undefined ? 'end' :
               currentMerge.endDate !== undefined ? 'endDate' :
               currentMerge.end_time !== undefined ? 'end_time' :
               currentMerge.endTime !== undefined ? 'endTime' :
               currentMerge.dtend !== undefined ? 'dtend' :
               currentMerge.end_date !== undefined ? 'end_date' :
               currentMerge.dateEnd !== undefined ? 'dateEnd' :
               currentMerge.date_end !== undefined ? 'date_end' : 'end')
            : 'end';
          
          // Update all possible end time fields to ensure compatibility
          if (currentMerge.end !== undefined) currentMerge.end = endTime;
          if (currentMerge.endDate !== undefined) currentMerge.endDate = endTime;
          if (currentMerge.end_time !== undefined) currentMerge.end_time = endTime;
          if (currentMerge.endTime !== undefined) currentMerge.endTime = endTime;
          if (currentMerge.dtend !== undefined) currentMerge.dtend = endTime;
          if (currentMerge.end_date !== undefined) currentMerge.end_date = endTime;
          if (currentMerge.dateEnd !== undefined) currentMerge.dateEnd = endTime;
          if (currentMerge.date_end !== undefined) currentMerge.date_end = endTime;
          if (!currentMerge.end && !currentMerge.endDate && !currentMerge.end_time && 
              !currentMerge.endTime && !currentMerge.dtend && !currentMerge.end_date &&
              !currentMerge.dateEnd && !currentMerge.date_end) {
            currentMerge.end = endTime;
          }
        } else {
          // Not consecutive, save current merge and start new one
          mergedEvents.push(currentMerge);
          currentMerge = { ...event };
        }
      }
    }
    
    // Add the last merge group if any
    if (currentMerge !== null) {
      mergedEvents.push(currentMerge);
    }
  }
  
  return mergedEvents;
}

/**
 * Process calendar events JSON and merge consecutive events
 */
function processCalendarEventsJson(jsonData) {
  if (Array.isArray(jsonData)) {
    // Format: [{event1}, {event2}, ...]
    return mergeConsecutiveEvents(jsonData);
  } else if (jsonData && typeof jsonData === 'object') {
    // Check for nested structures
    if (Array.isArray(jsonData.events)) {
      // Format: {events: [...], ...}
      return {
        ...jsonData,
        events: mergeConsecutiveEvents(jsonData.events)
      };
    } else if (Array.isArray(jsonData.calendars)) {
      // Format: {calendars: [{events: [...]}, ...], ...}
      return {
        ...jsonData,
        calendars: jsonData.calendars.map(calendar => {
          if (Array.isArray(calendar.events)) {
            return {
              ...calendar,
              events: mergeConsecutiveEvents(calendar.events)
            };
          }
          return calendar;
        })
      };
    } else if (Array.isArray(jsonData.data)) {
      // Format: {data: [...], ...}
      return {
        ...jsonData,
        data: mergeConsecutiveEvents(jsonData.data)
      };
    } else if (Array.isArray(jsonData.items)) {
      // Format: {items: [...], ...}
      return {
        ...jsonData,
        items: mergeConsecutiveEvents(jsonData.items)
      };
    }
    // Unknown structure, try to find any array of events
    for (const key in jsonData) {
      if (Array.isArray(jsonData[key]) && jsonData[key].length > 0) {
        // Check if it looks like events (has time fields)
        const firstItem = jsonData[key][0];
        if (firstItem && typeof firstItem === 'object') {
          const hasTimeField = getEventTime(firstItem, 'start') !== null || 
                              getEventTime(firstItem, 'end') !== null;
          if (hasTimeField) {
            return {
              ...jsonData,
              [key]: mergeConsecutiveEvents(jsonData[key])
            };
          }
        }
      }
    }
  }
  
  // Unknown format, return as-is
  return jsonData;
}

/**
 * Sanitize response body to hide calendar URLs in error messages
 * Only sanitizes HTML and JSON responses to avoid breaking JavaScript code
 */
async function sanitizeResponse(response, pathname) {
  const contentType = response.headers.get('content-type') || '';
  
  // Only sanitize HTML and JSON responses (error messages)
  // Skip JavaScript files to avoid breaking code
  if (!contentType.includes('text/html') && 
      !contentType.includes('application/json')) {
    // For non-HTML/JSON responses (including JavaScript), just add CORS header and return
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  }
  
  const body = await response.text();
  
  let sanitizedBody = body;
  
  // For JSON responses, check if it's a calendar events endpoint
  if (contentType.includes('application/json')) {
    // Check for calendar events endpoints - open-web-calendar uses /calendar.json
    // Also check for any .json file that might contain calendar events
    const isCalendarEventsEndpoint = pathname === '/calendar.events.json' ||
                                     pathname === '/calendar.json' ||
                                     pathname.endsWith('.events.json') ||
                                     pathname.endsWith('.json');
    
    if (isCalendarEventsEndpoint) {
      try {
        const jsonData = JSON.parse(body);
        const processedData = processCalendarEventsJson(jsonData);
        sanitizedBody = JSON.stringify(processedData);
      } catch (error) {
        // If JSON parsing fails, continue with original body
        console.error('Failed to parse calendar events JSON:', error);
      }
    }
  }
  
  // For HTML responses, inject console filtering
  if (contentType.includes('text/html')) {
    sanitizedBody = injectConsoleFilter(sanitizedBody);
  }
  
  // Patterns to detect and sanitize calendar URLs
  // Only match complete URLs, not code fragments
  const urlPatterns = [
    /https?:\/\/[^\s"']+\.ics/gi,
    /https?:\/\/calendar\.google\.com\/calendar\/ical\/[^\s"']+/gi,
    // Only match %40 when it's part of a URL (followed by domain-like pattern)
    /%40[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[^\s"']*/gi,
  ];
  
  urlPatterns.forEach(pattern => {
    sanitizedBody = sanitizedBody.replace(pattern, '[Calendar URL hidden]');
  });
  
  const responseHeaders = new Headers(response.headers);
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  
  return new Response(sanitizedBody, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      
      // ENCRYPTION_METHOD is hardcoded to 'fernet'
      const ENCRYPTION_METHOD = 'fernet';
      
      const encryptionKey = env.ENCRYPTION_KEY;
      const calendarUrlSecret = env.CALENDAR_URL; // Read from Cloudflare Worker secret
      
      if (!calendarUrlSecret) {
        return new Response('CALENDAR_URL not configured in Cloudflare Worker secrets', { 
          status: 500,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
      
      // Parse calendar URLs from secret (comma-separated, can be plain or fernet://)
      const calendarUrlsFromSecret = calendarUrlSecret
        .split(',')
        .map(s => s.trim())
        .filter(s => s);
      
      // Use calendar URLs from secret (they may be fernet:// encrypted or plain)
      const calendarUrls = calendarUrlsFromSecret;
      
      // Check if any of the URLs are fernet:// encrypted
      const hasFernetUrls = calendarUrls.some(url => url.startsWith('fernet://'));
      
      // If we have fernet:// URLs, we need ENCRYPTION_KEY
      if (hasFernetUrls && !encryptionKey) {
        return new Response('ENCRYPTION_KEY not configured (required for fernet:// URLs)', { 
          status: 500,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
      
      // Get the pathname to determine request type
      const pathname = url.pathname;
      
      // Check if this is the main calendar page request
      const isMainCalendarPage = pathname === '/' || 
                                  pathname === '/calendar.html' || 
                                  pathname.endsWith('/calendar.html') ||
                                  pathname === '';
      
      // Check if this is an API endpoint that needs calendar URLs
      // This includes /srcdoc, /calendar.events.json, /calendar.json, etc.
      const isApiEndpoint = pathname === '/srcdoc' || 
                            pathname.startsWith('/srcdoc') ||
                            pathname === '/calendar.events.json' ||
                            pathname === '/calendar.json' ||
                            pathname.endsWith('.events.json') ||
                            pathname.endsWith('.json');
      
      // For API endpoints like /srcdoc, always use calendar URLs from secret
      if (isApiEndpoint) {
        // Build the target URL
        const targetUrl = new URL(`https://open-web-calendar.hosted.quelltext.eu${pathname}`);
        
        // Copy all query parameters except 'url'
        for (const [key, value] of url.searchParams.entries()) {
          if (key !== 'url') {
            targetUrl.searchParams.append(key, value);
          }
        }
        
        // Decrypt and add calendar URLs from secret
        // ENCRYPTION_METHOD is hardcoded to 'fernet'
        const decryptedUrls = [];
        for (const urlParam of calendarUrls) {
          if (urlParam.startsWith('fernet://')) {
            if (!encryptionKey) {
              return new Response('ENCRYPTION_KEY not configured (required for fernet:// URLs)', { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
              });
            }
            try {
              const decrypted = await decryptFernetUrl(urlParam, encryptionKey);
              decryptedUrls.push(decrypted);
            } catch (error) {
              return new Response(`Failed to decrypt calendar URL: ${error.message}`, { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
              });
            }
          } else {
            // Plain URL, use as-is
            decryptedUrls.push(urlParam);
          }
        }
        
        // Add decrypted URLs
        for (const decryptedUrl of decryptedUrls) {
          targetUrl.searchParams.append('url', decryptedUrl);
        }
        
        // Forward all headers from the original request
        const requestHeaders = new Headers();
        request.headers.forEach((value, key) => {
          if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'cf-ray' && key.toLowerCase() !== 'cf-connecting-ip') {
            requestHeaders.set(key, value);
          }
        });
        
        const response = await fetch(targetUrl.toString(), {
          headers: requestHeaders,
        });
        
        // Sanitize response to hide calendar URLs in error messages
        // Pass pathname for calendar events processing
        return await sanitizeResponse(response, pathname);
      }
      
      // Handle main calendar page requests - always add calendar URLs from secret
      if (isMainCalendarPage) {
        // Decrypt calendar URLs from secret
        // ENCRYPTION_METHOD is hardcoded to 'fernet'
        const decryptedUrls = [];
        for (const urlParam of calendarUrls) {
          if (urlParam.startsWith('fernet://')) {
            if (!encryptionKey) {
              return new Response('ENCRYPTION_KEY not configured (required for fernet:// URLs)', { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
              });
            }
            try {
              const decrypted = await decryptFernetUrl(urlParam, encryptionKey);
              decryptedUrls.push(decrypted);
            } catch (error) {
              return new Response(`Failed to decrypt calendar URL: ${error.message}`, { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
              });
            }
          } else {
            // Plain URL, use as-is
            decryptedUrls.push(urlParam);
          }
        }
        
        // Build the open-web-calendar URL with decrypted URLs
        const calendarUrl = new URL('https://open-web-calendar.hosted.quelltext.eu/calendar.html');
        
        // Copy all query parameters except 'url' (calendar URLs come from secret)
        for (const [key, value] of url.searchParams.entries()) {
          if (key !== 'url') {
            calendarUrl.searchParams.append(key, value);
          }
        }
        
        // Add decrypted URLs from secret
        for (const decryptedUrl of decryptedUrls) {
          calendarUrl.searchParams.append('url', decryptedUrl);
        }
        
        // Fetch from open-web-calendar
        const response = await fetch(calendarUrl.toString(), {
          headers: {
            'User-Agent': request.headers.get('User-Agent') || 'Cloudflare-Worker',
          },
        });
        
        // Sanitize response to hide calendar URLs in error messages
        // Pass pathname for calendar events processing
        return await sanitizeResponse(response, pathname);
      }
      
      // For all other requests (static resources, etc.), proxy directly
      let targetPath = pathname;
      if (pathname === '/' || pathname === '') {
        targetPath = '/calendar.html';
      }
      
      const targetUrl = new URL(`https://open-web-calendar.hosted.quelltext.eu${targetPath}${url.search}`);
      
      // Forward all headers from the original request
      const requestHeaders = new Headers();
      request.headers.forEach((value, key) => {
        // Skip certain headers that shouldn't be forwarded
        if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'cf-ray' && key.toLowerCase() !== 'cf-connecting-ip') {
          requestHeaders.set(key, value);
        }
      });
      
      const response = await fetch(targetUrl.toString(), {
        headers: requestHeaders,
      });
      
      // Sanitize response to hide calendar URLs in error messages
      // Pass pathname for calendar events processing
      return await sanitizeResponse(response, pathname);
    } catch (error) {
      return new Response(`Error: ${error.message}`, { 
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  },
};
