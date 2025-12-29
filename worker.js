/**
 * Cloudflare Worker to decrypt fernet:// URLs and proxy to open-web-calendar
 * 
 * This worker:
 * 1. Reads CALENDAR_URL from Cloudflare Worker secrets (comma-separated)
 * 2. Decrypts fernet:// URLs using Fernet encryption (ENCRYPTION_METHOD is hardcoded to 'fernet')
 * 3. Forwards the request to open-web-calendar with decrypted URLs
 * 4. Filters out events declined by user (based on USER_EMAILS secret)
 * 5. Sanitizes non-PUBLIC events to only show busy time
 * 6. Returns the calendar HTML
 * 
 * Configuration:
 * - ENCRYPTION_METHOD: Hardcoded to 'fernet' (not configurable)
 * - ENCRYPTION_KEY: Required Cloudflare Worker secret (for decrypting fernet:// URLs)
 * - CALENDAR_URL: Required Cloudflare Worker secret (comma-separated, can be plain or fernet:// encrypted)
 * - USER_EMAILS: Optional Cloudflare Worker secret (comma-separated list of user emails for declined event filtering)
 * 
 * Usage:
 * 1. Set CALENDAR_URL secret: wrangler secret put CALENDAR_URL
 * 2. Set ENCRYPTION_KEY secret: wrangler secret put ENCRYPTION_KEY
 * 3. Set USER_EMAILS secret: wrangler secret put USER_EMAILS
 *    (e.g., "user1@gmail.com,user2@example.com,user3@domain.org")
 * 4. Deploy: wrangler deploy
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
  return event.title || event.summary || event.name || event.text || '';
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
 * Extract event CLASS property (handles various field name formats)
 * Returns null if not found (missing CLASS defaults to PRIVATE for privacy)
 */
function getEventClass(event) {
  // Check various possible field names for CLASS property
  // iCal format uses CLASS, but different parsers may use different field names
  let classValue = event.class || 
                   event.CLASS || 
                   event.classification || 
                   event['CLASS'] ||
                   event['class'] ||
                   null;
  
  // Check nested properties structure (common in some iCal parsers)
  if (!classValue && event.properties) {
    classValue = event.properties.CLASS || 
                 event.properties.class || 
                 event.properties.CLASS?.value ||
                 event.properties.class?.value ||
                 null;
  }
  
  // Check inside 'ical' field - open-web-calendar stores raw iCal data here
  if (!classValue && event.ical) {
    // ical might be a string containing raw iCal data or an object
    if (typeof event.ical === 'string') {
      // Parse CLASS from raw iCal string (e.g., "CLASS:PUBLIC" or "CLASS:PRIVATE")
      const classMatch = event.ical.match(/CLASS[:\s]*([A-Za-z]+)/i);
      if (classMatch) {
        classValue = classMatch[1];
      }
    } else if (typeof event.ical === 'object') {
      classValue = event.ical.CLASS || event.ical.class || null;
    }
  }
  
  // If no CLASS property found, return null (will be treated as PRIVATE by default)
  if (classValue === null || classValue === undefined || classValue === '') {
    return null;
  }
  
  // Normalize to uppercase string for comparison
  return String(classValue).toUpperCase();
}

/**
 * Check if event is PUBLIC
 * Only returns true if CLASS is explicitly set to 'PUBLIC'
 * Missing CLASS (null) defaults to PRIVATE - only shows start/end time
 * Any other value (PRIVATE, CONFIDENTIAL, etc.) also returns false
 */
function isPublicEvent(event) {
  const eventClass = getEventClass(event);
  // Only return true if CLASS is explicitly PUBLIC
  // null (missing CLASS) defaults to PRIVATE - only show time, no details
  // Any other value (PRIVATE, CONFIDENTIAL, etc.) also means non-PUBLIC
  return eventClass === 'PUBLIC';
}

/**
 * Remove all identifying information from an event object
 * This function is used to sanitize non-PUBLIC events
 */
function removeAllEventInfo(event) {
  // Remove ALL identifying information - only keep time fields
  event.title = '';
  event.summary = '';
  event.name = '';
  event.text = 'BUSY';  // open-web-calendar uses 'text' field for title
  event.description = '';
  event.desc = '';
  event.location = '';
  event.loc = '';
  event.url = '';
  event.link = '';
  event.organizer = '';
  event.attendees = '';
  event.attendee = '';
  event.participants = '';  // open-web-calendar uses 'participants'
  event.label = '';
  event.notes = '';
  event.note = '';
  event.comment = '';
  event.comments = '';
  
  // CRITICAL: Remove ical field which contains raw iCal data with all event details
  // This prevents any sensitive information from being exposed in the response
  event.ical = '';
  
  // Remove other fields that might contain identifying information
  event.uid = '';  // Remove unique identifier
  event.id = '';  // Remove ID if present
  event.categories = '';  // Remove categories
  event.color = '';  // Remove color
  event.css_classes = '';  // Remove CSS classes
  event.owc = '';  // Remove open-web-calendar specific data
  event.recurrence = '';  // Remove recurrence info
  event.sequence = '';  // Remove sequence
  event.type = '';  // Remove type
  
  // Mark this event as sanitized
  event._isNonPublic = true;
  
  return event;
}

/**
 * Sanitize non-PUBLIC events to only show start and end times
 * Removes title, description, location, and other details
 */
function sanitizeNonPublicEvent(event) {
  const eventClass = getEventClass(event);
  const isPublic = isPublicEvent(event);
  
  // If CLASS is PUBLIC, return event as-is (no sanitization)
  if (isPublic) {
    return event;
  }
  
  // For non-PUBLIC events (PRIVATE, CONFIDENTIAL, missing CLASS, or any other value), sanitize
  // Create a sanitized version with only time fields
  // Start with a copy of the event to preserve structure
  const sanitized = { ...event };
  
  // Remove ALL identifying information - only keep time fields
  removeAllEventInfo(sanitized);
  
  // Only preserve time fields, calendar ID, and CLASS property
  // All other fields have been removed to prevent information leakage
  
  return sanitized;
}

/**
 * Parse user emails from environment secret
 * USER_EMAILS secret should be comma-separated list of emails
 * e.g., "user1@gmail.com,user2@example.com,user3@domain.org"
 */
function parseUserEmails(userEmailsSecret) {
  if (!userEmailsSecret) {
    return [];
  }
  return userEmailsSecret
    .split(',')
    .map(email => email.trim().toLowerCase())
    .filter(email => email.length > 0);
}

/**
 * Check if event is declined by the calendar owner (user responded "no")
 * Returns true ONLY if the event is explicitly marked as declined by the calendar owner
 * 
 * For calendar invitations:
 * - When YOU decline an event, the event STATUS is still CONFIRMED
 * - But YOUR PARTSTAT (participation status) becomes DECLINED
 * - We need to check for PARTSTAT=DECLINED in YOUR ATTENDEE line specifically
 * - Other attendees declining should NOT filter the event
 * 
 * @param {Object} event - The event object to check
 * @param {string[]} userEmails - Array of user email addresses to check for declined status
 */
function isEventDeclined(event, userEmails = []) {
  const title = event.text || event.title || event.summary || '(no title)';
  const cssClasses = event['css-classes'] || event.css_classes || event.cssClasses || [];
  const eventType = event.type || '';
  const ical = event.ical || '';
  
  // Check css-classes for declined indicator
  // open-web-calendar uses an array of classes like:
  // ['event', 'STATUS-CONFIRMED', 'CLASS-PUBLIC', etc.]
  // We look for 'STATUS-DECLINED' or 'PARTSTAT-DECLINED' class
  if (Array.isArray(cssClasses)) {
    for (const cls of cssClasses) {
      const lowerCls = String(cls).toLowerCase();
      // Only match exact status classes, not just containing 'declined'
      if (lowerCls === 'status-declined' || 
          lowerCls === 'partstat-declined') {
        console.log('[Declined Check] FILTERED - css-class declined:', title);
        return true;
      }
    }
  }
  
  // Check the event's own type/status field
  if (eventType) {
    const upperType = String(eventType).toUpperCase();
    if (upperType === 'DECLINED' || upperType === 'CANCELLED') {
      console.log('[Declined Check] FILTERED - type declined/cancelled:', title);
      return true;
    }
  }
  
  // Check ical field for the USER's PARTSTAT=DECLINED
  if (ical && typeof ical === 'string') {
    // Check for STATUS:CANCELLED or STATUS:DECLINED (entire event cancelled)
    const cancelledPattern = /^STATUS:(CANCELLED|DECLINED)/im;
    if (cancelledPattern.test(ical)) {
      console.log('[Declined Check] FILTERED - event STATUS cancelled:', title);
      return true;
    }
    
    // Check for PARTSTAT=DECLINED in the user's ATTENDEE line
    // Format: ATTENDEE;...;PARTSTAT=DECLINED;...:mailto:user@email.com
    // We need to find ATTENDEE lines that contain both PARTSTAT=DECLINED AND a user email
    
    // Split ical into lines and look for ATTENDEE lines
    // Note: ATTENDEE lines can be folded (continuation lines start with space)
    const icalLines = ical.replace(/\r\n /g, '').split(/\r?\n/);
    
    for (const line of icalLines) {
      if (line.startsWith('ATTENDEE')) {
        // Check if this attendee line has PARTSTAT=DECLINED
        if (/PARTSTAT=DECLINED/i.test(line)) {
          // Check if this is for one of the user's emails
          for (const userEmail of userEmails) {
            if (line.toLowerCase().includes(userEmail.toLowerCase())) {
              console.log('[Declined Check] FILTERED - user PARTSTAT=DECLINED:', title, '| email:', userEmail);
              return true;
            }
          }
        }
      }
    }
  }
  
  // Check if event has explicit status field indicating declined/cancelled
  const eventStatus = event.event_status || event.status || null;
  if (eventStatus) {
    const normalizedStatus = String(eventStatus).toUpperCase();
    if (normalizedStatus === 'CANCELLED' || normalizedStatus === 'DECLINED') {
      console.log('[Declined Check] FILTERED - event_status:', title);
      return true;
    }
  }
  
  return false;
}

/**
 * Filter out declined events (events where user responded "no")
 * @param {Array} events - Array of events to filter
 * @param {string[]} userEmails - Array of user email addresses to check for declined status
 */
function filterDeclinedEvents(events, userEmails = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return events;
  }
  
  console.log('[Filter Declined] Processing', events.length, 'events');
  
  const filteredEvents = events.filter(event => !isEventDeclined(event, userEmails));
  
  console.log('[Filter Declined] After filtering:', filteredEvents.length, 'events remain');
  
  return filteredEvents;
}

/**
 * Merge consecutive events within the same calendar
 * Events are consecutive if event1.end === event2.start (exact match)
 * @param {Array} events - Array of events to process
 * @param {string[]} userEmails - Array of user email addresses to check for declined status
 */
function mergeConsecutiveEvents(events, userEmails = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return events;
  }
  
  // Filter out declined events first
  const filteredEvents = filterDeclinedEvents(events, userEmails);
  
  // Sanitize non-PUBLIC events
  const sanitizedEvents = filteredEvents.map(event => sanitizeNonPublicEvent(event));
  
  // Group events by calendar identifier
  const eventsByCalendar = {};
  for (const event of sanitizedEvents) {
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
      // Event is already sanitized, but we need to preserve it during merge
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
          // Check if either event is non-PUBLIC - if so, keep titles empty
          const currentIsNonPublic = currentMerge._isNonPublic || !isPublicEvent(currentMerge);
          const eventIsNonPublic = event._isNonPublic || !isPublicEvent(event);
          
          if (currentIsNonPublic || eventIsNonPublic) {
            // At least one event is non-PUBLIC, remove ALL identifying information
            removeAllEventInfo(currentMerge);
          } else {
            // Both are PUBLIC, merge titles normally
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
 * Remove calendar name from calendar object
 * @param {Object} calendar - The calendar object
 */
function removeCalendarName(calendar) {
  if (!calendar || typeof calendar !== 'object') {
    return calendar;
  }
  
  // Create a copy of the calendar object without the name field
  const sanitized = { ...calendar };
  delete sanitized.name;
  delete sanitized.calendarName;
  delete sanitized.title;
  
  return sanitized;
}

/**
 * Process calendar events JSON and merge consecutive events
 */
/**
 * Process calendar events JSON and merge consecutive events
 * @param {Object|Array} jsonData - The calendar events data
 * @param {string[]} userEmails - Array of user email addresses to check for declined status
 */
function processCalendarEventsJson(jsonData, userEmails = []) {
  // Debug: Log first event structure to understand data format
  // TODO: Remove or make conditional in production
  try {
    let firstEvent = null;
    if (Array.isArray(jsonData) && jsonData.length > 0) {
      firstEvent = jsonData[0];
    } else if (jsonData && typeof jsonData === 'object') {
      if (Array.isArray(jsonData.events) && jsonData.events.length > 0) {
        firstEvent = jsonData.events[0];
      } else if (Array.isArray(jsonData.calendars) && jsonData.calendars.length > 0) {
        const firstCalendar = jsonData.calendars[0];
        if (Array.isArray(firstCalendar.events) && firstCalendar.events.length > 0) {
          firstEvent = firstCalendar.events[0];
        }
      }
    }
    
    // Debug logging removed - CLASS detection is working
  } catch (e) {
    // Ignore errors
  }
  
  if (Array.isArray(jsonData)) {
    // Format: [{event1}, {event2}, ...]
    return mergeConsecutiveEvents(jsonData, userEmails);
  } else if (jsonData && typeof jsonData === 'object') {
    // Check for nested structures
    if (Array.isArray(jsonData.events)) {
      // Format: {events: [...], ...}
      // Remove calendar name from root level
      const sanitizedRoot = removeCalendarName(jsonData);
      return {
        ...sanitizedRoot,
        events: mergeConsecutiveEvents(jsonData.events, userEmails)
      };
    } else if (Array.isArray(jsonData.calendars)) {
      // Format: {calendars: [{events: [...]}, ...], ...}
      // Remove calendar name from root level as well
      const sanitizedRoot = removeCalendarName(jsonData);
      
      return {
        ...sanitizedRoot,
        calendars: jsonData.calendars.map(calendar => {
          // Remove calendar name from calendar object
          const sanitizedCalendar = removeCalendarName(calendar);
          
          if (Array.isArray(sanitizedCalendar.events)) {
            return {
              ...sanitizedCalendar,
              events: mergeConsecutiveEvents(sanitizedCalendar.events, userEmails)
            };
          }
          return sanitizedCalendar;
        })
      };
    } else if (Array.isArray(jsonData.data)) {
      // Format: {data: [...], ...}
      const sanitizedRoot = removeCalendarName(jsonData);
      return {
        ...sanitizedRoot,
        data: mergeConsecutiveEvents(jsonData.data, userEmails)
      };
    } else if (Array.isArray(jsonData.items)) {
      // Format: {items: [...], ...}
      const sanitizedRoot = removeCalendarName(jsonData);
      return {
        ...sanitizedRoot,
        items: mergeConsecutiveEvents(jsonData.items, userEmails)
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
            const sanitizedRoot = removeCalendarName(jsonData);
            return {
              ...sanitizedRoot,
              [key]: mergeConsecutiveEvents(jsonData[key], userEmails)
            };
          }
        }
      }
    }
  }
  
  // Unknown format, remove calendar name if present and return
  if (jsonData && typeof jsonData === 'object') {
    return removeCalendarName(jsonData);
  }
  return jsonData;
}

/**
 * Sanitize response body to hide calendar URLs in error messages
 * Only sanitizes HTML and JSON responses to avoid breaking JavaScript code
 * @param {Response} response - The response to sanitize
 * @param {string} pathname - The request pathname
 * @param {string[]} userEmails - Array of user email addresses to check for declined status
 */
async function sanitizeResponse(response, pathname, userEmails = []) {
  const contentType = response.headers.get('content-type') || '';
  
  // Block ICS/calendar file downloads - check content type and pathname
  if (contentType.includes('text/calendar') || 
      contentType.includes('application/ics') ||
      pathname.endsWith('.ics') || 
      pathname.endsWith('.ICAL') || 
      pathname.endsWith('.iCal')) {
    return new Response('Calendar file download is not allowed', { 
      status: 403,
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
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
        const processedData = processCalendarEventsJson(jsonData, userEmails);
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
      
      // Parse user emails from secret for declined event filtering
      // USER_EMAILS secret should be comma-separated list of emails
      const userEmails = parseUserEmails(env.USER_EMAILS);
      
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
      
      // Block ICS file downloads - prevent access to raw calendar files
      if (pathname.endsWith('.ics') || pathname.endsWith('.ICAL') || pathname.endsWith('.iCal')) {
        return new Response('Calendar file download is not allowed', { 
          status: 403,
          headers: { 
            'Content-Type': 'text/plain',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      
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
        // Pass pathname for calendar events processing and user emails for declined filtering
        return await sanitizeResponse(response, pathname, userEmails);
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
        return await sanitizeResponse(response, pathname, userEmails);
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
      return await sanitizeResponse(response, pathname, userEmails);
    } catch (error) {
      return new Response(`Error: ${error.message}`, { 
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  },
};
