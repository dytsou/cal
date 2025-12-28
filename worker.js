/**
 * Cloudflare Worker to decrypt fernet:// URLs and proxy to open-web-calendar
 * 
 * This worker:
 * 1. Receives requests with fernet:// URLs in query parameters
 * 2. Decrypts the fernet:// URLs using Fernet
 * 3. Forwards the request to open-web-calendar with decrypted URLs
 * 4. Returns the calendar HTML
 * 
 * Usage:
 * 1. Set ENCRYPTION_KEY secret: wrangler secret put ENCRYPTION_KEY
 * 2. Deploy: wrangler deploy
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
 * Sanitize response body to hide calendar URLs in error messages
 */
async function sanitizeResponse(response) {
  const contentType = response.headers.get('content-type') || '';
  
  // Only sanitize text-based responses
  if (!contentType.includes('text/html') && 
      !contentType.includes('application/json') && 
      !contentType.includes('text/javascript') &&
      !contentType.includes('application/javascript')) {
    // For non-text responses, just add CORS header and return
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  }
  
  const body = await response.text();
  
  // Patterns to detect and sanitize calendar URLs
  const urlPatterns = [
    /https?:\/\/[^\s"']+\.ics/gi,
    /https?:\/\/calendar\.google\.com\/calendar\/ical\/[^\s"']+/gi,
    /%40[^\s"']+/gi, // URL-encoded @ symbols
    /@[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, // Email patterns in URLs
  ];
  
  let sanitizedBody = body;
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
      const encryptionKey = env.ENCRYPTION_KEY;
      
      if (!encryptionKey) {
        return new Response('ENCRYPTION_KEY not configured', { 
          status: 500,
          headers: { 'Content-Type': 'text/plain' }
        });
      }
      
      // Get all url parameters (may be multiple)
      const fernetUrls = url.searchParams.getAll('url');
      
      // Check if any of the URLs are fernet:// encrypted
      const hasFernetUrls = fernetUrls.some(url => url.startsWith('fernet://'));
      
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
      
      // For API endpoints like /srcdoc, we need to get the calendar URLs
      // Priority: 1) Query params, 2) Cookie, 3) Referer header
      if (isApiEndpoint) {
        let urlsToUse = fernetUrls;
        
        // If no URLs in current request, try to get them from cookie
        if (urlsToUse.length === 0) {
          const cookieHeader = request.headers.get('Cookie');
          if (cookieHeader) {
            const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
              const [key, value] = cookie.trim().split('=');
              acc[key] = value;
              return acc;
            }, {});
            
            if (cookies['owc_urls']) {
              try {
                urlsToUse = decodeURIComponent(cookies['owc_urls']).split('|');
              } catch (e) {
                // Ignore cookie parse errors
              }
            }
          }
        }
        
        // If still no URLs, try Referer
        if (urlsToUse.length === 0) {
          const refererHeader = request.headers.get('Referer');
          if (refererHeader) {
            try {
              const refererUrl = new URL(refererHeader);
              urlsToUse = refererUrl.searchParams.getAll('url');
            } catch (e) {
              // Ignore referer parse errors
            }
          }
        }
        
        // Build the target URL
        const targetUrl = new URL(`https://open-web-calendar.hosted.quelltext.eu${pathname}`);
        
        // Copy all query parameters except 'url'
        for (const [key, value] of url.searchParams.entries()) {
          if (key !== 'url') {
            targetUrl.searchParams.append(key, value);
          }
        }
        
        // If we have URLs (fernet:// or plain), decrypt and add them
        if (urlsToUse.length > 0) {
          const decryptedUrls = [];
          for (const urlParam of urlsToUse) {
            if (urlParam.startsWith('fernet://')) {
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
              decryptedUrls.push(urlParam);
            }
          }
          
          // Add decrypted URLs
          for (const decryptedUrl of decryptedUrls) {
            targetUrl.searchParams.append('url', decryptedUrl);
          }
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
        return await sanitizeResponse(response);
      }
      
      // Only decrypt fernet:// URLs if:
      // 1. There are fernet:// URLs in the query params, AND
      // 2. This is the main calendar page request
      // All other requests (static resources, etc.) should be proxied directly
      if (!hasFernetUrls || !isMainCalendarPage) {
        // Proxy this request directly to open-web-calendar
        // Handle root path and calendar.html specially
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
        return await sanitizeResponse(response);
      }
      
      // Decrypt fernet:// URLs
      const decryptedUrls = [];
      for (const fernetUrl of fernetUrls) {
        if (fernetUrl.startsWith('fernet://')) {
          try {
            // Decrypt the URL
            const decrypted = await decryptFernetUrl(fernetUrl, encryptionKey);
            decryptedUrls.push(decrypted);
          } catch (error) {
            return new Response(`Failed to decrypt calendar URL: ${error.message}`, { 
              status: 500,
              headers: { 'Content-Type': 'text/plain' }
            });
          }
        } else {
          // Already a plain URL, use as-is
          decryptedUrls.push(fernetUrl);
        }
      }
      
      // Build the open-web-calendar URL with decrypted URLs
      const calendarUrl = new URL('https://open-web-calendar.hosted.quelltext.eu/calendar.html');
      
      // Copy all query parameters except 'url'
      for (const [key, value] of url.searchParams.entries()) {
        if (key !== 'url') {
          calendarUrl.searchParams.append(key, value);
        }
      }
      
      // Add decrypted URLs
      for (const decryptedUrl of decryptedUrls) {
        calendarUrl.searchParams.append('url', decryptedUrl);
      }
      
      // Fetch from open-web-calendar
      const response = await fetch(calendarUrl.toString(), {
        headers: {
          'User-Agent': request.headers.get('User-Agent') || 'Cloudflare-Worker',
        },
      });
      
      // Clone response headers and modify them
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      
      // Set cookie with fernet:// URLs so subsequent requests (like /srcdoc) can access them
      // Use pipe separator since URLs may contain commas
      if (fernetUrls.length > 0) {
        const cookieValue = encodeURIComponent(fernetUrls.join('|'));
        responseHeaders.set('Set-Cookie', `owc_urls=${cookieValue}; Path=/; SameSite=Lax; Max-Age=3600`);
      }
      
      // Sanitize response to hide calendar URLs in error messages
      // Clone response first to avoid modifying the original
      const clonedResponse = response.clone();
      return await sanitizeResponse(clonedResponse);
    } catch (error) {
      return new Response(`Error: ${error.message}`, { 
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  },
};
