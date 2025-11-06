/**
 * PhishTank Worker
 * Handles database lookups in background thread (non-blocking)
 */

let phishTankDB = null;

// Listen for messages from main thread
self.addEventListener('message', async (event) => {
  const { action, data } = event.data;

  switch (action) {
    case 'loadDatabase':
      await loadDatabase(data.urls);
      break;
    
    case 'checkUrl':
      const result = checkUrl(data.url);
      self.postMessage({ action: 'checkResult', data: result });
      break;
    
    case 'checkBatch':
      const results = checkBatch(data.urls);
      self.postMessage({ action: 'batchResults', data: results });
      break;
    
    default:
      self.postMessage({ action: 'error', data: 'Unknown action' });
  }
});

/**
 * Load PhishTank database into worker memory
 */
async function loadDatabase(urls) {
  try {
    phishTankDB = {
      urls: urls,
      domains: new Set(urls.map(entry => entry.domain)),
      urlMap: new Map(urls.map(entry => [entry.url.toLowerCase(), entry])),
      domainMap: new Map()
    };
    
    // Create domain lookup map
    urls.forEach(entry => {
      if (!phishTankDB.domainMap.has(entry.domain)) {
        phishTankDB.domainMap.set(entry.domain, []);
      }
      phishTankDB.domainMap.get(entry.domain).push(entry);
    });
    
    self.postMessage({ 
      action: 'databaseLoaded', 
      data: { count: urls.length } 
    });
  } catch (error) {
    self.postMessage({ 
      action: 'error', 
      data: { message: 'Failed to load database', error: error.message } 
    });
  }
}

/**
 * Check single URL against database
 */
function checkUrl(url) {
  if (!phishTankDB) {
    return { found: false, error: 'Database not loaded' };
  }

  try {
    const normalizedUrl = url.toLowerCase().replace(/\/$/, '');
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Fast exact URL match
    if (phishTankDB.urlMap.has(normalizedUrl)) {
      const entry = phishTankDB.urlMap.get(normalizedUrl);
      return {
        found: true,
        verified: entry.verified,
        timestamp: entry.timestamp,
        source: 'PhishTank',
        matchType: 'exact'
      };
    }
    
    // Fast domain check
    if (phishTankDB.domains.has(domain)) {
      const entries = phishTankDB.domainMap.get(domain);
      const verified = entries.some(e => e.verified);
      return {
        found: true,
        verified: verified,
        timestamp: entries[0].timestamp,
        source: 'PhishTank',
        matchType: 'domain'
      };
    }
    
    return { found: false };
  } catch (error) {
    return { found: false, error: error.message };
  }
}

/**
 * Check multiple URLs at once (batch operation)
 */
function checkBatch(urls) {
  return urls.map(url => ({
    url: url,
    result: checkUrl(url)
  }));
}

// Notify that worker is ready
self.postMessage({ action: 'ready' });
