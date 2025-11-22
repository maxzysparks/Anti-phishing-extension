/**
 * Google Safe Browsing API Integration
 * Provides real-time URL reputation checking against Google's threat database
 */

const SAFE_BROWSING_API_KEY = 'YOUR_API_KEY_HERE'; // User needs to add their API key
const SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// Threat types to check
const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION'
];

// Platform types
const PLATFORM_TYPES = [
  'ANY_PLATFORM',
  'WINDOWS',
  'LINUX',
  'OSX',
  'CHROME'
];

// Threat entry types
const THREAT_ENTRY_TYPES = ['URL'];

/**
 * Check URLs against Google Safe Browsing API
 * @param {string|string[]} urls - Single URL or array of URLs to check
 * @returns {Promise<Object>} Threat information
 */
export async function checkUrlSafety(urls) {
  try {
    // Ensure urls is an array
    const urlArray = Array.isArray(urls) ? urls : [urls];
    
    // Validate URLs
    const validUrls = urlArray.filter(url => {
      try {
        new URL(url);
        return true;
      } catch {
        return false;
      }
    });

    if (validUrls.length === 0) {
      return {
        success: false,
        error: 'No valid URLs provided'
      };
    }

    // Check if API key is configured
    if (SAFE_BROWSING_API_KEY === 'YOUR_API_KEY_HERE') {
      console.warn('[Safe Browsing] API key not configured, using fallback detection');
      return {
        success: true,
        threats: [],
        usingFallback: true,
        message: 'Google Safe Browsing API key not configured'
      };
    }

    // Prepare request body
    const requestBody = {
      client: {
        clientId: 'anti-phishing-guardian',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: PLATFORM_TYPES,
        threatEntryTypes: THREAT_ENTRY_TYPES,
        threatEntries: validUrls.map(url => ({ url }))
      }
    };

    // Make API request
    const response = await fetch(`${SAFE_BROWSING_API_URL}?key=${SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    // Process results
    const threats = data.matches || [];
    
    return {
      success: true,
      threats: threats.map(match => ({
        url: match.threat.url,
        threatType: match.threatType,
        platformType: match.platformType,
        threatEntryType: match.threatEntryType,
        cacheDuration: match.cacheDuration,
        severity: getThreatSeverity(match.threatType)
      })),
      checkedUrls: validUrls,
      timestamp: Date.now()
    };

  } catch (error) {
    console.error('[Safe Browsing] Error checking URL safety:', error);
    return {
      success: false,
      error: error.message,
      threats: []
    };
  }
}

/**
 * Get threat severity level
 * @param {string} threatType - Type of threat
 * @returns {string} Severity level
 */
function getThreatSeverity(threatType) {
  const severityMap = {
    'MALWARE': 'critical',
    'SOCIAL_ENGINEERING': 'critical',
    'UNWANTED_SOFTWARE': 'high',
    'POTENTIALLY_HARMFUL_APPLICATION': 'medium'
  };
  
  return severityMap[threatType] || 'low';
}

/**
 * Check if URL is safe (no threats found)
 * @param {string} url - URL to check
 * @returns {Promise<boolean>} True if safe, false if threats found
 */
export async function isUrlSafe(url) {
  const result = await checkUrlSafety(url);
  return result.success && result.threats.length === 0;
}

/**
 * Get detailed threat report for URL
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Detailed threat report
 */
export async function getThreatReport(url) {
  const result = await checkUrlSafety(url);
  
  if (!result.success) {
    return {
      url,
      safe: false,
      error: result.error,
      threats: []
    };
  }

  const threats = result.threats.filter(t => t.url === url);
  
  return {
    url,
    safe: threats.length === 0,
    threatCount: threats.length,
    threats: threats,
    highestSeverity: threats.length > 0 
      ? getHighestSeverity(threats.map(t => t.severity))
      : 'none',
    timestamp: result.timestamp,
    usingFallback: result.usingFallback || false
  };
}

/**
 * Get highest severity from list
 * @param {string[]} severities - Array of severity levels
 * @returns {string} Highest severity
 */
function getHighestSeverity(severities) {
  const order = ['critical', 'high', 'medium', 'low', 'none'];
  
  for (const severity of order) {
    if (severities.includes(severity)) {
      return severity;
    }
  }
  
  return 'none';
}

/**
 * Batch check multiple URLs with caching
 * @param {string[]} urls - Array of URLs to check
 * @param {Object} cache - Cache object
 * @returns {Promise<Object>} Results with cache info
 */
export async function batchCheckUrls(urls, cache = {}) {
  const uncachedUrls = [];
  const cachedResults = [];

  // Check cache first
  for (const url of urls) {
    if (cache[url] && Date.now() - cache[url].timestamp < 3600000) { // 1 hour cache
      cachedResults.push(cache[url]);
    } else {
      uncachedUrls.push(url);
    }
  }

  // Check uncached URLs
  let newResults = [];
  if (uncachedUrls.length > 0) {
    const result = await checkUrlSafety(uncachedUrls);
    if (result.success) {
      newResults = uncachedUrls.map(url => {
        const threats = result.threats.filter(t => t.url === url);
        return {
          url,
          safe: threats.length === 0,
          threats,
          timestamp: Date.now()
        };
      });

      // Update cache
      newResults.forEach(r => {
        cache[r.url] = r;
      });
    }
  }

  return {
    success: true,
    results: [...cachedResults, ...newResults],
    cacheHits: cachedResults.length,
    apiCalls: uncachedUrls.length
  };
}

/**
 * Format threat information for display
 * @param {Object} threat - Threat object
 * @returns {string} Formatted threat description
 */
export function formatThreatInfo(threat) {
  const descriptions = {
    'MALWARE': 'This site may install malicious software on your computer',
    'SOCIAL_ENGINEERING': 'This site may be attempting to steal your personal information (phishing)',
    'UNWANTED_SOFTWARE': 'This site may install unwanted software',
    'POTENTIALLY_HARMFUL_APPLICATION': 'This site may contain potentially harmful applications'
  };

  return descriptions[threat.threatType] || 'This site may be unsafe';
}

/**
 * Get recommendation based on threat
 * @param {Object} threatReport - Threat report object
 * @returns {Object} Recommendation
 */
export function getRecommendation(threatReport) {
  if (threatReport.safe) {
    return {
      action: 'allow',
      message: 'This URL appears to be safe',
      color: 'green'
    };
  }

  const severity = threatReport.highestSeverity;

  if (severity === 'critical') {
    return {
      action: 'block',
      message: 'DANGER: This URL is known to be malicious. Do not visit!',
      color: 'red'
    };
  }

  if (severity === 'high') {
    return {
      action: 'warn',
      message: 'WARNING: This URL may be dangerous. Proceed with extreme caution.',
      color: 'orange'
    };
  }

  return {
    action: 'caution',
    message: 'CAUTION: This URL has been flagged. Be careful.',
    color: 'yellow'
  };
}

export default {
  checkUrlSafety,
  isUrlSafe,
  getThreatReport,
  batchCheckUrls,
  formatThreatInfo,
  getRecommendation
};
