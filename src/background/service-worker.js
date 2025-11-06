import { PhishingDetector } from '../utils/phishing-detector.js';
import { StorageManager } from '../utils/storage.js';
import { ThreatIntelligence } from '../utils/threat-intelligence.js';

/**
 * Background service worker for the anti-phishing extension
 * Handles messages from content scripts and performs threat analysis
 */

console.log('Anti-Phishing Guardian: Background service worker loaded');

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('Extension installed/updated:', details.reason);
  
  if (details.reason === 'install') {
    // Set default settings
    await StorageManager.saveSettings({});
    console.log('Default settings initialized');
    
    // Initialize PhishTank database
    console.log('Initializing PhishTank threat intelligence...');
    await ThreatIntelligence.updatePhishTankDatabase();
  }
  
  // Schedule automatic daily updates
  ThreatIntelligence.scheduleAutomaticUpdates();
});

// Rate limiting for message processing
const rateLimiter = {
  requests: new Map(),
  limit: 100, // max requests per minute
  window: 60000, // 1 minute
  
  checkLimit(senderId) {
    const now = Date.now();
    const senderData = this.requests.get(senderId) || { count: 0, resetTime: now + this.window };
    
    // Reset if window expired
    if (now > senderData.resetTime) {
      senderData.count = 0;
      senderData.resetTime = now + this.window;
    }
    
    // Check limit
    if (senderData.count >= this.limit) {
      console.warn(`[Security] Rate limit exceeded for sender: ${senderId}`);
      return false;
    }
    
    // Increment count
    senderData.count++;
    this.requests.set(senderId, senderData);
    return true;
  }
};

// Listen for messages from content scripts
// SECURITY: Comprehensive validation and rate limiting
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // SECURITY FIX #1: Validate sender origin
  if (!sender || !sender.id) {
    console.error('[Security] Message from unknown sender, rejecting');
    sendResponse({ success: false, error: 'Unauthorized' });
    return false;
  }
  
  // SECURITY FIX #2: Only accept messages from our own extension
  if (sender.id !== chrome.runtime.id) {
    console.error('[Security] Message from different extension, rejecting:', sender.id);
    sendResponse({ success: false, error: 'Unauthorized' });
    return false;
  }
  
  // SECURITY FIX #3: Validate message structure
  if (!request || typeof request !== 'object') {
    console.error('[Security] Invalid message format');
    sendResponse({ success: false, error: 'Invalid message format' });
    return false;
  }
  
  // SECURITY FIX #4: Validate action exists and is string
  if (!request.action || typeof request.action !== 'string') {
    console.error('[Security] Missing or invalid action');
    sendResponse({ success: false, error: 'Invalid action' });
    return false;
  }
  
  // SECURITY FIX #5: Whitelist allowed actions
  const ALLOWED_ACTIONS = [
    'analyzeLink',
    'analyzeLinks',
    'addToWhitelist',
    'addToBlacklist',
    'getSettings',
    'updateSettings',
    'getStats',
    'clearCache'
  ];
  
  if (!ALLOWED_ACTIONS.includes(request.action)) {
    console.error('[Security] Unknown or disallowed action:', request.action);
    sendResponse({ success: false, error: 'Unknown action' });
    return false;
  }
  
  // SECURITY FIX #6: Rate limiting
  const senderId = `${sender.id}-${sender.tab?.id || 'popup'}`;
  if (!rateLimiter.checkLimit(senderId)) {
    sendResponse({ success: false, error: 'Rate limit exceeded' });
    return false;
  }
  
  // SECURITY FIX #7: Sanitize inputs
  const sanitizedRequest = sanitizeMessageData(request);
  
  console.log('[Security] Validated message:', sanitizedRequest.action);

  // Handle different message types
  switch (sanitizedRequest.action) {
    case 'analyzeLink':
      handleAnalyzeLink(sanitizedRequest.url, sanitizedRequest.context, sendResponse);
      return true; // Keep channel open for async response

    case 'analyzeLinks':
      handleAnalyzeLinks(sanitizedRequest.urls, sendResponse);
      return true;

    case 'addToWhitelist':
      handleAddToWhitelist(sanitizedRequest.domain, sendResponse);
      return true;

    case 'addToBlacklist':
      handleAddToBlacklist(sanitizedRequest.domain, sendResponse);
      return true;

    case 'getSettings':
      handleGetSettings(sendResponse);
      return true;

    case 'updateSettings':
      handleUpdateSettings(sanitizedRequest.settings, sendResponse);
      return true;

    case 'getStats':
      handleGetStats(sendResponse);
      return true;

    case 'clearCache':
      handleClearCache(sendResponse);
      return true;

    default:
      // This should never happen due to whitelist check above
      console.error('[Security] Unexpected action bypass:', sanitizedRequest.action);
      sendResponse({ success: false, error: 'Invalid action' });
      return false;
  }
});

/**
 * Sanitize message data to prevent injection attacks
 * SECURITY: Essential defensive layer
 */
function sanitizeMessageData(request) {
  const sanitized = {
    action: String(request.action).substring(0, 50) // Limit action length
  };
  
  // Sanitize based on action
  if (request.url) {
    sanitized.url = sanitizeURL(request.url);
  }
  
  if (request.urls && Array.isArray(request.urls)) {
    // Limit array size to prevent DoS
    sanitized.urls = request.urls.slice(0, 100).map(url => sanitizeURL(url));
  }
  
  if (request.domain) {
    sanitized.domain = sanitizeDomain(request.domain);
  }
  
  if (request.context && typeof request.context === 'string') {
    // Limit context length to prevent memory attacks
    sanitized.context = request.context.substring(0, 10000);
  }
  
  if (request.settings && typeof request.settings === 'object') {
    // Only allow expected settings fields
    sanitized.settings = sanitizeSettings(request.settings);
  }
  
  return sanitized;
}

/**
 * Sanitize URL input
 */
function sanitizeURL(url) {
  if (!url || typeof url !== 'string') return '';
  
  // Limit length
  const cleaned = url.substring(0, 2048);
  
  // Validate it's a valid URL
  try {
    new URL(cleaned);
    return cleaned;
  } catch {
    console.warn('[Security] Invalid URL provided:', cleaned.substring(0, 100));
    return '';
  }
}

/**
 * Sanitize domain input
 */
function sanitizeDomain(domain) {
  if (!domain || typeof domain !== 'string') return '';
  
  // Remove protocol if present
  let cleaned = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
  
  // Remove path, query, fragment
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];
  
  // Validate domain format
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(cleaned)) {
    console.warn('[Security] Invalid domain format:', cleaned);
    return '';
  }
  
  return cleaned.substring(0, 255);
}

/**
 * Sanitize settings object
 */
function sanitizeSettings(settings) {
  const ALLOWED_SETTINGS = [
    'enabled',
    'blockDangerous',
    'showWarnings',
    'notifyDangerous',
    'notifySuspicious',
    'notifyUpdates',
    'protectionLevel'
  ];
  
  const sanitized = {};
  
  for (const key of ALLOWED_SETTINGS) {
    if (key in settings) {
      // Type validation
      if (typeof settings[key] === 'boolean') {
        sanitized[key] = settings[key];
      } else if (typeof settings[key] === 'string') {
        sanitized[key] = String(settings[key]).substring(0, 50);
      }
    }
  }
  
  return sanitized;
}

/**
 * Handle single link analysis request
 * ENHANCED: Now accepts email context for spam detection
 * SECURITY: All inputs pre-sanitized
 */
async function handleAnalyzeLink(url, context, sendResponse) {
  try {
    // Additional validation
    if (!url) {
      sendResponse({ success: false, error: 'URL required' });
      return;
    }
    
    const analysis = await PhishingDetector.analyzeLink(url, context);
    const formatted = PhishingDetector.formatAnalysis(analysis);
    sendResponse({ success: true, data: formatted });
  } catch (error) {
    console.error('Error analyzing link:', error);
    sendResponse({ success: false, error: 'Analysis failed' });
  }
}

/**
 * Handle multiple links analysis request
 * SECURITY: Inputs pre-sanitized, array size limited
 */
async function handleAnalyzeLinks(urls, sendResponse) {
  try {
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      sendResponse({ success: false, error: 'Invalid URLs array' });
      return;
    }
    
    const results = await PhishingDetector.analyzeLinks(urls);
    const formatted = results.map(r => PhishingDetector.formatAnalysis(r));
    sendResponse({ success: true, data: formatted });
  } catch (error) {
    console.error('Error analyzing links:', error);
    sendResponse({ success: false, error: 'Analysis failed' });
  }
}

/**
 * Handle add to whitelist request
 * SECURITY: Domain pre-sanitized
 */
async function handleAddToWhitelist(domain, sendResponse) {
  try {
    if (!domain) {
      sendResponse({ success: false, error: 'Domain required' });
      return;
    }
    
    await StorageManager.addToWhitelist(domain);
    await StorageManager.clearCache(); // Clear cache to re-analyze
    sendResponse({ success: true });
  } catch (error) {
    console.error('Error adding to whitelist:', error);
    sendResponse({ success: false, error: 'Operation failed' });
  }
}

/**
 * Handle add to blacklist request
 * SECURITY: Domain pre-sanitized
 */
async function handleAddToBlacklist(domain, sendResponse) {
  try {
    if (!domain) {
      sendResponse({ success: false, error: 'Domain required' });
      return;
    }
    
    await StorageManager.addToBlacklist(domain);
    await StorageManager.clearCache(); // Clear cache to re-analyze
    sendResponse({ success: true });
  } catch (error) {
    console.error('Error adding to blacklist:', error);
    sendResponse({ success: false, error: 'Operation failed' });
  }
}

/**
 * Handle get settings request
 */
async function handleGetSettings(sendResponse) {
  try {
    const settings = await StorageManager.getSettings();
    sendResponse({ success: true, data: settings });
  } catch (error) {
    console.error('Error getting settings:', error);
    sendResponse({ success: false, error: error.message });
  }
}

/**
 * Handle update settings request
 * SECURITY: Settings pre-sanitized
 */
async function handleUpdateSettings(settings, sendResponse) {
  try {
    if (!settings || typeof settings !== 'object') {
      sendResponse({ success: false, error: 'Invalid settings' });
      return;
    }
    
    await StorageManager.saveSettings(settings);
    sendResponse({ success: true });
  } catch (error) {
    console.error('Error updating settings:', error);
    sendResponse({ success: false, error: 'Operation failed' });
  }
}

/**
 * Handle get statistics request
 */
async function handleGetStats(sendResponse) {
  try {
    const stats = await StorageManager.getStats();
    sendResponse({ success: true, data: stats });
  } catch (error) {
    console.error('Error getting stats:', error);
    sendResponse({ success: false, error: error.message });
  }
}

/**
 * Handle clear cache request
 */
async function handleClearCache(sendResponse) {
  try {
    await StorageManager.clearCache();
    sendResponse({ success: true });
  } catch (error) {
    console.error('Error clearing cache:', error);
    sendResponse({ success: false, error: error.message });
  }
}

// Keep service worker alive with periodic tasks
chrome.runtime.onStartup.addListener(() => {
  console.log('Extension started');
  
  // Ensure threat intelligence updates are scheduled
  ThreatIntelligence.scheduleAutomaticUpdates();
});

// SOLUTION: Keep service worker alive by responding to alarms
// This prevents the "service worker (Inactive)" issue
let keepAliveInterval = null;

// Set up keep-alive mechanism
function setupKeepAlive() {
  // Create a periodic alarm to keep service worker active
  chrome.alarms.create('keepAlive', {
    periodInMinutes: 1 // Ping every minute
  });
  
  console.log('[Service Worker] Keep-alive alarm created');
}

// Listen for alarm to keep service worker active
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    // Simple operation to keep worker alive
    console.log('[Service Worker] Keep-alive ping');
    
    // Check database health periodically
    ThreatIntelligence.getDatabaseStats().then(stats => {
      if (stats.exists && stats.needsUpdate) {
        console.log('[Service Worker] Database needs update, triggering refresh');
        ThreatIntelligence.updatePhishTankDatabase();
      }
    }).catch(err => {
      console.error('[Service Worker] Health check failed:', err);
    });
  }
});

// Initialize keep-alive on service worker activation
setupKeepAlive();

// Re-establish keep-alive on extension update
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'update') {
    console.log('[Service Worker] Extension updated, re-establishing keep-alive');
    setupKeepAlive();
  }
});

// Handle long-running connections from content scripts
const connections = new Map();

chrome.runtime.onConnect.addListener((port) => {
  console.log('[Service Worker] New connection established:', port.name);
  
  const tabId = port.sender?.tab?.id;
  if (tabId) {
    connections.set(tabId, port);
    
    port.onDisconnect.addListener(() => {
      console.log('[Service Worker] Connection closed:', port.name);
      connections.delete(tabId);
    });
    
    // Keep connection alive with periodic messages
    const keepAliveTimer = setInterval(() => {
      try {
        port.postMessage({ type: 'ping' });
      } catch (error) {
        clearInterval(keepAliveTimer);
        connections.delete(tabId);
      }
    }, 20000); // Ping every 20 seconds
    
    port.onMessage.addListener((message) => {
      if (message.type === 'pong') {
        console.log('[Service Worker] Received pong from tab:', tabId);
      }
    });
  }
});

// Ensure service worker stays active during critical operations
let activeOperations = 0;

function incrementActiveOperations() {
  activeOperations++;
  console.log('[Service Worker] Active operations:', activeOperations);
}

function decrementActiveOperations() {
  activeOperations = Math.max(0, activeOperations - 1);
  console.log('[Service Worker] Active operations:', activeOperations);
}

// Wrap critical handlers to track active operations
const originalHandleAnalyzeLink = handleAnalyzeLink;
handleAnalyzeLink = async function(url, context, sendResponse) {
  incrementActiveOperations();
  try {
    await originalHandleAnalyzeLink(url, context, sendResponse);
  } finally {
    decrementActiveOperations();
  }
};

console.log('[Service Worker] Keep-alive mechanisms initialized');
