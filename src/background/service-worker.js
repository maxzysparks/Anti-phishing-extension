import { PhishingDetector } from '../utils/phishing-detector.js';
import { StorageManager } from '../utils/storage.js';
import { ThreatIntelligence } from '../utils/threat-intelligence.js';
import { tfManager } from '../ml/tensorflow-manager.js';
import { ModelTrainer } from '../ml/model-trainer.js';
import { TrainingDataCollector } from '../ml/training-data-collector.js';
import { PatternDetector } from '../ml/pattern-detector.js';
import { p2pThreatNetwork } from '../network/p2p-threat-network.js';
import { GraphNeuralNetwork } from '../ml/graph-neural-network.js';
import { distributedThreatDB } from '../network/distributed-threat-db.js';
import { behavioralBiometrics } from '../security/behavioral-biometrics.js';
import { TelemetrySystem } from '../production/telemetry-system.js';
import { ProductionManager } from '../production/production-suite.js';

/**
 * Background service worker for the anti-phishing extension
 * Handles messages from content scripts and performs threat analysis
 */

console.log('Anti-Phishing Guardian: Background service worker loaded');

// Initialize TensorFlow.js on startup (with error recovery)
// CRITICAL FIX: Wrap in try-catch and don't let TF errors crash service worker
let tfInitialized = false;

async function initializeTensorFlow() {
  if (tfInitialized) return;
  
  try {
    console.log('[ML] Initializing TensorFlow.js...');
    const initResult = await tfManager.initialize();
    if (initResult.success) {
      console.log('[ML] TensorFlow.js initialized:', initResult.message);
      tfInitialized = true;
      
      // Try to load saved model (non-blocking)
      tfManager.loadModel().then(loadResult => {
        if (loadResult.success) {
          console.log('[ML] Pre-trained model loaded successfully');
        } else {
          console.log('[ML] No pre-trained model found, will create new model on first use');
        }
      }).catch(err => {
        console.warn('[ML] Model loading failed (non-critical):', err.message);
      });
    } else {
      console.warn('[ML] TensorFlow.js initialization failed (non-critical):', initResult.error);
    }
  } catch (error) {
    console.warn('[ML] TensorFlow initialization error (non-critical):', error.message);
    // Don't let TF errors crash the service worker
  }
}

// Initialize ML Systems with staggered loading for better performance
setTimeout(() => {
  // Priority 1: TensorFlow (needed by ensemble)
  initializeTensorFlow().catch(err => {
    console.warn('[ML] Deferred TF init failed (non-critical):', err.message);
  });
  
  // Priority 2: Ensemble Detector (highest accuracy, load after TF)
  setTimeout(() => {
    PatternDetector.initializeEnsemble().catch(err => {
      console.warn('[ML] Ensemble init failed (non-critical):', err.message);
    });
  }, 2000); // Wait 2 seconds after TF
  
  // Priority 3: Zero-Day Detector (lightweight, load in parallel)
  setTimeout(() => {
    PatternDetector.initializeZeroDay().catch(err => {
      console.warn('[ML] Zero-Day init failed (non-critical):', err.message);
    });
  }, 3000); // Wait 3 seconds
  
  // Priority 4: LSTM (heavy, load last)
  setTimeout(() => {
    PatternDetector.initializeLSTM().catch(err => {
      console.warn('[ML] LSTM init failed (non-critical):', err.message);
    });
  }, 5000); // Wait 5 seconds (load in background)
  
  // PHASE 4: Initialize P2P Network (6 seconds)
  setTimeout(() => {
    p2pThreatNetwork.initialize().then(result => {
      if (result.success) {
        console.log('[Phase 4] P2P Network initialized:', result.peerId);
      }
    }).catch(err => {
      console.warn('[Phase 4] P2P init failed (non-critical):', err.message);
    });
  }, 6000);
  
  // PHASE 4: Initialize Distributed Threat DB (7 seconds)
  setTimeout(() => {
    distributedThreatDB.initialize().then(result => {
      if (result.success) {
        console.log('[Phase 4] Distributed Threat DB initialized');
      }
    }).catch(err => {
      console.warn('[Phase 4] Distributed DB init failed (non-critical):', err.message);
    });
  }, 7000);
  
  // PHASE 4: Initialize Graph Neural Network (8 seconds)
  setTimeout(() => {
    const gnn = new GraphNeuralNetwork();
    gnn.initialize().then(result => {
      if (result.success) {
        console.log('[Phase 4] Graph Neural Network initialized');
      }
    }).catch(err => {
      console.warn('[Phase 4] GNN init failed (non-critical):', err.message);
    });
  }, 8000);
  
  // PHASE 5: Initialize Telemetry System (9 seconds)
  setTimeout(() => {
    const telemetry = new TelemetrySystem();
    telemetry.initialize().then(result => {
      if (result.success) {
        console.log('[Phase 5] Telemetry System initialized');
        
        // Record system startup
        telemetry.recordEvent('system', 'startup', {
          version: '1.0.0',
          timestamp: Date.now()
        });
      }
    }).catch(err => {
      console.warn('[Phase 5] Telemetry init failed (non-critical):', err.message);
    });
  }, 9000);
  
  // PHASE 5: Initialize Production Manager (10 seconds)
  setTimeout(() => {
    const productionManager = new ProductionManager();
    productionManager.initialize().then(result => {
      if (result.success) {
        console.log('[Phase 5] Production Manager initialized');
        
        // Register initial model version
        productionManager.modelVersioning.registerVersion('phishing-detector', '1.0.0', {
          accuracy: 0.95,
          precision: 0.93,
          recall: 0.94,
          f1Score: 0.935,
          trainingDate: Date.now()
        });
        
        // Activate version
        productionManager.modelVersioning.activateVersion('phishing-detector', '1.0.0');
      }
    }).catch(err => {
      console.warn('[Phase 5] Production Manager init failed (non-critical):', err.message);
    });
  }, 10000);
  
  // PHASE 5: Initialize Behavioral Biometrics (11 seconds) - Content script will handle actual monitoring
  setTimeout(() => {
    console.log('[Phase 5] Behavioral Biometrics ready (will initialize in content scripts)');
  }, 11000);
}, 500); // Start faster (500ms instead of 1000ms)

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('Extension installed/updated:', details.reason);
  
  if (details.reason === 'install') {
    // Set default settings
    await StorageManager.saveSettings({});
    console.log('Default settings initialized');
    
    // CRITICAL FIX #1: Immediately download database on first install
    console.log('[Install] Starting immediate PhishTank database download...');
    
    // Show user notification that setup is in progress
    try {
      await chrome.notifications.create('setup-in-progress', {
        type: 'basic',
        iconUrl: '/icons/icon48.png',
        title: '🛡️ Anti-Phishing Guardian',
        message: 'Setting up protection... Downloading threat database.',
        priority: 2
      });
    } catch (notifError) {
      console.warn('[Install] Could not show setup notification:', notifError);
    }
    
    // Download database immediately (don't wait for schedule)
    const downloadResult = await ThreatIntelligence.updatePhishTankDatabase();
    
    if (downloadResult.success) {
      console.log(`[Install] ✓ Database ready: ${downloadResult.count} threats loaded`);
      
      // Show success notification
      try {
        await chrome.notifications.clear('setup-in-progress');
        await chrome.notifications.create('setup-complete', {
          type: 'basic',
          iconUrl: '/icons/icon48.png',
          title: '✅ Protection Active',
          message: `Ready! Monitoring ${downloadResult.count.toLocaleString()} known phishing threats.`,
          priority: 1
        });
        
        // Auto-clear success notification after 5 seconds
        setTimeout(() => {
          chrome.notifications.clear('setup-complete');
        }, 5000);
      } catch (notifError) {
        console.warn('[Install] Could not show success notification:', notifError);
      }
    } else {
      console.error('[Install] ✗ Database download failed:', downloadResult.error);
      
      // Show error notification
      try {
        await chrome.notifications.clear('setup-in-progress');
        await chrome.notifications.create('setup-failed', {
          type: 'basic',
          iconUrl: '/icons/icon48.png',
          title: '⚠️ Setup Issue',
          message: 'Using fallback protection. Check your internet connection.',
          priority: 2
        });
      } catch (notifError) {
        console.warn('[Install] Could not show error notification:', notifError);
      }
    }
    
    // Schedule automatic updates for future
    ThreatIntelligence.scheduleAutomaticUpdates();
    
    // AUTOMATIC ML TRAINING: Train model in background on first install
    console.log('[ML Training] Starting automatic model training...');
    setTimeout(async () => {
      try {
        // Initialize training data
        const dataInit = await TrainingDataCollector.initializeTrainingData();
        if (dataInit.success) {
          console.log(`[ML Training] Training data ready: ${dataInit.count} samples`);
          
          // Train model (lightweight: 30 epochs, fast training)
          console.log('[ML Training] Training neural network...');
          const trainingResult = await ModelTrainer.trainModel({
            epochs: 30,
            batchSize: 16,
            learningRate: 0.001
          });
          
          if (trainingResult.success) {
            const acc = (trainingResult.evaluation.finalAccuracy * 100).toFixed(1);
            console.log(`[ML Training] ✓ Model trained successfully! Accuracy: ${acc}%`);
            
            // Save training metadata
            await ModelTrainer.saveTrainingMetadata(trainingResult);
            
            // Show notification to user
            try {
              await chrome.notifications.create('ml-trained', {
                type: 'basic',
                iconUrl: '/icons/icon48.png',
                title: '🤖 AI Model Trained',
                message: `Neural network ready! Detection accuracy: ${acc}%`,
                priority: 1
              });
              
              setTimeout(() => chrome.notifications.clear('ml-trained'), 5000);
            } catch (notifError) {
              console.warn('[ML Training] Could not show training notification:', notifError);
            }
          } else {
            console.warn('[ML Training] Training failed:', trainingResult.error);
            console.log('[ML Training] Falling back to heuristic detection');
          }
        }
      } catch (trainingError) {
        console.warn('[ML Training] Training error (non-critical):', trainingError.message);
        console.log('[ML Training] Extension will use heuristic detection');
      }
    }, 5000); // Start training 5 seconds after install (let other setup complete first)
  }
  
  // On update, check if database needs refresh
  if (details.reason === 'update') {
    console.log('[Update] Checking database status...');
    const stats = await ThreatIntelligence.getDatabaseStats();
    
    if (!stats.exists || stats.needsUpdate) {
      console.log('[Update] Database needs refresh, updating...');
      ThreatIntelligence.updatePhishTankDatabase();
    } else {
      console.log('[Update] Database is current');
    }
  }
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

// CRITICAL FIX #2: Service Worker Error Recovery and Health Monitoring
let serviceWorkerHealthy = true;
let lastHealthCheck = Date.now();
let consecutiveErrors = 0;
const MAX_CONSECUTIVE_ERRORS = 5;

/**
 * Monitor service worker health
 */
function monitorServiceWorkerHealth() {
  const now = Date.now();
  const timeSinceLastCheck = now - lastHealthCheck;
  
  // If more than 5 minutes since last health check, something is wrong
  if (timeSinceLastCheck > 300000) {
    console.error('[Service Worker] Health check timeout - worker may be inactive');
    serviceWorkerHealthy = false;
    attemptRecovery();
  }
  
  lastHealthCheck = now;
  
  // Reset error counter if we're healthy
  if (serviceWorkerHealthy && consecutiveErrors > 0) {
    console.log('[Service Worker] Health restored, resetting error counter');
    consecutiveErrors = 0;
  }
}

/**
 * Attempt to recover from service worker errors
 */
async function attemptRecovery() {
  console.log('[Service Worker] Attempting recovery...');
  
  try {
    // Re-initialize critical components
    await initializeTensorFlow();
    
    // Verify database exists
    const stats = await ThreatIntelligence.getDatabaseStats();
    if (!stats.exists) {
      console.log('[Recovery] Database missing, re-downloading...');
      await ThreatIntelligence.updatePhishTankDatabase();
    }
    
    // Verify settings exist
    const settings = await StorageManager.getSettings();
    if (!settings) {
      console.log('[Recovery] Settings missing, re-initializing...');
      await StorageManager.saveSettings({});
    }
    
    serviceWorkerHealthy = true;
    consecutiveErrors = 0;
    console.log('[Service Worker] ✓ Recovery successful');
    
  } catch (error) {
    consecutiveErrors++;
    console.error(`[Service Worker] Recovery failed (attempt ${consecutiveErrors}/${MAX_CONSECUTIVE_ERRORS}):`, error);
    
    if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
      console.error('[Service Worker] CRITICAL: Max recovery attempts reached');
      
      // Show critical error notification to user
      try {
        await chrome.notifications.create('critical-error', {
          type: 'basic',
          iconUrl: '/icons/icon48.png',
          title: '🚨 Protection Error',
          message: 'Extension needs attention. Please reload the extension or restart your browser.',
          priority: 2,
          requireInteraction: true
        });
      } catch (notifError) {
        console.error('[Service Worker] Could not show critical error notification:', notifError);
      }
    }
  }
}

// Keep service worker alive with periodic tasks
chrome.runtime.onStartup.addListener(() => {
  console.log('Extension started');
  console.log('Service worker started, alarms will trigger updates as scheduled');
  
  // CRITICAL FIX #2: Perform health check on startup
  monitorServiceWorkerHealth();
});

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
    
    // Perform health check
    monitorServiceWorkerHealth();
    
    // Check database health periodically
    ThreatIntelligence.getDatabaseStats().then(stats => {
      if (stats.exists && stats.needsUpdate) {
        console.log('[Service Worker] Database needs update, triggering refresh');
        ThreatIntelligence.updatePhishTankDatabase();
      }
    }).catch(err => {
      console.error('[Service Worker] Health check failed:', err);
      consecutiveErrors++;
      if (consecutiveErrors >= 3) {
        attemptRecovery();
      }
    });
  }
});

// Initialize keep-alive on service worker activation
setupKeepAlive();

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

console.log('[Service Worker] Initialization complete - Ready to process requests');
