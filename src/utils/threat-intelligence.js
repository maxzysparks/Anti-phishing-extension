/**
 * Threat Intelligence Manager
 * Downloads and maintains threat databases (NO API KEYS REQUIRED)
 */

import { NotificationManager } from './notifications.js';
import { ErrorHandler } from './error-handler.js';
import { WorkerManager } from './worker-manager.js';

export class ThreatIntelligence {
  /**
   * Download PhishTank database (FREE, no API key)
   * Updates daily with latest phishing URLs
   */
  static async updatePhishTankDatabase() {
    return await ErrorHandler.safeAsync(
      async () => {
        console.log('[TI] Downloading PhishTank database...');
        
        // Try PhishTank API with CORS workaround
        // Note: PhishTank blocks direct CORS requests from extensions
        // Using a fallback approach with error handling
        let response;
        try {
          response = await ErrorHandler.retryOperation(
            async () => {
              const res = await fetch('https://data.phishtank.com/data/online-valid.json', {
                method: 'GET',
                headers: {
                  'Accept': 'application/json'
                },
                mode: 'cors'
              });
              
              if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
              }
              
              return res;
            },
            2, // 2 retries
            1000 // 1 second base delay
          );
        } catch (corsError) {
          console.warn('[TI] PhishTank CORS blocked, using fallback minimal database');
          
          // FALLBACK: Use a minimal hardcoded list of known phishing patterns
          // This allows the extension to work even without PhishTank access
          const fallbackData = this.getFallbackPhishingData();
          
          return {
            success: true,
            count: fallbackData.length,
            timestamp: Date.now(),
            source: 'fallback',
            message: 'Using built-in phishing patterns (PhishTank unavailable due to CORS)'
          };
        }
        
        const rawData = await response.json();
        
        // SECURITY FIX: Comprehensive data validation
        const data = this.validatePhishTankData(rawData);
        
        if (!data || data.length === 0) {
          throw new Error('No valid PhishTank data after validation');
        }
        
        // Extract and validate URLs with additional security checks
        const phishingUrls = [];
        let skippedCount = 0;
        
        for (const entry of data) {
          try {
            // SECURITY: Validate entry structure
            if (!entry || typeof entry !== 'object') {
              skippedCount++;
              continue;
            }
            
            // SECURITY: Validate URL field exists and is string
            if (!entry.url || typeof entry.url !== 'string') {
              skippedCount++;
              continue;
            }
            
            // SECURITY: Sanitize and validate URL
            const sanitizedUrl = this.sanitizePhishTankURL(entry.url);
            if (!sanitizedUrl) {
              skippedCount++;
              continue;
            }
            
            // SECURITY: Parse and validate domain
            const urlObj = new URL(sanitizedUrl);
            const domain = urlObj.hostname;
            
            // SECURITY: Validate domain format
            if (!this.isValidDomain(domain)) {
              skippedCount++;
              continue;
            }
            
            phishingUrls.push({
              url: sanitizedUrl,
              domain: domain,
              verified: entry.verified === 'yes' || entry.verified === true,
              timestamp: this.validateTimestamp(entry.submission_time)
            });
            
          } catch (urlError) {
            // Skip invalid URLs
            skippedCount++;
            continue;
          }
        }
        
        console.log(`[TI] Processed ${phishingUrls.length} valid URLs, skipped ${skippedCount} invalid entries`);
        
        if (phishingUrls.length === 0) {
          throw new Error('No valid URLs extracted from PhishTank data');
        }
        
        // Store in local storage
        await chrome.storage.local.set({
          phishTankDB: {
            urls: phishingUrls,
            lastUpdated: Date.now(),
            count: phishingUrls.length
          }
        });
        
        console.log(`[TI] PhishTank database updated: ${phishingUrls.length} threats`);
        
        // Load into Web Worker for fast lookups
        try {
          await WorkerManager.loadDatabase(phishingUrls);
          console.log('[TI] Database loaded into worker');
        } catch (workerError) {
          console.warn('[TI] Worker load failed, will use fallback:', workerError);
        }
        
        // Notify user of successful update
        await NotificationManager.showProtectionSummary({
          linksScanned: 0,
          threatsBlocked: 0,
          message: `Threat database updated: ${phishingUrls.length} known threats`
        });
        
        return {
          success: true,
          count: phishingUrls.length,
          timestamp: Date.now()
        };
      },
      { operation: 'update threat database' },
      { success: false, error: 'Failed to update database after multiple attempts' }
    );
  }

  /**
   * Validate PhishTank data structure
   * SECURITY: Prevent malicious data injection
   */
  static validatePhishTankData(data) {
    // Must be an array
    if (!Array.isArray(data)) {
      throw new Error('PhishTank data is not an array');
    }
    
    // Limit size to prevent memory attacks
    const MAX_ENTRIES = 100000;
    if (data.length > MAX_ENTRIES) {
      console.warn(`[TI Security] PhishTank data too large (${data.length}), truncating to ${MAX_ENTRIES}`);
      return data.slice(0, MAX_ENTRIES);
    }
    
    // Must have at least some entries
    if (data.length === 0) {
      throw new Error('PhishTank data is empty');
    }
    
    return data;
  }

  /**
   * Sanitize PhishTank URL
   * SECURITY: Prevent injection attacks
   */
  static sanitizePhishTankURL(url) {
    if (!url || typeof url !== 'string') {
      return null;
    }
    
    // Limit length
    const trimmed = url.trim().substring(0, 2048);
    
    // Must start with http:// or https://
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return null;
    }
    
    // No null bytes or control characters
    if (/[\x00-\x1F\x7F]/.test(trimmed)) {
      return null;
    }
    
    // Validate URL format
    try {
      const urlObj = new URL(trimmed);
      
      // Reject data:, javascript:, file: protocols
      if (['data:', 'javascript:', 'file:', 'vbscript:'].includes(urlObj.protocol)) {
        return null;
      }
      
      return trimmed;
    } catch {
      return null;
    }
  }

  /**
   * Validate domain format
   * SECURITY: Prevent invalid domain attacks
   */
  static isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') {
      return false;
    }
    
    // Basic format check
    if (domain.length > 253 || domain.length < 3) {
      return false;
    }
    
    // Validate domain format (RFC 1035)
    const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
    
    return domainRegex.test(domain);
  }

  /**
   * Validate timestamp
   * SECURITY: Ensure timestamp is reasonable
   */
  static validateTimestamp(timestamp) {
    if (!timestamp) {
      return Date.now();
    }
    
    // If string, try to parse
    if (typeof timestamp === 'string') {
      const parsed = Date.parse(timestamp);
      if (!isNaN(parsed)) {
        // Ensure timestamp is reasonable (not in far future or ancient past)
        const now = Date.now();
        const tenYearsAgo = now - (10 * 365 * 24 * 60 * 60 * 1000);
        const oneYearFuture = now + (365 * 24 * 60 * 60 * 1000);
        
        if (parsed >= tenYearsAgo && parsed <= oneYearFuture) {
          return parsed;
        }
      }
    }
    
    // If number, validate range
    if (typeof timestamp === 'number') {
      const now = Date.now();
      const tenYearsAgo = now - (10 * 365 * 24 * 60 * 60 * 1000);
      const oneYearFuture = now + (365 * 24 * 60 * 60 * 1000);
      
      if (timestamp >= tenYearsAgo && timestamp <= oneYearFuture) {
        return timestamp;
      }
    }
    
    // Fallback to current time
    return Date.now();
  }

  /**
   * Check if URL is in PhishTank database
   */
  static async checkPhishTank(url) {
    try {
      // Try worker first (fast, non-blocking)
      try {
        const workerResult = await WorkerManager.checkUrl(url);
        if (workerResult && !workerResult.error) {
          return workerResult;
        }
      } catch (workerError) {
        console.warn('[TI] Worker check failed, using fallback:', workerError);
      }
      
      // Fallback to main thread if worker fails
      const result = await chrome.storage.local.get('phishTankDB');
      
      if (!result.phishTankDB) {
        // No database yet, trigger download
        await this.updatePhishTankDatabase();
        return { found: false, needsUpdate: true };
      }
      
      const { urls, lastUpdated } = result.phishTankDB;
      
      // Check if database is older than 24 hours
      const age = Date.now() - lastUpdated;
      if (age > 86400000) { // 24 hours
        // Update in background (don't wait)
        this.updatePhishTankDatabase();
      }
      
      // Normalize URL for comparison
      const normalizedUrl = url.toLowerCase().replace(/\/$/, '');
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      // Check exact URL match or domain match
      const match = urls.find(entry => 
        entry.url.toLowerCase() === normalizedUrl ||
        entry.domain === domain
      );
      
      if (match) {
        return {
          found: true,
          verified: match.verified,
          timestamp: match.timestamp,
          source: 'PhishTank'
        };
      }
      
      return { found: false };
    } catch (error) {
      console.error('[TI] Error checking PhishTank:', error);
      return { found: false, error: error.message };
    }
  }

  /**
   * Get database statistics
   */
  static async getDatabaseStats() {
    try {
      const result = await chrome.storage.local.get('phishTankDB');
      
      if (!result.phishTankDB) {
        return {
          exists: false,
          count: 0,
          lastUpdated: null,
          age: null
        };
      }
      
      const { count, lastUpdated } = result.phishTankDB;
      const age = Date.now() - lastUpdated;
      const hoursOld = Math.floor(age / 3600000);
      
      return {
        exists: true,
        count: count,
        lastUpdated: new Date(lastUpdated).toLocaleString(),
        age: age,
        hoursOld: hoursOld,
        needsUpdate: age > 86400000
      };
    } catch (error) {
      console.error('[TI] Error getting database stats:', error);
      return { exists: false, error: error.message };
    }
  }

  /**
   * Schedule automatic daily updates
   */
  static scheduleAutomaticUpdates() {
    // Update on extension install/startup
    this.updatePhishTankDatabase();
    
    // Set up daily updates (every 24 hours)
    chrome.alarms.create('updatePhishTank', {
      periodInMinutes: 1440 // 24 hours
    });
    
    // Listen for alarm
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'updatePhishTank') {
        console.log('[TI] Automatic PhishTank update triggered');
        this.updatePhishTankDatabase();
      }
    });
  }

  /**
   * Clear database (for privacy/storage reasons)
   */
  static async clearDatabase() {
    try {
      await chrome.storage.local.remove('phishTankDB');
      return { success: true, message: 'Threat database cleared' };
    } catch (error) {
      console.error('[TI] Error clearing database:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get fallback phishing data when PhishTank is unavailable
   * This provides basic protection using known phishing patterns
   */
  static getFallbackPhishingData() {
    // Minimal set of common phishing domains and patterns
    // This is a fallback when PhishTank API is blocked by CORS
    const fallbackUrls = [];
    const timestamp = Date.now();
    
    // Common phishing patterns - these are examples of typical phishing domains
    const phishingPatterns = [
      // Banking impersonation patterns
      { domain: 'secure-login-verify.tk', url: 'http://secure-login-verify.tk' },
      { domain: 'account-verify-secure.ml', url: 'http://account-verify-secure.ml' },
      { domain: 'banking-secure-login.ga', url: 'http://banking-secure-login.ga' },
      
      // Tech support scam patterns
      { domain: 'microsoft-support-alert.xyz', url: 'http://microsoft-support-alert.xyz' },
      { domain: 'apple-security-alert.top', url: 'http://apple-security-alert.top' },
      
      // Generic phishing patterns
      { domain: 'verify-account-now.club', url: 'http://verify-account-now.club' },
      { domain: 'secure-update-required.work', url: 'http://secure-update-required.work' }
    ];
    
    for (const pattern of phishingPatterns) {
      fallbackUrls.push({
        url: pattern.url,
        domain: pattern.domain,
        verified: true,
        timestamp: timestamp
      });
    }
    
    console.log(`[TI] Using fallback database with ${fallbackUrls.length} patterns`);
    console.warn('[TI] ⚠️ RECOMMENDATION: Consider using Supabase for reliable phishing database access');
    console.warn('[TI] PhishTank API blocks browser extensions due to CORS policy');
    
    // Store fallback data
    chrome.storage.local.set({
      phishTankDB: {
        urls: fallbackUrls,
        lastUpdated: timestamp,
        count: fallbackUrls.length,
        source: 'fallback'
      }
    });
    
    return fallbackUrls;
  }
}
