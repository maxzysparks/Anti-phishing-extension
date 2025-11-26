import { STORAGE_KEYS, DEFAULT_SETTINGS, CACHE_DURATION } from './constants.js';

/**
 * Storage helper for Chrome extension storage API
 */
export class StorageManager {
  /**
   * Get settings from storage
   */
  static async getSettings() {
    try {
      const result = await chrome.storage.sync.get(STORAGE_KEYS.SETTINGS);
      return result[STORAGE_KEYS.SETTINGS] || DEFAULT_SETTINGS;
    } catch (error) {
      console.error('Error getting settings:', error);
      return DEFAULT_SETTINGS;
    }
  }

  /**
   * Save settings to storage
   */
  static async saveSettings(settings) {
    try {
      await chrome.storage.sync.set({
        [STORAGE_KEYS.SETTINGS]: { ...DEFAULT_SETTINGS, ...settings }
      });
      return true;
    } catch (error) {
      console.error('Error saving settings:', error);
      return false;
    }
  }

  /**
   * Get whitelist from storage
   */
  static async getWhitelist() {
    try {
      const result = await chrome.storage.sync.get(STORAGE_KEYS.WHITELIST);
      return result[STORAGE_KEYS.WHITELIST] || [];
    } catch (error) {
      console.error('Error getting whitelist:', error);
      return [];
    }
  }

  /**
   * Add domain to whitelist
   */
  static async addToWhitelist(domain) {
    try {
      const whitelist = await this.getWhitelist();
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.sync.set({ [STORAGE_KEYS.WHITELIST]: whitelist });
      }
      return true;
    } catch (error) {
      console.error('Error adding to whitelist:', error);
      return false;
    }
  }

  /**
   * Remove domain from whitelist
   */
  static async removeFromWhitelist(domain) {
    try {
      const whitelist = await this.getWhitelist();
      const filtered = whitelist.filter(d => d !== domain);
      await chrome.storage.sync.set({ [STORAGE_KEYS.WHITELIST]: filtered });
      return true;
    } catch (error) {
      console.error('Error removing from whitelist:', error);
      return false;
    }
  }

  /**
   * Check if domain is whitelisted
   */
  static async isWhitelisted(domain) {
    const whitelist = await this.getWhitelist();
    return whitelist.some(d => domain.includes(d) || d.includes(domain));
  }

  /**
   * Get blacklist from storage
   */
  static async getBlacklist() {
    try {
      const result = await chrome.storage.sync.get(STORAGE_KEYS.BLACKLIST);
      return result[STORAGE_KEYS.BLACKLIST] || [];
    } catch (error) {
      console.error('Error getting blacklist:', error);
      return [];
    }
  }

  /**
   * Add domain to blacklist
   */
  static async addToBlacklist(domain) {
    try {
      const blacklist = await this.getBlacklist();
      if (!blacklist.includes(domain)) {
        blacklist.push(domain);
        await chrome.storage.sync.set({ [STORAGE_KEYS.BLACKLIST]: blacklist });
      }
      return true;
    } catch (error) {
      console.error('Error adding to blacklist:', error);
      return false;
    }
  }

  /**
   * Remove domain from blacklist
   */
  static async removeFromBlacklist(domain) {
    try {
      const blacklist = await this.getBlacklist();
      const filtered = blacklist.filter(d => d !== domain);
      await chrome.storage.sync.set({ [STORAGE_KEYS.BLACKLIST]: filtered });
      return true;
    } catch (error) {
      console.error('Error removing from blacklist:', error);
      return false;
    }
  }

  /**
   * Check if domain is blacklisted
   */
  static async isBlacklisted(domain) {
    const blacklist = await this.getBlacklist();
    return blacklist.some(d => domain.includes(d) || d.includes(domain));
  }

  /**
   * Get cached threat analysis for a URL
   */
  static async getCachedThreat(url) {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.CACHE);
      const cache = result[STORAGE_KEYS.CACHE] || {};
      
      const cached = cache[url];
      if (!cached) return null;

      // Check if cache is expired
      const now = Date.now();
      const age = now - cached.timestamp;
      const maxAge = CACHE_DURATION[cached.threatLevel.toUpperCase()] || CACHE_DURATION.SUSPICIOUS;

      if (age > maxAge) {
        // Cache expired, remove it
        delete cache[url];
        await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: cache });
        return null;
      }

      return cached;
    } catch (error) {
      console.error('Error getting cached threat:', error);
      return null;
    }
  }

  /**
   * Cache threat analysis for a URL
   * CRITICAL FIX #8: Enhanced with automatic cleanup and memory management
   */
  static async cacheThreat(url, analysis) {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.CACHE);
      const cache = result[STORAGE_KEYS.CACHE] || {};

      cache[url] = {
        ...analysis,
        timestamp: Date.now()
      };

      // CRITICAL FIX #8: Bounded cache with automatic cleanup
      const MAX_CACHE_SIZE = 500; // Reduced from 1000 for better memory management
      const entries = Object.entries(cache);
      
      if (entries.length > MAX_CACHE_SIZE) {
        console.log(`[Storage] Cache size (${entries.length}) exceeds limit, cleaning up...`);
        
        // Remove expired entries first
        const now = Date.now();
        const validEntries = entries.filter(([_, data]) => {
          const age = now - data.timestamp;
          const maxAge = CACHE_DURATION[data.threatLevel?.toUpperCase()] || CACHE_DURATION.SUSPICIOUS;
          return age < maxAge;
        });
        
        // If still too large, keep only most recent entries
        if (validEntries.length > MAX_CACHE_SIZE) {
          validEntries.sort((a, b) => b[1].timestamp - a[1].timestamp);
          const toKeep = validEntries.slice(0, MAX_CACHE_SIZE);
          const newCache = Object.fromEntries(toKeep);
          await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: newCache });
          console.log(`[Storage] Cache cleaned: ${entries.length} → ${toKeep.length} entries`);
        } else {
          const newCache = Object.fromEntries(validEntries);
          await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: newCache });
          console.log(`[Storage] Expired entries removed: ${entries.length} → ${validEntries.length} entries`);
        }
      } else {
        await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: cache });
      }

      return true;
    } catch (error) {
      console.error('Error caching threat:', error);
      return false;
    }
  }

  /**
   * Perform periodic cache cleanup
   * CRITICAL FIX #8: Removes expired entries to prevent memory leaks
   */
  static async cleanupCache() {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.CACHE);
      const cache = result[STORAGE_KEYS.CACHE] || {};
      
      const now = Date.now();
      const entries = Object.entries(cache);
      const initialCount = entries.length;
      
      // Remove expired entries
      const validEntries = entries.filter(([_, data]) => {
        const age = now - data.timestamp;
        const maxAge = CACHE_DURATION[data.threatLevel?.toUpperCase()] || CACHE_DURATION.SUSPICIOUS;
        return age < maxAge;
      });
      
      if (validEntries.length < initialCount) {
        const newCache = Object.fromEntries(validEntries);
        await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: newCache });
        console.log(`[Storage] Cache cleanup: ${initialCount} → ${validEntries.length} entries`);
        return { cleaned: initialCount - validEntries.length, remaining: validEntries.length };
      }
      
      return { cleaned: 0, remaining: initialCount };
    } catch (error) {
      console.error('Error cleaning cache:', error);
      return { cleaned: 0, remaining: 0, error: error.message };
    }
  }

  /**
   * Get cache statistics
   * CRITICAL FIX #8: Monitor cache health
   */
  static async getCacheStats() {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.CACHE);
      const cache = result[STORAGE_KEYS.CACHE] || {};
      
      const entries = Object.entries(cache);
      const now = Date.now();
      
      let expired = 0;
      let byThreatLevel = { safe: 0, suspicious: 0, dangerous: 0, unknown: 0 };
      
      entries.forEach(([_, data]) => {
        const age = now - data.timestamp;
        const maxAge = CACHE_DURATION[data.threatLevel?.toUpperCase()] || CACHE_DURATION.SUSPICIOUS;
        
        if (age > maxAge) {
          expired++;
        }
        
        const level = data.threatLevel?.toLowerCase() || 'unknown';
        byThreatLevel[level] = (byThreatLevel[level] || 0) + 1;
      });
      
      return {
        total: entries.length,
        expired: expired,
        valid: entries.length - expired,
        byThreatLevel: byThreatLevel
      };
    } catch (error) {
      console.error('Error getting cache stats:', error);
      return { total: 0, expired: 0, valid: 0, byThreatLevel: {} };
    }
  }

  /**
   * Clear all cached threats
   */
  static async clearCache() {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: {} });
      return true;
    } catch (error) {
      console.error('Error clearing cache:', error);
      return false;
    }
  }

  /**
   * Get statistics
   */
  static async getStats() {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.STATS);
      return result[STORAGE_KEYS.STATS] || {
        linksScanned: 0,
        threatsBlocked: 0,
        lastScan: null
      };
    } catch (error) {
      console.error('Error getting stats:', error);
      return { linksScanned: 0, threatsBlocked: 0, lastScan: null };
    }
  }

  /**
   * Update statistics
   */
  static async updateStats(updates) {
    try {
      const stats = await this.getStats();
      const newStats = { ...stats, ...updates };
      await chrome.storage.local.set({ [STORAGE_KEYS.STATS]: newStats });
      return true;
    } catch (error) {
      console.error('Error updating stats:', error);
      return false;
    }
  }

  /**
   * Increment link scan count
   */
  static async incrementScanned() {
    const stats = await this.getStats();
    await this.updateStats({
      linksScanned: stats.linksScanned + 1,
      lastScan: new Date().toISOString()
    });
  }

  /**
   * Increment threat blocked count
   */
  static async incrementBlocked() {
    const stats = await this.getStats();
    await this.updateStats({
      threatsBlocked: stats.threatsBlocked + 1
    });
  }

  /**
   * Reset statistics
   */
  static async resetStats() {
    try {
      await chrome.storage.local.set({
        [STORAGE_KEYS.STATS]: {
          linksScanned: 0,
          threatsBlocked: 0,
          lastScan: null
        }
      });
      return true;
    } catch (error) {
      console.error('Error resetting stats:', error);
      return false;
    }
  }
}
