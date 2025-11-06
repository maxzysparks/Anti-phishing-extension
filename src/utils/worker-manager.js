/**
 * Worker Manager
 * Manages Web Worker for PhishTank database lookups
 * NOTE: Web Workers are NOT available in service workers (Manifest V3)
 * This class provides fallback functionality using in-memory database
 */

export class WorkerManager {
  static worker = null;
  static isReady = false;
  static pendingCallbacks = new Map();
  static callbackId = 0;
  static inMemoryDatabase = [];

  /**
   * Initialize the worker
   * FIXED: Web Workers don't work in service workers, use in-memory fallback
   */
  static async initialize() {
    if (this.isReady) {
      return; // Already initialized
    }

    try {
      // CRITICAL FIX: Cannot use Web Workers in service workers (Manifest V3)
      // Using in-memory database instead
      console.log('[Worker] Using in-memory database (Web Workers not available in service workers)');
      this.isReady = true;
      
    } catch (error) {
      console.error('[Worker] Failed to initialize:', error);
      throw error;
    }
  }

  /**
   * Wait for worker to be ready
   * FIXED: No actual worker, just mark as ready
   */
  static waitForReady() {
    return Promise.resolve();
  }

  /**
   * Load database into worker
   * FIXED: Load into in-memory database instead
   */
  static async loadDatabase(urls) {
    if (!this.isReady) {
      await this.initialize();
    }

    try {
      // Store in memory
      this.inMemoryDatabase = urls || [];
      console.log(`[Worker] Database loaded in memory: ${this.inMemoryDatabase.length} threats`);
      
      return {
        success: true,
        count: this.inMemoryDatabase.length
      };
    } catch (error) {
      console.error('[Worker] Failed to load database:', error);
      throw error;
    }
  }

  /**
   * Check URL using worker
   * FIXED: Check using in-memory database
   */
  static async checkUrl(url) {
    if (!this.isReady) {
      await this.initialize();
    }

    try {
      // Normalize URL for comparison
      const normalizedUrl = url.toLowerCase().replace(/\/$/, '');
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      // Check exact URL match or domain match
      const match = this.inMemoryDatabase.find(entry => 
        entry.url.toLowerCase() === normalizedUrl ||
        entry.domain === domain
      );
      
      if (match) {
        return {
          found: true,
          verified: match.verified,
          timestamp: match.timestamp,
          source: 'InMemory'
        };
      }
      
      return { found: false };
    } catch (error) {
      console.error('[Worker] Error checking URL:', error);
      return { found: false, error: error.message };
    }
  }

  /**
   * Check multiple URLs
   * FIXED: Check using in-memory database
   */
  static async checkBatch(urls) {
    if (!this.isReady) {
      await this.initialize();
    }

    try {
      const results = [];
      
      for (const url of urls) {
        const result = await this.checkUrl(url);
        results.push({ url, result });
      }
      
      return results;
    } catch (error) {
      console.error('[Worker] Error checking batch:', error);
      return urls.map(url => ({ url, result: { found: false } }));
    }
  }

  /**
   * Handle messages from worker
   * FIXED: No longer needed as we don't use Web Workers
   */
  static handleMessage(event) {
    // Not used in in-memory implementation
    console.log('[Worker] Message handling not needed for in-memory database');
  }

  /**
   * Terminate worker
   * FIXED: Clear in-memory database
   */
  static terminate() {
    this.inMemoryDatabase = [];
    this.isReady = false;
    this.pendingCallbacks.clear();
    console.log('[Worker] In-memory database cleared');
  }
}
