/**
 * Worker Manager
 * Manages Web Worker for PhishTank database lookups
 */

export class WorkerManager {
  static worker = null;
  static isReady = false;
  static pendingCallbacks = new Map();
  static callbackId = 0;

  /**
   * Initialize the worker
   */
  static async initialize() {
    if (this.worker) {
      return; // Already initialized
    }

    try {
      this.worker = new Worker(chrome.runtime.getURL('phishtank-worker.js'));
      
      // Setup message handler
      this.worker.onmessage = (event) => this.handleMessage(event);
      
      this.worker.onerror = (error) => {
        console.error('[Worker] Error:', error);
        this.isReady = false;
      };

      // Wait for ready signal
      await this.waitForReady();
      
      console.log('[Worker] Initialized successfully');
    } catch (error) {
      console.error('[Worker] Failed to initialize:', error);
      throw error;
    }
  }

  /**
   * Wait for worker to be ready
   */
  static waitForReady() {
    return new Promise((resolve) => {
      const checkReady = (event) => {
        if (event.data.action === 'ready') {
          this.isReady = true;
          resolve();
        }
      };
      
      if (this.worker) {
        this.worker.addEventListener('message', checkReady, { once: true });
      } else {
        resolve(); // Fallback if no worker
      }
    });
  }

  /**
   * Load database into worker
   */
  static async loadDatabase(urls) {
    if (!this.worker || !this.isReady) {
      await this.initialize();
    }

    return new Promise((resolve, reject) => {
      const id = this.callbackId++;
      
      this.pendingCallbacks.set(id, { resolve, reject });
      
      this.worker.postMessage({
        id: id,
        action: 'loadDatabase',
        data: { urls }
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pendingCallbacks.has(id)) {
          this.pendingCallbacks.delete(id);
          reject(new Error('Worker timeout'));
        }
      }, 30000);
    });
  }

  /**
   * Check URL using worker
   */
  static async checkUrl(url) {
    if (!this.worker || !this.isReady) {
      // Fallback to non-worker check if worker not available
      return { found: false, error: 'Worker not available' };
    }

    return new Promise((resolve) => {
      const id = this.callbackId++;
      
      this.pendingCallbacks.set(id, { resolve, reject: resolve });
      
      this.worker.postMessage({
        id: id,
        action: 'checkUrl',
        data: { url }
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        if (this.pendingCallbacks.has(id)) {
          this.pendingCallbacks.delete(id);
          resolve({ found: false, error: 'Timeout' });
        }
      }, 5000);
    });
  }

  /**
   * Check multiple URLs
   */
  static async checkBatch(urls) {
    if (!this.worker || !this.isReady) {
      return urls.map(url => ({ url, result: { found: false } }));
    }

    return new Promise((resolve) => {
      const id = this.callbackId++;
      
      this.pendingCallbacks.set(id, { resolve, reject: resolve });
      
      this.worker.postMessage({
        id: id,
        action: 'checkBatch',
        data: { urls }
      });

      // Timeout after 10 seconds
      setTimeout(() => {
        if (this.pendingCallbacks.has(id)) {
          this.pendingCallbacks.delete(id);
          resolve(urls.map(url => ({ url, result: { found: false } })));
        }
      }, 10000);
    });
  }

  /**
   * Handle messages from worker
   */
  static handleMessage(event) {
    const { id, action, data } = event.data;

    // Handle database loaded
    if (action === 'databaseLoaded') {
      console.log(`[Worker] Database loaded: ${data.count} threats`);
      if (this.pendingCallbacks.has(id)) {
        const { resolve } = this.pendingCallbacks.get(id);
        this.pendingCallbacks.delete(id);
        resolve(data);
      }
      return;
    }

    // Handle check result
    if (action === 'checkResult') {
      if (this.pendingCallbacks.has(id)) {
        const { resolve } = this.pendingCallbacks.get(id);
        this.pendingCallbacks.delete(id);
        resolve(data);
      }
      return;
    }

    // Handle batch results
    if (action === 'batchResults') {
      if (this.pendingCallbacks.has(id)) {
        const { resolve } = this.pendingCallbacks.get(id);
        this.pendingCallbacks.delete(id);
        resolve(data);
      }
      return;
    }

    // Handle errors
    if (action === 'error') {
      console.error('[Worker] Error:', data);
      if (this.pendingCallbacks.has(id)) {
        const { reject } = this.pendingCallbacks.get(id);
        this.pendingCallbacks.delete(id);
        reject(new Error(data.message || 'Worker error'));
      }
    }
  }

  /**
   * Terminate worker
   */
  static terminate() {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      this.isReady = false;
      this.pendingCallbacks.clear();
      console.log('[Worker] Terminated');
    }
  }
}
