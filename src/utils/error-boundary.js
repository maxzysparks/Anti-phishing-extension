/**
 * Error Boundary Utility
 * Provides comprehensive error handling and recovery mechanisms
 */

export class ErrorBoundary {
  /**
   * Wrap async function with error handling
   * @param {Function} fn - Async function to wrap
   * @param {Object} options - Error handling options
   * @returns {Function} Wrapped function
   */
  static wrapAsync(fn, options = {}) {
    const {
      fallbackValue = null,
      onError = null,
      retries = 0,
      retryDelay = 1000,
      context = 'operation'
    } = options;

    return async function(...args) {
      let lastError;
      
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          return await fn.apply(this, args);
        } catch (error) {
          lastError = error;
          
          console.error(`[ErrorBoundary] ${context} failed (attempt ${attempt + 1}/${retries + 1}):`, error);
          
          // Call custom error handler if provided
          if (onError) {
            try {
              await onError(error, attempt);
            } catch (handlerError) {
              console.error('[ErrorBoundary] Error handler failed:', handlerError);
            }
          }
          
          // Retry if attempts remaining
          if (attempt < retries) {
            const delay = retryDelay * Math.pow(2, attempt); // Exponential backoff
            console.log(`[ErrorBoundary] Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }
      
      // All retries exhausted
      console.error(`[ErrorBoundary] ${context} failed after ${retries + 1} attempts`);
      
      // Log to storage for debugging
      await this.logError(lastError, context);
      
      return fallbackValue;
    };
  }

  /**
   * Wrap sync function with error handling
   */
  static wrapSync(fn, options = {}) {
    const {
      fallbackValue = null,
      onError = null,
      context = 'operation'
    } = options;

    return function(...args) {
      try {
        return fn.apply(this, args);
      } catch (error) {
        console.error(`[ErrorBoundary] ${context} failed:`, error);
        
        if (onError) {
          try {
            onError(error);
          } catch (handlerError) {
            console.error('[ErrorBoundary] Error handler failed:', handlerError);
          }
        }
        
        // Log synchronously
        this.logErrorSync(error, context);
        
        return fallbackValue;
      }
    };
  }

  /**
   * Log error to storage for debugging
   */
  static async logError(error, context) {
    try {
      const errorLog = {
        timestamp: Date.now(),
        context,
        message: error.message,
        stack: error.stack,
        type: error.name
      };

      const result = await chrome.storage.local.get('errorLogs');
      const logs = result.errorLogs || [];
      
      logs.push(errorLog);
      
      // Keep only last 100 errors
      if (logs.length > 100) {
        logs.shift();
      }
      
      await chrome.storage.local.set({ errorLogs: logs });
    } catch (logError) {
      console.error('[ErrorBoundary] Failed to log error:', logError);
    }
  }

  /**
   * Log error synchronously (best effort)
   */
  static logErrorSync(error, context) {
    try {
      // Store in memory for later persistence
      if (!window._apgErrorQueue) {
        window._apgErrorQueue = [];
      }
      
      window._apgErrorQueue.push({
        timestamp: Date.now(),
        context,
        message: error.message,
        stack: error.stack,
        type: error.name
      });
      
      // Flush queue asynchronously
      setTimeout(() => this.flushErrorQueue(), 0);
    } catch (e) {
      console.error('[ErrorBoundary] Failed to queue error:', e);
    }
  }

  /**
   * Flush error queue to storage
   */
  static async flushErrorQueue() {
    if (!window._apgErrorQueue || window._apgErrorQueue.length === 0) {
      return;
    }

    try {
      const result = await chrome.storage.local.get('errorLogs');
      const logs = result.errorLogs || [];
      
      logs.push(...window._apgErrorQueue);
      window._apgErrorQueue = [];
      
      // Keep only last 100 errors
      while (logs.length > 100) {
        logs.shift();
      }
      
      await chrome.storage.local.set({ errorLogs: logs });
    } catch (error) {
      console.error('[ErrorBoundary] Failed to flush error queue:', error);
    }
  }

  /**
   * Get error logs for debugging
   */
  static async getErrorLogs() {
    try {
      const result = await chrome.storage.local.get('errorLogs');
      return result.errorLogs || [];
    } catch (error) {
      console.error('[ErrorBoundary] Failed to get error logs:', error);
      return [];
    }
  }

  /**
   * Clear error logs
   */
  static async clearErrorLogs() {
    try {
      await chrome.storage.local.remove('errorLogs');
      return { success: true };
    } catch (error) {
      console.error('[ErrorBoundary] Failed to clear error logs:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Create a safe version of chrome.runtime.sendMessage with timeout
   */
  static async sendMessageSafe(message, options = {}) {
    const { timeout = 5000, fallbackValue = null } = options;

    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        console.warn('[ErrorBoundary] Message timeout:', message.action);
        resolve(fallbackValue);
      }, timeout);

      try {
        chrome.runtime.sendMessage(message, (response) => {
          clearTimeout(timeoutId);
          
          if (chrome.runtime.lastError) {
            console.error('[ErrorBoundary] Message error:', chrome.runtime.lastError);
            resolve(fallbackValue);
          } else {
            resolve(response);
          }
        });
      } catch (error) {
        clearTimeout(timeoutId);
        console.error('[ErrorBoundary] Failed to send message:', error);
        resolve(fallbackValue);
      }
    });
  }

  /**
   * Monitor storage quota
   */
  static async checkStorageQuota() {
    try {
      if (navigator.storage && navigator.storage.estimate) {
        const estimate = await navigator.storage.estimate();
        const percentUsed = (estimate.usage / estimate.quota) * 100;
        
        return {
          usage: estimate.usage,
          quota: estimate.quota,
          percentUsed: percentUsed.toFixed(2),
          available: estimate.quota - estimate.usage,
          warning: percentUsed > 80,
          critical: percentUsed > 95
        };
      }
      
      return { available: true, warning: false, critical: false };
    } catch (error) {
      console.error('[ErrorBoundary] Failed to check storage quota:', error);
      return { available: true, warning: false, critical: false };
    }
  }

  /**
   * Health check for extension
   */
  static async performHealthCheck() {
    const health = {
      timestamp: Date.now(),
      status: 'healthy',
      checks: {}
    };

    // Check storage
    try {
      await chrome.storage.local.get('test');
      health.checks.storage = { status: 'ok' };
    } catch (error) {
      health.checks.storage = { status: 'error', error: error.message };
      health.status = 'degraded';
    }

    // Check storage quota
    const quota = await this.checkStorageQuota();
    health.checks.quota = quota;
    if (quota.critical) {
      health.status = 'critical';
    } else if (quota.warning) {
      health.status = 'degraded';
    }

    // Check permissions
    try {
      const hasPermissions = await chrome.permissions.contains({
        permissions: ['storage', 'notifications']
      });
      health.checks.permissions = { status: hasPermissions ? 'ok' : 'missing' };
      if (!hasPermissions) {
        health.status = 'degraded';
      }
    } catch (error) {
      health.checks.permissions = { status: 'error', error: error.message };
      health.status = 'degraded';
    }

    // Check database
    try {
      const result = await chrome.storage.local.get('phishTankDB');
      health.checks.database = {
        status: result.phishTankDB ? 'ok' : 'missing',
        count: result.phishTankDB?.count || 0
      };
      if (!result.phishTankDB) {
        health.status = 'degraded';
      }
    } catch (error) {
      health.checks.database = { status: 'error', error: error.message };
      health.status = 'degraded';
    }

    return health;
  }
}

// Initialize error queue
if (typeof window !== 'undefined') {
  window._apgErrorQueue = [];
}
