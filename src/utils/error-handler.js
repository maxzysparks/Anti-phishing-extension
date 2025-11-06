/**
 * Centralized Error Handler
 * User-friendly error messages, logging, and recovery
 */

export class ErrorHandler {
  /**
   * Handle and log errors with context
   */
  static async handle(error, context = {}) {
    const errorInfo = {
      message: error.message || 'Unknown error',
      stack: error.stack,
      timestamp: new Date().toISOString(),
      context: context,
      userAgent: navigator.userAgent,
      extensionVersion: chrome.runtime.getManifest().version
    };

    // Log to console with full details
    console.error('[APG Error]', errorInfo);

    // Store error for debugging
    await this.logError(errorInfo);

    // Return user-friendly message
    return this.getUserFriendlyMessage(error, context);
  }

  /**
   * Get user-friendly error message
   */
  static getUserFriendlyMessage(error, context) {
    const errorType = context.operation || 'operation';
    
    // Network errors
    if (error.message.includes('fetch') || error.message.includes('network')) {
      return {
        title: 'Connection Error',
        message: `Unable to ${errorType}. Please check your internet connection and try again.`,
        action: 'Retry',
        severity: 'warning'
      };
    }

    // Storage errors
    if (error.message.includes('storage') || error.message.includes('quota')) {
      return {
        title: 'Storage Error',
        message: 'Not enough storage space. Please clear some data or increase storage limit.',
        action: 'Clear Cache',
        severity: 'error'
      };
    }

    // Permission errors
    if (error.message.includes('permission')) {
      return {
        title: 'Permission Required',
        message: `Extension needs additional permissions to ${errorType}. Please grant permissions and try again.`,
        action: 'Grant Permissions',
        severity: 'warning'
      };
    }

    // URL parsing errors
    if (error.message.includes('Invalid URL')) {
      return {
        title: 'Invalid Link',
        message: 'The link format is not recognized. Unable to analyze this URL.',
        action: 'Dismiss',
        severity: 'info'
      };
    }

    // Database errors
    if (context.operation === 'update threat database') {
      return {
        title: 'Database Update Failed',
        message: 'Unable to update threat database. The extension will continue using cached data.',
        action: 'Retry Later',
        severity: 'warning'
      };
    }

    // Generic error
    return {
      title: 'Something Went Wrong',
      message: `Unable to ${errorType}. Please try again. If the problem persists, try restarting the extension.`,
      action: 'Retry',
      severity: 'error'
    };
  }

  /**
   * Log error to storage for debugging
   */
  static async logError(errorInfo) {
    try {
      const result = await chrome.storage.local.get('errorLogs');
      const logs = result.errorLogs || [];
      
      // Add new error
      logs.push(errorInfo);
      
      // Keep only last 50 errors
      if (logs.length > 50) {
        logs.splice(0, logs.length - 50);
      }
      
      await chrome.storage.local.set({ errorLogs: logs });
    } catch (e) {
      // Fallback if even logging fails
      console.error('[APG] Failed to log error:', e);
    }
  }

  /**
   * Get all error logs
   */
  static async getErrorLogs() {
    try {
      const result = await chrome.storage.local.get('errorLogs');
      return result.errorLogs || [];
    } catch (error) {
      console.error('[APG] Failed to get error logs:', error);
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
      console.error('[APG] Failed to clear error logs:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Retry operation with exponential backoff
   */
  static async retryOperation(operation, maxRetries = 3, baseDelay = 1000) {
    let lastError;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        if (attempt < maxRetries - 1) {
          // Exponential backoff: 1s, 2s, 4s
          const delay = baseDelay * Math.pow(2, attempt);
          console.log(`[APG] Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    // All retries failed
    throw lastError;
  }

  /**
   * Safe async operation wrapper
   */
  static async safeAsync(operation, context = {}, fallback = null) {
    try {
      return await operation();
    } catch (error) {
      const userMessage = await this.handle(error, context);
      
      // Show user-friendly notification
      try {
        await chrome.notifications.create({
          type: 'basic',
          iconUrl: '/icons/icon48.png',
          title: userMessage.title,
          message: userMessage.message,
          priority: userMessage.severity === 'error' ? 2 : 1
        });
      } catch (notifError) {
        console.error('[APG] Failed to show error notification:', notifError);
      }
      
      return fallback;
    }
  }

  /**
   * Validate and sanitize URL
   */
  static validateURL(url) {
    try {
      const urlObj = new URL(url);
      
      // Check for valid protocols
      const validProtocols = ['http:', 'https:', 'ftp:', 'mailto:'];
      if (!validProtocols.includes(urlObj.protocol)) {
        throw new Error(`Invalid protocol: ${urlObj.protocol}`);
      }
      
      return { valid: true, url: urlObj.href };
    } catch (error) {
      return {
        valid: false,
        error: 'Invalid URL format',
        message: 'Please enter a valid URL (e.g., https://example.com)'
      };
    }
  }

  /**
   * Check system health
   */
  static async checkHealth() {
    const health = {
      storage: false,
      permissions: false,
      database: false,
      timestamp: Date.now()
    };

    try {
      // Check storage access
      await chrome.storage.local.get('test');
      health.storage = true;
    } catch (e) {
      console.error('[APG Health] Storage check failed:', e);
    }

    try {
      // Check permissions
      const hasPermissions = await chrome.permissions.contains({
        permissions: ['storage', 'notifications', 'alarms']
      });
      health.permissions = hasPermissions;
    } catch (e) {
      console.error('[APG Health] Permissions check failed:', e);
    }

    try {
      // Check database
      const result = await chrome.storage.local.get('phishTankDB');
      health.database = !!result.phishTankDB;
    } catch (e) {
      console.error('[APG Health] Database check failed:', e);
    }

    return health;
  }
}

/**
 * Global error boundary
 */
// Only add window listeners if window is available (not in service worker)
if (typeof window !== 'undefined') {
  window.addEventListener('error', (event) => {
    ErrorHandler.handle(event.error, {
      operation: 'global error',
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno
    });
  });

  window.addEventListener('unhandledrejection', (event) => {
    ErrorHandler.handle(event.reason, {
      operation: 'unhandled promise rejection'
    });
  });
}
