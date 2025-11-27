/**
 * Performance Monitor
 * CRITICAL FIX #12: Track and report extension performance metrics
 */

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      scanTimes: [],
      analysisCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      mlInferences: 0,
      heuristicFallbacks: 0,
      errors: 0,
      startTime: Date.now()
    };
    
    this.maxScanTimes = 100; // Keep last 100 scan times
  }

  /**
   * Record a link scan time
   */
  recordScanTime(milliseconds) {
    this.metrics.scanTimes.push(milliseconds);
    
    // Keep only last N scan times
    if (this.metrics.scanTimes.length > this.maxScanTimes) {
      this.metrics.scanTimes.shift();
    }
    
    this.metrics.analysisCount++;
    this.saveMetrics();
  }

  /**
   * Record cache hit
   */
  recordCacheHit() {
    this.metrics.cacheHits++;
    this.saveMetrics();
  }

  /**
   * Record cache miss
   */
  recordCacheMiss() {
    this.metrics.cacheMisses++;
    this.saveMetrics();
  }

  /**
   * Record ML inference
   */
  recordMLInference() {
    this.metrics.mlInferences++;
    this.saveMetrics();
  }

  /**
   * Record heuristic fallback
   */
  recordHeuristicFallback() {
    this.metrics.heuristicFallbacks++;
    this.saveMetrics();
  }

  /**
   * Record error
   */
  recordError() {
    this.metrics.errors++;
    this.saveMetrics();
  }

  /**
   * Get performance statistics
   */
  getStats() {
    const scanTimes = this.metrics.scanTimes;
    const avgScanTime = scanTimes.length > 0
      ? scanTimes.reduce((a, b) => a + b, 0) / scanTimes.length
      : 0;
    
    const minScanTime = scanTimes.length > 0
      ? Math.min(...scanTimes)
      : 0;
    
    const maxScanTime = scanTimes.length > 0
      ? Math.max(...scanTimes)
      : 0;
    
    const totalAnalyses = this.metrics.cacheHits + this.metrics.cacheMisses;
    const cacheHitRate = totalAnalyses > 0
      ? (this.metrics.cacheHits / totalAnalyses) * 100
      : 0;
    
    const mlUsageRate = this.metrics.analysisCount > 0
      ? (this.metrics.mlInferences / this.metrics.analysisCount) * 100
      : 0;
    
    const errorRate = this.metrics.analysisCount > 0
      ? (this.metrics.errors / this.metrics.analysisCount) * 100
      : 0;
    
    const uptime = Date.now() - this.metrics.startTime;
    
    return {
      // Scan performance
      avgScanTime: Math.round(avgScanTime),
      minScanTime: Math.round(minScanTime),
      maxScanTime: Math.round(maxScanTime),
      totalScans: this.metrics.analysisCount,
      
      // Cache performance
      cacheHits: this.metrics.cacheHits,
      cacheMisses: this.metrics.cacheMisses,
      cacheHitRate: Math.round(cacheHitRate * 10) / 10,
      
      // ML usage
      mlInferences: this.metrics.mlInferences,
      heuristicFallbacks: this.metrics.heuristicFallbacks,
      mlUsageRate: Math.round(mlUsageRate * 10) / 10,
      
      // Reliability
      errors: this.metrics.errors,
      errorRate: Math.round(errorRate * 10) / 10,
      
      // Uptime
      uptime: uptime,
      uptimeFormatted: this.formatUptime(uptime)
    };
  }

  /**
   * Format uptime in human-readable format
   */
  formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) {
      return `${days}d ${hours % 24}h`;
    } else if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Save metrics to storage
   */
  async saveMetrics() {
    try {
      await chrome.storage.local.set({
        performanceMetrics: this.metrics
      });
    } catch (error) {
      console.error('[Performance] Failed to save metrics:', error);
    }
  }

  /**
   * Load metrics from storage
   */
  async loadMetrics() {
    try {
      const result = await chrome.storage.local.get('performanceMetrics');
      if (result.performanceMetrics) {
        this.metrics = result.performanceMetrics;
        console.log('[Performance] Metrics loaded');
      }
    } catch (error) {
      console.error('[Performance] Failed to load metrics:', error);
    }
  }

  /**
   * Reset all metrics
   */
  async reset() {
    this.metrics = {
      scanTimes: [],
      analysisCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      mlInferences: 0,
      heuristicFallbacks: 0,
      errors: 0,
      startTime: Date.now()
    };
    
    await this.saveMetrics();
    console.log('[Performance] Metrics reset');
  }

  /**
   * Get memory usage (if available)
   */
  async getMemoryUsage() {
    try {
      if (performance.memory) {
        return {
          usedJSHeapSize: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024),
          totalJSHeapSize: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024),
          jsHeapSizeLimit: Math.round(performance.memory.jsHeapSizeLimit / 1024 / 1024)
        };
      }
    } catch (error) {
      console.warn('[Performance] Memory API not available');
    }
    
    return null;
  }
}

// Export singleton instance
export const performanceMonitor = new PerformanceMonitor();
