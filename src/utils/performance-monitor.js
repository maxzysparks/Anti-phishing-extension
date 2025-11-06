/**
 * Performance Monitor
 * Tracks and optimizes extension performance
 */

export class PerformanceMonitor {
  static metrics = new Map();
  static batchQueue = [];
  static batchSize = 50;
  static batchDelay = 100; // ms
  static batchTimer = null;

  /**
   * Start performance measurement
   */
  static startMeasure(label) {
    const startTime = performance.now();
    this.metrics.set(label, { startTime, endTime: null, duration: null });
    return startTime;
  }

  /**
   * End performance measurement
   */
  static endMeasure(label) {
    const metric = this.metrics.get(label);
    if (!metric) {
      console.warn(`[Performance] No start time found for: ${label}`);
      return null;
    }

    metric.endTime = performance.now();
    metric.duration = metric.endTime - metric.startTime;

    // Log slow operations
    if (metric.duration > 1000) {
      console.warn(`[Performance] Slow operation detected: ${label} took ${metric.duration.toFixed(2)}ms`);
    }

    return metric.duration;
  }

  /**
   * Get metric
   */
  static getMetric(label) {
    return this.metrics.get(label);
  }

  /**
   * Clear all metrics
   */
  static clearMetrics() {
    this.metrics.clear();
  }

  /**
   * Batch process links to avoid UI blocking
   */
  static async processBatch(items, processor, options = {}) {
    const {
      batchSize = this.batchSize,
      delay = this.batchDelay,
      onProgress = null
    } = options;

    const results = [];
    const total = items.length;

    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      
      // Process batch
      const batchResults = await Promise.all(
        batch.map(item => processor(item))
      );
      
      results.push(...batchResults);

      // Report progress
      if (onProgress) {
        const progress = Math.min(((i + batchSize) / total) * 100, 100);
        onProgress(progress, results.length, total);
      }

      // Delay between batches to prevent UI blocking
      if (i + batchSize < items.length) {
        await this.delay(delay);
      }
    }

    return results;
  }

  /**
   * Debounce function execution
   */
  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  /**
   * Throttle function execution
   */
  static throttle(func, limit) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  /**
   * Delay execution
   */
  static delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Queue item for batch processing
   */
  static queueForBatch(item, processor) {
    return new Promise((resolve) => {
      this.batchQueue.push({ item, processor, resolve });

      // Clear existing timer
      if (this.batchTimer) {
        clearTimeout(this.batchTimer);
      }

      // Process batch if size reached or after delay
      if (this.batchQueue.length >= this.batchSize) {
        this.processBatchQueue();
      } else {
        this.batchTimer = setTimeout(() => {
          this.processBatchQueue();
        }, this.batchDelay);
      }
    });
  }

  /**
   * Process queued batch
   */
  static async processBatchQueue() {
    if (this.batchQueue.length === 0) return;

    const batch = this.batchQueue.splice(0, this.batchSize);
    
    // Process all items in parallel
    const results = await Promise.allSettled(
      batch.map(({ item, processor }) => processor(item))
    );

    // Resolve promises
    batch.forEach(({ resolve }, index) => {
      const result = results[index];
      if (result.status === 'fulfilled') {
        resolve(result.value);
      } else {
        console.error('[Performance] Batch item failed:', result.reason);
        resolve(null);
      }
    });

    // Continue processing if more items
    if (this.batchQueue.length > 0) {
      setTimeout(() => this.processBatchQueue(), this.batchDelay);
    }
  }

  /**
   * Monitor memory usage
   */
  static getMemoryUsage() {
    if (performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
        percentUsed: ((performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit) * 100).toFixed(2)
      };
    }
    return null;
  }

  /**
   * Get performance summary
   */
  static getSummary() {
    const summary = {
      metrics: {},
      memory: this.getMemoryUsage(),
      timestamp: Date.now()
    };

    this.metrics.forEach((value, key) => {
      if (value.duration !== null) {
        summary.metrics[key] = {
          duration: value.duration.toFixed(2),
          startTime: value.startTime.toFixed(2),
          endTime: value.endTime.toFixed(2)
        };
      }
    });

    return summary;
  }

  /**
   * Optimize large dataset processing
   */
  static async processLargeDataset(dataset, processor, options = {}) {
    const {
      chunkSize = 100,
      onProgress = null,
      maxConcurrent = 5
    } = options;

    const chunks = [];
    for (let i = 0; i < dataset.length; i += chunkSize) {
      chunks.push(dataset.slice(i, i + chunkSize));
    }

    const results = [];
    let processed = 0;

    // Process chunks with concurrency limit
    for (let i = 0; i < chunks.length; i += maxConcurrent) {
      const chunkBatch = chunks.slice(i, i + maxConcurrent);
      
      const batchResults = await Promise.all(
        chunkBatch.map(async (chunk) => {
          const chunkResults = [];
          for (const item of chunk) {
            try {
              const result = await processor(item);
              chunkResults.push(result);
              processed++;
              
              if (onProgress) {
                onProgress((processed / dataset.length) * 100, processed, dataset.length);
              }
            } catch (error) {
              console.error('[Performance] Item processing failed:', error);
              chunkResults.push(null);
            }
          }
          return chunkResults;
        })
      );

      results.push(...batchResults.flat());
      
      // Small delay between batches
      if (i + maxConcurrent < chunks.length) {
        await this.delay(50);
      }
    }

    return results;
  }

  /**
   * Cache with TTL
   */
  static createCache(ttl = 3600000) {
    const cache = new Map();

    return {
      get(key) {
        const item = cache.get(key);
        if (!item) return null;

        if (Date.now() > item.expiry) {
          cache.delete(key);
          return null;
        }

        return item.value;
      },

      set(key, value) {
        cache.set(key, {
          value,
          expiry: Date.now() + ttl
        });
      },

      has(key) {
        const item = cache.get(key);
        if (!item) return false;

        if (Date.now() > item.expiry) {
          cache.delete(key);
          return false;
        }

        return true;
      },

      delete(key) {
        cache.delete(key);
      },

      clear() {
        cache.clear();
      },

      size() {
        // Clean expired items first
        for (const [key, item] of cache.entries()) {
          if (Date.now() > item.expiry) {
            cache.delete(key);
          }
        }
        return cache.size;
      }
    };
  }

  /**
   * Measure async function performance
   */
  static async measureAsync(label, fn) {
    this.startMeasure(label);
    try {
      const result = await fn();
      this.endMeasure(label);
      return result;
    } catch (error) {
      this.endMeasure(label);
      throw error;
    }
  }

  /**
   * Measure sync function performance
   */
  static measureSync(label, fn) {
    this.startMeasure(label);
    try {
      const result = fn();
      this.endMeasure(label);
      return result;
    } catch (error) {
      this.endMeasure(label);
      throw error;
    }
  }

  /**
   * Log performance report
   */
  static logReport() {
    const summary = this.getSummary();
    console.group('[Performance Report]');
    console.log('Timestamp:', new Date(summary.timestamp).toISOString());
    
    if (summary.memory) {
      console.log('Memory Usage:', `${summary.memory.percentUsed}%`);
      console.log('Used Heap:', `${(summary.memory.usedJSHeapSize / 1024 / 1024).toFixed(2)} MB`);
    }
    
    console.log('Metrics:');
    Object.entries(summary.metrics).forEach(([key, value]) => {
      console.log(`  ${key}: ${value.duration}ms`);
    });
    
    console.groupEnd();
  }
}
