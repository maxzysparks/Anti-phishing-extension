/**
 * Telemetry & Metrics System
 * Production-grade monitoring and analytics
 * Privacy-compliant data collection
 * Professional implementation
 */

/**
 * Telemetry System
 * Collects and reports system metrics
 */
export class TelemetrySystem {
  constructor() {
    this.initialized = false;
    this.metrics = new Map();
    this.events = [];
    
    // Configuration
    this.config = {
      enabled: true,
      privacyMode: true, // Anonymize all data
      batchSize: 100,
      flushInterval: 300000, // 5 minutes
      maxEventsBuffer: 1000,
      retentionDays: 30
    };
    
    // Metric types
    this.metricTypes = {
      COUNTER: 'counter',
      GAUGE: 'gauge',
      HISTOGRAM: 'histogram',
      TIMER: 'timer'
    };
  }

  /**
   * Initialize telemetry
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[Telemetry] Initializing...');
      
      // Check user consent
      const consent = await this.checkConsent();
      if (!consent) {
        this.config.enabled = false;
        console.log('[Telemetry] Disabled (no consent)');
        return { success: true, enabled: false };
      }
      
      // Load existing metrics
      await this.loadMetrics();
      
      // Start periodic flush
      this.startPeriodicFlush();
      
      // Register default metrics
      this.registerDefaultMetrics();
      
      this.initialized = true;
      console.log('[Telemetry] Initialized');
      
      return { success: true, enabled: true };
      
    } catch (error) {
      console.error('[Telemetry] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Check user consent
   * @returns {Promise<boolean>} Has consent
   */
  async checkConsent() {
    try {
      const stored = await chrome.storage.local.get('telemetryConsent');
      return stored.telemetryConsent !== false; // Default true
    } catch (error) {
      return false;
    }
  }

  /**
   * Record metric
   * @param {string} name - Metric name
   * @param {number} value - Metric value
   * @param {string} type - Metric type
   * @param {Object} tags - Tags
   */
  recordMetric(name, value, type = this.metricTypes.COUNTER, tags = {}) {
    if (!this.config.enabled) return;

    try {
      const key = this.getMetricKey(name, tags);
      const existing = this.metrics.get(key) || {
        name,
        type,
        tags,
        values: [],
        count: 0,
        sum: 0,
        min: Infinity,
        max: -Infinity,
        lastUpdated: Date.now()
      };

      // Update metric
      existing.values.push(value);
      existing.count++;
      existing.sum += value;
      existing.min = Math.min(existing.min, value);
      existing.max = Math.max(existing.max, value);
      existing.lastUpdated = Date.now();

      // Keep only recent values
      if (existing.values.length > 1000) {
        existing.values = existing.values.slice(-1000);
      }

      this.metrics.set(key, existing);

    } catch (error) {
      console.error('[Telemetry] Failed to record metric:', error);
    }
  }

  /**
   * Record event
   * @param {string} category - Event category
   * @param {string} action - Event action
   * @param {Object} properties - Event properties
   */
  recordEvent(category, action, properties = {}) {
    if (!this.config.enabled) return;

    try {
      const event = {
        category,
        action,
        properties: this.config.privacyMode ? this.anonymizeProperties(properties) : properties,
        timestamp: Date.now()
      };

      this.events.push(event);

      // Limit buffer size
      if (this.events.length > this.config.maxEventsBuffer) {
        this.events.shift();
      }

      // Auto-flush if batch size reached
      if (this.events.length >= this.config.batchSize) {
        this.flush();
      }

    } catch (error) {
      console.error('[Telemetry] Failed to record event:', error);
    }
  }

  /**
   * Start timer
   * @param {string} name - Timer name
   * @returns {Function} Stop function
   */
  startTimer(name) {
    const startTime = Date.now();
    
    return () => {
      const duration = Date.now() - startTime;
      this.recordMetric(name, duration, this.metricTypes.TIMER);
      return duration;
    };
  }

  /**
   * Increment counter
   * @param {string} name - Counter name
   * @param {number} value - Increment value
   * @param {Object} tags - Tags
   */
  incrementCounter(name, value = 1, tags = {}) {
    this.recordMetric(name, value, this.metricTypes.COUNTER, tags);
  }

  /**
   * Set gauge
   * @param {string} name - Gauge name
   * @param {number} value - Gauge value
   * @param {Object} tags - Tags
   */
  setGauge(name, value, tags = {}) {
    this.recordMetric(name, value, this.metricTypes.GAUGE, tags);
  }

  /**
   * Record histogram
   * @param {string} name - Histogram name
   * @param {number} value - Value
   * @param {Object} tags - Tags
   */
  recordHistogram(name, value, tags = {}) {
    this.recordMetric(name, value, this.metricTypes.HISTOGRAM, tags);
  }

  /**
   * Get metric key
   * @param {string} name - Metric name
   * @param {Object} tags - Tags
   * @returns {string} Key
   */
  getMetricKey(name, tags) {
    const tagString = Object.entries(tags)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v}`)
      .join(',');
    
    return tagString ? `${name}[${tagString}]` : name;
  }

  /**
   * Anonymize properties
   * @param {Object} properties - Properties
   * @returns {Object} Anonymized properties
   */
  anonymizeProperties(properties) {
    const anonymized = {};
    
    for (const [key, value] of Object.entries(properties)) {
      // Remove PII
      if (['url', 'email', 'ip', 'userId'].includes(key)) {
        anonymized[key] = '[REDACTED]';
      } else if (typeof value === 'string' && value.length > 100) {
        anonymized[key] = value.substring(0, 100) + '...';
      } else {
        anonymized[key] = value;
      }
    }
    
    return anonymized;
  }

  /**
   * Flush metrics and events
   * @returns {Promise<void>}
   */
  async flush() {
    if (!this.config.enabled) return;

    try {
      // Save to storage
      await this.saveMetrics();
      
      // In production, send to analytics server
      // await this.sendToServer();
      
      // Clear old events
      const cutoff = Date.now() - (this.config.retentionDays * 86400000);
      this.events = this.events.filter(e => e.timestamp > cutoff);

      console.log('[Telemetry] Flushed metrics and events');

    } catch (error) {
      console.error('[Telemetry] Flush failed:', error);
    }
  }

  /**
   * Start periodic flush
   */
  startPeriodicFlush() {
    setInterval(() => {
      this.flush();
    }, this.config.flushInterval);
    
    console.log('[Telemetry] Periodic flush started');
  }

  /**
   * Register default metrics
   */
  registerDefaultMetrics() {
    // System metrics
    this.setGauge('system.initialized', 1);
    this.setGauge('system.version', 1, { version: '1.0.0' });
    
    // Performance metrics
    this.recordEvent('system', 'initialized', {
      timestamp: Date.now(),
      browser: navigator.userAgent.split(' ')[0]
    });
  }

  /**
   * Get metrics summary
   * @returns {Object} Summary
   */
  getMetricsSummary() {
    const summary = {
      totalMetrics: this.metrics.size,
      totalEvents: this.events.length,
      metrics: {}
    };

    for (const [key, metric] of this.metrics.entries()) {
      summary.metrics[key] = {
        type: metric.type,
        count: metric.count,
        sum: metric.sum,
        avg: metric.sum / metric.count,
        min: metric.min,
        max: metric.max,
        lastUpdated: metric.lastUpdated
      };
    }

    return summary;
  }

  /**
   * Get events by category
   * @param {string} category - Category
   * @param {number} limit - Limit
   * @returns {Array} Events
   */
  getEventsByCategory(category, limit = 100) {
    return this.events
      .filter(e => e.category === category)
      .slice(-limit);
  }

  /**
   * Load metrics
   * @returns {Promise<void>}
   */
  async loadMetrics() {
    try {
      const stored = await chrome.storage.local.get('telemetryMetrics');
      
      if (stored.telemetryMetrics) {
        this.metrics = new Map(Object.entries(stored.telemetryMetrics));
      }
      
      const storedEvents = await chrome.storage.local.get('telemetryEvents');
      
      if (storedEvents.telemetryEvents) {
        this.events = storedEvents.telemetryEvents;
      }
      
    } catch (error) {
      console.error('[Telemetry] Load failed:', error);
    }
  }

  /**
   * Save metrics
   * @returns {Promise<void>}
   */
  async saveMetrics() {
    try {
      await chrome.storage.local.set({
        telemetryMetrics: Object.fromEntries(this.metrics),
        telemetryEvents: this.events,
        telemetryTimestamp: Date.now()
      });
    } catch (error) {
      console.error('[Telemetry] Save failed:', error);
    }
  }

  /**
   * Clear all data
   * @returns {Promise<void>}
   */
  async clearAllData() {
    this.metrics.clear();
    this.events = [];
    await chrome.storage.local.remove(['telemetryMetrics', 'telemetryEvents']);
    console.log('[Telemetry] All data cleared');
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      enabled: this.config.enabled,
      metrics: this.metrics.size,
      events: this.events.length,
      config: this.config
    };
  }
}

