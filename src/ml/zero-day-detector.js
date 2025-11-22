/**
 * Zero-Day Phishing Detection
 * Detects novel phishing techniques never seen before
 * Uses anomaly detection and generative AI concepts
 */

import * as tf from '@tensorflow/tfjs';

/**
 * Zero-Day Detector
 * Identifies new phishing techniques using anomaly detection
 */
export class ZeroDayDetector {
  constructor() {
    this.initialized = false;
    this.autoencoderModel = null;
    
    // Known good patterns (for anomaly detection)
    this.legitimatePatterns = new Map();
    
    // Anomaly threshold
    this.anomalyThreshold = 0.7;
    
    // Feature extractors
    this.featureExtractors = {
      url: this.extractURLFeatures.bind(this),
      content: this.extractContentFeatures.bind(this),
      visual: this.extractVisualFeatures.bind(this),
      behavioral: this.extractBehavioralFeatures.bind(this)
    };
    
    // Novelty detection cache
    this.noveltyCache = new Map();
    this.cacheTimeout = 3600000; // 1 hour
  }

  /**
   * Initialize zero-day detector
   * @returns {Promise<Object>} Initialization result
   */
  async initialize() {
    try {
      console.log('[Zero-Day Detector] Initializing...');
      
      // Load legitimate patterns
      await this.loadLegitimatePatterns();
      
      // Initialize autoencoder for anomaly detection
      await this.initializeAutoencoder();
      
      this.initialized = true;
      console.log('[Zero-Day Detector] Initialized successfully');
      
      return { success: true };
      
    } catch (error) {
      console.error('[Zero-Day Detector] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Initialize autoencoder model for anomaly detection
   * @returns {Promise<void>}
   */
  async initializeAutoencoder() {
    try {
      // Create autoencoder architecture
      const inputDim = 50; // Feature vector size
      const encodingDim = 10; // Compressed representation
      
      // Encoder
      const encoder = tf.sequential({
        layers: [
          tf.layers.dense({ inputShape: [inputDim], units: 32, activation: 'relu' }),
          tf.layers.dense({ units: 16, activation: 'relu' }),
          tf.layers.dense({ units: encodingDim, activation: 'relu' })
        ]
      });
      
      // Decoder
      const decoder = tf.sequential({
        layers: [
          tf.layers.dense({ inputShape: [encodingDim], units: 16, activation: 'relu' }),
          tf.layers.dense({ units: 32, activation: 'relu' }),
          tf.layers.dense({ units: inputDim, activation: 'sigmoid' })
        ]
      });
      
      // Full autoencoder
      this.autoencoderModel = tf.sequential();
      encoder.layers.forEach(layer => this.autoencoderModel.add(layer));
      decoder.layers.forEach(layer => this.autoencoderModel.add(layer));
      
      this.autoencoderModel.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'meanSquaredError'
      });
      
      console.log('[Zero-Day Detector] Autoencoder initialized');
      
    } catch (error) {
      console.error('[Zero-Day Detector] Autoencoder initialization failed:', error);
      this.autoencoderModel = null;
    }
  }

  /**
   * Detect zero-day phishing attempt
   * @param {Object} data - Data to analyze
   * @returns {Promise<Object>} Detection result
   */
  async detectZeroDay(data) {
    try {
      if (!this.initialized) {
        await this.initialize();
      }

      // Check cache first
      const cacheKey = this.generateCacheKey(data);
      const cached = this.noveltyCache.get(cacheKey);
      
      if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.result;
      }

      // Extract features from all available data
      const features = await this.extractAllFeatures(data);
      
      // Perform anomaly detection
      const anomalyScore = await this.detectAnomaly(features);
      
      // Analyze novelty patterns
      const noveltyAnalysis = this.analyzeNovelty(features, data);
      
      // Detect emerging techniques
      const emergingTechniques = this.detectEmergingTechniques(features, data);
      
      // Calculate overall zero-day probability
      const zeroDayProbability = this.calculateZeroDayProbability({
        anomalyScore,
        noveltyAnalysis,
        emergingTechniques
      });

      const result = {
        success: true,
        isZeroDay: zeroDayProbability > 0.7,
        probability: zeroDayProbability,
        confidence: this.calculateConfidence(anomalyScore, noveltyAnalysis),
        anomalyScore: anomalyScore,
        noveltyFactors: noveltyAnalysis.factors,
        emergingTechniques: emergingTechniques,
        recommendation: this.generateRecommendation(zeroDayProbability),
        timestamp: Date.now()
      };

      // Cache result
      this.noveltyCache.set(cacheKey, {
        result: result,
        timestamp: Date.now()
      });

      // Learn from this observation
      if (!result.isZeroDay) {
        await this.learnLegitimatePattern(features);
      }

      return result;

    } catch (error) {
      console.error('[Zero-Day Detector] Detection failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Extract all available features
   * @param {Object} data - Input data
   * @returns {Promise<Object>} Extracted features
   */
  async extractAllFeatures(data) {
    const features = {
      url: null,
      content: null,
      visual: null,
      behavioral: null,
      combined: null
    };

    try {
      if (data.url) {
        features.url = this.featureExtractors.url(data.url);
      }

      if (data.content) {
        features.content = this.featureExtractors.content(data.content);
      }

      if (data.screenshot) {
        features.visual = await this.featureExtractors.visual(data.screenshot);
      }

      if (data.behavior) {
        features.behavioral = this.featureExtractors.behavioral(data.behavior);
      }

      // Combine all features into single vector
      features.combined = this.combineFeatures(features);

    } catch (error) {
      console.error('[Zero-Day Detector] Feature extraction failed:', error);
    }

    return features;
  }

  /**
   * Extract URL features
   * @param {string} url - URL to analyze
   * @returns {Array} Feature vector
   */
  extractURLFeatures(url) {
    const features = [];
    
    try {
      const urlObj = new URL(url);
      
      // Length features
      features.push(url.length / 100); // Normalized length
      features.push(urlObj.hostname.length / 50);
      features.push(urlObj.pathname.length / 100);
      
      // Character distribution
      const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
      features.push(specialChars / url.length);
      
      // Subdomain count
      const subdomains = urlObj.hostname.split('.').length - 2;
      features.push(Math.min(subdomains / 5, 1));
      
      // Entropy (randomness)
      features.push(this.calculateEntropy(url));
      
      // Suspicious patterns
      features.push(/-/.test(url) ? 1 : 0);
      features.push(/\d{4,}/.test(url) ? 1 : 0);
      features.push(/@/.test(url) ? 1 : 0);
      features.push(/\.tk|\.ml|\.ga|\.cf/.test(url) ? 1 : 0);
      
    } catch (error) {
      console.error('[Zero-Day Detector] URL feature extraction failed:', error);
      // Return zero vector on error
      return new Array(10).fill(0);
    }
    
    return features;
  }

  /**
   * Extract content features
   * @param {string} content - Content to analyze
   * @returns {Array} Feature vector
   */
  extractContentFeatures(content) {
    const features = [];
    
    try {
      const text = content.toLowerCase();
      
      // Length features
      features.push(Math.min(text.length / 1000, 1));
      
      // Word count
      const words = text.split(/\s+/).length;
      features.push(Math.min(words / 500, 1));
      
      // Sentence count
      const sentences = text.split(/[.!?]+/).length;
      features.push(Math.min(sentences / 50, 1));
      
      // Keyword density
      const urgentWords = ['urgent', 'immediately', 'now', 'asap', 'hurry'];
      const urgentCount = urgentWords.filter(w => text.includes(w)).length;
      features.push(urgentCount / urgentWords.length);
      
      // Link density
      const links = (text.match(/https?:\/\//g) || []).length;
      features.push(Math.min(links / 10, 1));
      
      // Capitalization ratio
      const caps = (content.match(/[A-Z]/g) || []).length;
      features.push(caps / content.length);
      
      // Punctuation density
      const punct = (content.match(/[!?]/g) || []).length;
      features.push(Math.min(punct / 20, 1));
      
      // Number density
      const numbers = (content.match(/\d/g) || []).length;
      features.push(numbers / content.length);
      
      // Special character ratio
      const special = (content.match(/[^a-zA-Z0-9\s]/g) || []).length;
      features.push(special / content.length);
      
      // Entropy
      features.push(this.calculateEntropy(text));
      
    } catch (error) {
      console.error('[Zero-Day Detector] Content feature extraction failed:', error);
      return new Array(10).fill(0);
    }
    
    return features;
  }

  /**
   * Extract visual features (placeholder)
   * @param {string} screenshot - Screenshot data
   * @returns {Promise<Array>} Feature vector
   */
  async extractVisualFeatures(screenshot) {
    // Simplified visual feature extraction
    // In production, use actual computer vision
    return new Array(10).fill(0.5);
  }

  /**
   * Extract behavioral features
   * @param {Object} behavior - Behavioral data
   * @returns {Array} Feature vector
   */
  extractBehavioralFeatures(behavior) {
    const features = [];
    
    try {
      features.push(behavior.clickSpeed || 0);
      features.push(behavior.scrollSpeed || 0);
      features.push(behavior.timeOnPage || 0);
      features.push(behavior.mouseMovements || 0);
      features.push(behavior.keystrokes || 0);
      features.push(behavior.formInteractions || 0);
      features.push(behavior.navigationPattern || 0);
      features.push(behavior.deviceType || 0);
      features.push(behavior.browserType || 0);
      features.push(behavior.screenResolution || 0);
      
    } catch (error) {
      console.error('[Zero-Day Detector] Behavioral feature extraction failed:', error);
      return new Array(10).fill(0);
    }
    
    return features;
  }

  /**
   * Combine features into single vector
   * @param {Object} features - Feature object
   * @returns {Array} Combined feature vector
   */
  combineFeatures(features) {
    const combined = [];
    
    if (features.url) combined.push(...features.url);
    if (features.content) combined.push(...features.content);
    if (features.visual) combined.push(...features.visual);
    if (features.behavioral) combined.push(...features.behavioral);
    
    // Pad to fixed size (50 features)
    while (combined.length < 50) {
      combined.push(0);
    }
    
    return combined.slice(0, 50);
  }

  /**
   * Detect anomaly using autoencoder
   * @param {Object} features - Extracted features
   * @returns {Promise<number>} Anomaly score (0-1)
   */
  async detectAnomaly(features) {
    try {
      if (!this.autoencoderModel || !features.combined) {
        // Fallback to statistical anomaly detection
        return this.statisticalAnomalyDetection(features);
      }

      // Convert to tensor
      const inputTensor = tf.tensor2d([features.combined]);
      
      // Get reconstruction
      const reconstruction = this.autoencoderModel.predict(inputTensor);
      
      // Calculate reconstruction error
      const error = tf.losses.meanSquaredError(inputTensor, reconstruction);
      const errorValue = await error.data();
      
      // Cleanup
      inputTensor.dispose();
      reconstruction.dispose();
      error.dispose();
      
      // Normalize error to 0-1 range
      const anomalyScore = Math.min(errorValue[0] * 10, 1);
      
      return anomalyScore;
      
    } catch (error) {
      console.error('[Zero-Day Detector] Anomaly detection failed:', error);
      return 0.5; // Neutral score on error
    }
  }

  /**
   * Statistical anomaly detection (fallback)
   * @param {Object} features - Extracted features
   * @returns {number} Anomaly score
   */
  statisticalAnomalyDetection(features) {
    if (!features.combined) return 0.5;
    
    // Calculate distance from known legitimate patterns
    let minDistance = Infinity;
    
    for (const pattern of this.legitimatePatterns.values()) {
      const distance = this.euclideanDistance(features.combined, pattern.features);
      minDistance = Math.min(minDistance, distance);
    }
    
    // Normalize distance to 0-1 score
    const anomalyScore = Math.min(minDistance / 10, 1);
    
    return anomalyScore;
  }

  /**
   * Analyze novelty in patterns
   * @param {Object} features - Extracted features
   * @param {Object} data - Original data
   * @returns {Object} Novelty analysis
   */
  analyzeNovelty(features, data) {
    const analysis = {
      score: 0,
      factors: []
    };

    try {
      // Check for novel URL patterns
      if (features.url) {
        const urlNovelty = this.checkURLNovelty(features.url, data.url);
        if (urlNovelty.isNovel) {
          analysis.score += 0.3;
          analysis.factors.push(urlNovelty);
        }
      }

      // Check for novel content patterns
      if (features.content) {
        const contentNovelty = this.checkContentNovelty(features.content, data.content);
        if (contentNovelty.isNovel) {
          analysis.score += 0.3;
          analysis.factors.push(contentNovelty);
        }
      }

      // Check for novel behavioral patterns
      if (features.behavioral) {
        const behavioralNovelty = this.checkBehavioralNovelty(features.behavioral);
        if (behavioralNovelty.isNovel) {
          analysis.score += 0.2;
          analysis.factors.push(behavioralNovelty);
        }
      }

      // Check for novel visual patterns
      if (features.visual) {
        const visualNovelty = this.checkVisualNovelty(features.visual);
        if (visualNovelty.isNovel) {
          analysis.score += 0.2;
          analysis.factors.push(visualNovelty);
        }
      }

      analysis.score = Math.min(1.0, analysis.score);

    } catch (error) {
      console.error('[Zero-Day Detector] Novelty analysis failed:', error);
    }

    return analysis;
  }

  /**
   * Check URL novelty
   * @param {Array} features - URL features
   * @param {string} url - Original URL
   * @returns {Object} Novelty result
   */
  checkURLNovelty(features, url) {
    // Check for unusual patterns
    const novelPatterns = [
      /[a-z]{20,}/, // Very long random strings
      /\d{10,}/, // Long number sequences
      /[A-Z]{10,}/, // Long uppercase sequences
      /-{3,}/, // Multiple hyphens
      /_{3,}/, // Multiple underscores
    ];

    const detectedPatterns = novelPatterns.filter(p => p.test(url));

    return {
      type: 'url_novelty',
      isNovel: detectedPatterns.length > 0,
      description: `Novel URL patterns detected: ${detectedPatterns.length}`,
      patterns: detectedPatterns.map(p => p.source)
    };
  }

  /**
   * Check content novelty
   * @param {Array} features - Content features
   * @param {string} content - Original content
   * @returns {Object} Novelty result
   */
  checkContentNovelty(features, content) {
    // Check for unusual content patterns
    const entropy = this.calculateEntropy(content);
    const isHighEntropy = entropy > 0.8;

    return {
      type: 'content_novelty',
      isNovel: isHighEntropy,
      description: isHighEntropy ? 'Unusually high content entropy' : 'Normal content patterns',
      entropy: entropy
    };
  }

  /**
   * Check behavioral novelty
   * @param {Array} features - Behavioral features
   * @returns {Object} Novelty result
   */
  checkBehavioralNovelty(features) {
    // Simple novelty check
    const avgFeature = features.reduce((a, b) => a + b, 0) / features.length;
    const isNovel = avgFeature > 0.8 || avgFeature < 0.2;

    return {
      type: 'behavioral_novelty',
      isNovel: isNovel,
      description: isNovel ? 'Unusual behavioral patterns' : 'Normal behavior'
    };
  }

  /**
   * Check visual novelty
   * @param {Array} features - Visual features
   * @returns {Object} Novelty result
   */
  checkVisualNovelty(features) {
    return {
      type: 'visual_novelty',
      isNovel: false,
      description: 'Visual analysis not available'
    };
  }

  /**
   * Detect emerging techniques
   * @param {Object} features - Extracted features
   * @param {Object} data - Original data
   * @returns {Array} Detected techniques
   */
  detectEmergingTechniques(features, data) {
    const techniques = [];

    // Technique 1: Homograph attacks (lookalike domains)
    if (data.url && /[а-яА-Я]/.test(data.url)) { // Cyrillic characters
      techniques.push({
        name: 'Homograph Attack',
        description: 'Uses lookalike characters from different alphabets',
        severity: 'high'
      });
    }

    // Technique 2: Zero-width characters
    if (data.content && /[\u200B-\u200D\uFEFF]/.test(data.content)) {
      techniques.push({
        name: 'Zero-Width Character Obfuscation',
        description: 'Uses invisible characters to hide content',
        severity: 'medium'
      });
    }

    // Technique 3: Punycode abuse
    if (data.url && /xn--/.test(data.url)) {
      techniques.push({
        name: 'Punycode Domain',
        description: 'Uses internationalized domain encoding',
        severity: 'medium'
      });
    }

    return techniques;
  }

  /**
   * Calculate zero-day probability
   * @param {Object} analysis - Analysis results
   * @returns {number} Probability (0-1)
   */
  calculateZeroDayProbability(analysis) {
    let probability = 0;

    // Weight factors
    probability += analysis.anomalyScore * 0.4;
    probability += analysis.noveltyAnalysis.score * 0.4;
    probability += (analysis.emergingTechniques.length / 5) * 0.2;

    return Math.min(1.0, probability);
  }

  /**
   * Calculate confidence
   * @param {number} anomalyScore - Anomaly score
   * @param {Object} noveltyAnalysis - Novelty analysis
   * @returns {number} Confidence (0-1)
   */
  calculateConfidence(anomalyScore, noveltyAnalysis) {
    const factorCount = noveltyAnalysis.factors.length;
    const baseConfidence = Math.min(factorCount / 4, 1);
    
    // Higher anomaly score increases confidence
    const anomalyBonus = anomalyScore * 0.3;
    
    return Math.min(1.0, baseConfidence + anomalyBonus);
  }

  /**
   * Generate recommendation
   * @param {number} probability - Zero-day probability
   * @returns {Object} Recommendation
   */
  generateRecommendation(probability) {
    if (probability >= 0.8) {
      return {
        action: 'block',
        message: 'Novel attack technique detected - BLOCK immediately',
        priority: 'critical'
      };
    } else if (probability >= 0.6) {
      return {
        action: 'warn',
        message: 'Possible zero-day attack - Exercise extreme caution',
        priority: 'high'
      };
    } else if (probability >= 0.4) {
      return {
        action: 'caution',
        message: 'Unusual patterns detected - Verify carefully',
        priority: 'medium'
      };
    }
    
    return {
      action: 'monitor',
      message: 'No zero-day indicators detected',
      priority: 'low'
    };
  }

  /**
   * Learn legitimate pattern
   * @param {Object} features - Features to learn
   * @returns {Promise<void>}
   */
  async learnLegitimatePattern(features) {
    try {
      if (!features.combined) return;

      const patternKey = this.generatePatternKey(features.combined);
      
      this.legitimatePatterns.set(patternKey, {
        features: features.combined,
        timestamp: Date.now(),
        count: 1
      });

      // Limit size
      if (this.legitimatePatterns.size > 1000) {
        const oldest = Array.from(this.legitimatePatterns.entries())
          .sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
        this.legitimatePatterns.delete(oldest[0]);
      }

      await this.saveLegitimatePatterns();

    } catch (error) {
      console.error('[Zero-Day Detector] Failed to learn pattern:', error);
    }
  }

  /**
   * Load legitimate patterns
   * @returns {Promise<void>}
   */
  async loadLegitimatePatterns() {
    try {
      const stored = await chrome.storage.local.get('legitimatePatterns');
      
      if (stored.legitimatePatterns) {
        this.legitimatePatterns = new Map(Object.entries(stored.legitimatePatterns));
        console.log('[Zero-Day Detector] Loaded', this.legitimatePatterns.size, 'legitimate patterns');
      }
      
    } catch (error) {
      console.error('[Zero-Day Detector] Failed to load patterns:', error);
    }
  }

  /**
   * Save legitimate patterns
   * @returns {Promise<void>}
   */
  async saveLegitimatePatterns() {
    try {
      const patternsObj = Object.fromEntries(this.legitimatePatterns);
      await chrome.storage.local.set({
        legitimatePatterns: patternsObj
      });
    } catch (error) {
      console.error('[Zero-Day Detector] Failed to save patterns:', error);
    }
  }

  /**
   * Calculate entropy
   * @param {string} str - String to analyze
   * @returns {number} Entropy value
   */
  calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    // Normalize to 0-1
    return Math.min(entropy / 8, 1);
  }

  /**
   * Calculate Euclidean distance
   * @param {Array} a - First vector
   * @param {Array} b - Second vector
   * @returns {number} Distance
   */
  euclideanDistance(a, b) {
    let sum = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      sum += Math.pow(a[i] - b[i], 2);
    }
    return Math.sqrt(sum);
  }

  /**
   * Generate pattern key
   * @param {Array} features - Feature vector
   * @returns {string} Pattern key
   */
  generatePatternKey(features) {
    // Create hash from first few features
    const keyFeatures = features.slice(0, 5);
    return keyFeatures.map(f => Math.round(f * 10)).join('_');
  }

  /**
   * Generate cache key
   * @param {Object} data - Input data
   * @returns {string} Cache key
   */
  generateCacheKey(data) {
    const parts = [
      data.url || '',
      (data.content || '').substring(0, 100)
    ];
    return parts.join('|');
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      legitimatePatterns: this.legitimatePatterns.size,
      cacheSize: this.noveltyCache.size,
      modelLoaded: !!this.autoencoderModel
    };
  }
}

// Create singleton instance
export const zeroDayDetector = new ZeroDayDetector();

export default zeroDayDetector;
