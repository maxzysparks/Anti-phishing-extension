/**
 * ML Training Data Collector
 * Collects and prepares training data for the phishing detection model
 */

import { PatternDetector } from './pattern-detector.js';

export class TrainingDataCollector {
  /**
   * Generate synthetic training data based on known patterns
   * This creates a baseline dataset for initial model training
   */
  static generateSyntheticData() {
    const trainingData = [];
    
    // LEGITIMATE URLs (Safe examples)
    const legitimateUrls = [
      'https://www.google.com', 'https://www.microsoft.com', 'https://www.apple.com',
      'https://www.amazon.com', 'https://www.facebook.com', 'https://www.github.com',
      'https://www.chase.com', 'https://www.bankofamerica.com',
      'https://www.ebay.com', 'https://www.walmart.com',
      'https://www.cnn.com', 'https://www.bbc.com',
      'https://www.wikipedia.org', 'https://www.coursera.org',
      'https://mail.google.com', 'https://drive.google.com',
      'https://www.paypal.com/signin', 'https://secure.chase.com/web/auth'
    ];
    
    // PHISHING URLs (patterns only)
    const phishingPatterns = [
      'http://192.168.1.100/login', 'http://paypal-secure.tk/login',
      'http://amazon-verify.ml/account', 'http://gooogle.com/signin',
      'http://secure-login.paypal.phishing.com', 'http://secure-banking-login.xyz',
      'http://paypal.com@phishing-site.tk', 'http://secure-login.com:8080/verify'
    ];
    
    // SUSPICIOUS examples
    const suspiciousPatterns = [
      'http://login-secure.com', 'https://verify-account.info',
      'http://secure-banking.biz', 'https://account-update.online'
    ];
    
    // Add to training data
    legitimateUrls.forEach(url => {
      const features = PatternDetector.extractFeatures(url);
      if (features) {
        trainingData.push({
          url, features,
          label: 'SAFE',
          labelEncoded: [1, 0, 0]
        });
      }
    });
    
    phishingPatterns.forEach(url => {
      const features = PatternDetector.extractFeatures(url);
      if (features) {
        trainingData.push({
          url, features,
          label: 'DANGEROUS',
          labelEncoded: [0, 0, 1]
        });
      }
    });
    
    suspiciousPatterns.forEach(url => {
      const features = PatternDetector.extractFeatures(url);
      if (features) {
        trainingData.push({
          url, features,
          label: 'SUSPICIOUS',
          labelEncoded: [0, 1, 0]
        });
      }
    });
    
    console.log(`[Training] Generated ${trainingData.length} synthetic training samples`);
    return trainingData;
  }
  
  /**
   * Augment training data by creating variations
   */
  static augmentData(trainingData) {
    const augmented = [...trainingData];
    const phishingUrls = trainingData.filter(d => d.label === 'DANGEROUS');
    
    phishingUrls.forEach(sample => {
      try {
        const withParams = `${sample.url}?id=${Math.random().toString(36).substring(7)}`;
        const features = PatternDetector.extractFeatures(withParams);
        if (features) {
          augmented.push({
            url: withParams, features,
            label: 'DANGEROUS',
            labelEncoded: [0, 0, 1],
            augmented: true
          });
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });
    
    console.log(`[Training] Augmented dataset: ${trainingData.length} → ${augmented.length} samples`);
    return augmented;
  }
  
  /**
   * Split data into train/validation/test sets
   */
  static splitData(data, trainRatio = 0.7, valRatio = 0.15) {
    const shuffled = [...data].sort(() => Math.random() - 0.5);
    const trainSize = Math.floor(shuffled.length * trainRatio);
    const valSize = Math.floor(shuffled.length * valRatio);
    
    return {
      trainData: shuffled.slice(0, trainSize),
      valData: shuffled.slice(trainSize, trainSize + valSize),
      testData: shuffled.slice(trainSize + valSize)
    };
  }
  
  /**
   * Balance dataset
   */
  static balanceDataset(data) {
    const safe = data.filter(d => d.label === 'SAFE');
    const suspicious = data.filter(d => d.label === 'SUSPICIOUS');
    const dangerous = data.filter(d => d.label === 'DANGEROUS');
    
    const minSize = Math.min(safe.length, suspicious.length, dangerous.length);
    const balanced = [
      ...safe.slice(0, minSize),
      ...suspicious.slice(0, minSize),
      ...dangerous.slice(0, minSize)
    ];
    
    return balanced.sort(() => Math.random() - 0.5);
  }
  
  /**
   * Save training data to storage
   */
  static async saveTrainingData(data) {
    try {
      await chrome.storage.local.set({
        trainingData: {
          data: data,
          timestamp: Date.now(),
          count: data.length
        }
      });
      console.log(`[Training] Saved ${data.length} training samples`);
      return { success: true, count: data.length };
    } catch (error) {
      console.error('[Training] Error saving:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Load training data from storage
   */
  static async loadTrainingData() {
    try {
      const result = await chrome.storage.local.get('trainingData');
      if (result.trainingData) {
        return {
          success: true,
          data: result.trainingData.data,
          count: result.trainingData.count,
          timestamp: result.trainingData.timestamp
        };
      }
      return { success: false, message: 'No training data found' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Initialize training data
   */
  static async initializeTrainingData() {
    console.log('[Training] Initializing training data...');
    let data = this.generateSyntheticData();
    data = this.augmentData(data);
    data = this.balanceDataset(data);
    
    const saveResult = await this.saveTrainingData(data);
    if (saveResult.success) {
      console.log('[Training] ✓ Training data initialized successfully');
      return {
        success: true,
        count: data.length,
        message: 'Training data ready'
      };
    }
    return saveResult;
  }
  
  /**
   * Get training data statistics
   */
  static async getDataStats() {
    const loadResult = await this.loadTrainingData();
    if (!loadResult.success) {
      return { exists: false };
    }
    
    const data = loadResult.data;
    return {
      exists: true,
      total: data.length,
      safe: data.filter(d => d.label === 'SAFE').length,
      suspicious: data.filter(d => d.label === 'SUSPICIOUS').length,
      dangerous: data.filter(d => d.label === 'DANGEROUS').length,
      timestamp: new Date(loadResult.timestamp).toLocaleString()
    };
  }
}
