/**
 * Adaptive Learning Engine
 * Makes the extension "sentient" through continuous learning
 * 
 * Features:
 * 1. Automatic retraining on collected feedback
 * 2. Adaptive threshold adjustment based on accuracy
 * 3. Behavioral pattern recognition
 * 4. Self-improving detection system
 */

import { ModelTrainer } from './model-trainer.js';
import { TrainingDataCollector } from './training-data-collector.js';
import { tfManager } from './tensorflow-manager.js';
import { StorageManager } from '../utils/storage.js';

export class AdaptiveLearningEngine {
  static learningConfig = {
    // Retraining settings
    minFeedbackForRetraining: 50,
    retrainingInterval: 604800000, // 7 days in ms
    lastRetraining: 0,
    
    // Adaptive threshold settings
    baseThreshold: 0.5,
    currentThreshold: 0.5,
    minThreshold: 0.3,
    maxThreshold: 0.8,
    
    // Accuracy tracking
    targetAccuracy: 0.85,
    falsePositiveRate: 0,
    falseNegativeRate: 0,
    
    // Pattern recognition
    patternCache: new Map(),
    minPatternOccurrences: 5,
    
    // Behavioral learning
    userBehaviorPatterns: new Map(),
    trustedDomains: new Set(),
    suspiciousDomains: new Set()
  };
  
  /**
   * Initialize adaptive learning engine
   */
  static async initialize() {
    try {
      console.log('[Adaptive Learning] Initializing sentient learning engine...');
      
      // Load saved configuration
      await this.loadConfiguration();
      
      // Schedule automatic retraining
      this.scheduleAutomaticRetraining();
      
      // Start behavioral learning
      this.startBehavioralLearning();
      
      // Initialize pattern recognition
      await this.initializePatternRecognition();
      
      console.log('[Adaptive Learning] ✓ Sentient engine initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[Adaptive Learning] Initialization error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Load saved learning configuration
   */
  static async loadConfiguration() {
    try {
      const result = await chrome.storage.local.get('adaptiveLearningConfig');
      
      if (result.adaptiveLearningConfig) {
        const saved = result.adaptiveLearningConfig;
        
        this.learningConfig.lastRetraining = saved.lastRetraining || 0;
        this.learningConfig.currentThreshold = saved.currentThreshold || 0.5;
        this.learningConfig.falsePositiveRate = saved.falsePositiveRate || 0;
        this.learningConfig.falseNegativeRate = saved.falseNegativeRate || 0;
        
        // Load behavioral patterns
        if (saved.trustedDomains) {
          this.learningConfig.trustedDomains = new Set(saved.trustedDomains);
        }
        if (saved.suspiciousDomains) {
          this.learningConfig.suspiciousDomains = new Set(saved.suspiciousDomains);
        }
        
        console.log('[Adaptive Learning] Configuration loaded');
      }
    } catch (error) {
      console.error('[Adaptive Learning] Failed to load config:', error);
    }
  }
  
  /**
   * Save learning configuration
   */
  static async saveConfiguration() {
    try {
      const config = {
        lastRetraining: this.learningConfig.lastRetraining,
        currentThreshold: this.learningConfig.currentThreshold,
        falsePositiveRate: this.learningConfig.falsePositiveRate,
        falseNegativeRate: this.learningConfig.falseNegativeRate,
        trustedDomains: Array.from(this.learningConfig.trustedDomains),
        suspiciousDomains: Array.from(this.learningConfig.suspiciousDomains),
        lastUpdated: Date.now()
      };
      
      await chrome.storage.local.set({ adaptiveLearningConfig: config });
    } catch (error) {
      console.error('[Adaptive Learning] Failed to save config:', error);
    }
  }
  
  /**
   * FEATURE 1: Automatic Retraining
   * Retrains model weekly on collected feedback
   */
  static scheduleAutomaticRetraining() {
    // Create weekly retraining alarm
    chrome.alarms.create('weeklyRetraining', {
      periodInMinutes: 10080 // 7 days
    });
    
    // Also check on startup if retraining is due
    this.checkRetrainingDue();
    
    console.log('[Adaptive Learning] Automatic retraining scheduled (weekly)');
  }
  
  /**
   * Check if retraining is due
   */
  static async checkRetrainingDue() {
    const now = Date.now();
    const timeSinceLastRetraining = now - this.learningConfig.lastRetraining;
    
    // If more than 7 days since last retraining
    if (timeSinceLastRetraining > this.learningConfig.retrainingInterval) {
      console.log('[Adaptive Learning] Retraining is due, checking feedback...');
      await this.performAutomaticRetraining();
    }
  }
  
  /**
   * Perform automatic retraining
   */
  static async performAutomaticRetraining() {
    try {
      console.log('[Adaptive Learning] 🤖 Starting automatic retraining...');
      
      // Get collected feedback
      const result = await chrome.storage.local.get('userFeedback');
      const feedback = result.userFeedback || [];
      
      // Check if we have enough feedback
      if (feedback.length < this.learningConfig.minFeedbackForRetraining) {
        console.log(`[Adaptive Learning] Not enough feedback yet (${feedback.length}/${this.learningConfig.minFeedbackForRetraining})`);
        return { success: false, reason: 'insufficient_feedback' };
      }
      
      console.log(`[Adaptive Learning] Retraining with ${feedback.length} feedback samples...`);
      
      // Prepare training data from feedback
      const trainingData = await this.prepareFeedbackTrainingData(feedback);
      
      if (trainingData.length === 0) {
        console.log('[Adaptive Learning] No valid training data from feedback');
        return { success: false, reason: 'no_valid_data' };
      }
      
      // Retrain model
      const retrainingResult = await ModelTrainer.retrainWithFeedback(trainingData);
      
      if (retrainingResult.success) {
        // Update last retraining time
        this.learningConfig.lastRetraining = Date.now();
        await this.saveConfiguration();
        
        // Calculate and update accuracy metrics
        await this.updateAccuracyMetrics(feedback);
        
        // Adjust thresholds based on new accuracy
        await this.adjustAdaptiveThresholds();
        
        console.log('[Adaptive Learning] ✓ Automatic retraining complete!');
        console.log(`[Adaptive Learning] New accuracy: ${(retrainingResult.accuracy * 100).toFixed(1)}%`);
        
        // Notify user
        try {
          await chrome.notifications.create('retraining-complete', {
            type: 'basic',
            iconUrl: '/icons/icon48.png',
            title: 'AI Model Updated',
            message: `Learned from ${feedback.length} feedbacks. Accuracy: ${(retrainingResult.accuracy * 100).toFixed(1)}%`,
            priority: 1
          });
          
          setTimeout(() => chrome.notifications.clear('retraining-complete'), 5000);
        } catch (notifError) {
          console.warn('[Adaptive Learning] Could not show notification:', notifError);
        }
        
        return { success: true, accuracy: retrainingResult.accuracy };
      } else {
        console.error('[Adaptive Learning] Retraining failed:', retrainingResult.error);
        return { success: false, error: retrainingResult.error };
      }
      
    } catch (error) {
      console.error('[Adaptive Learning] Retraining error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Prepare training data from user feedback
   */
  static async prepareFeedbackTrainingData(feedback) {
    const trainingData = [];
    
    for (const item of feedback) {
      // Only use feedback where user corrected our detection
      if (item.feedbackType === 'incorrect') {
        // We were wrong, learn from this
        const correctLabel = item.detectedThreatLevel === 'dangerous' ? 0 : 1; // Flip the label
        
        trainingData.push({
          url: item.url,
          label: correctLabel,
          features: item.issues || [],
          weight: 2.0 // Give more weight to corrections
        });
      } else if (item.feedbackType === 'correct') {
        // We were right, reinforce this
        const label = item.detectedThreatLevel === 'dangerous' ? 1 : 0;
        
        trainingData.push({
          url: item.url,
          label: label,
          features: item.issues || [],
          weight: 1.0
        });
      }
    }
    
    return trainingData;
  }
  
  /**
   * FEATURE 2: Adaptive Threshold Adjustment
   * Adjusts detection sensitivity based on accuracy
   */
  static async adjustAdaptiveThresholds() {
    try {
      console.log('[Adaptive Learning] Adjusting detection thresholds...');
      
      const { falsePositiveRate, falseNegativeRate, targetAccuracy } = this.learningConfig;
      
      // Calculate overall accuracy
      const totalErrors = falsePositiveRate + falseNegativeRate;
      const currentAccuracy = 1 - totalErrors;
      
      console.log(`[Adaptive Learning] Current accuracy: ${(currentAccuracy * 100).toFixed(1)}%`);
      console.log(`[Adaptive Learning] False positive rate: ${(falsePositiveRate * 100).toFixed(1)}%`);
      console.log(`[Adaptive Learning] False negative rate: ${(falseNegativeRate * 100).toFixed(1)}%`);
      
      let newThreshold = this.learningConfig.currentThreshold;
      
      // If too many false positives, increase threshold (be less aggressive)
      if (falsePositiveRate > 0.1) {
        newThreshold = Math.min(
          this.learningConfig.maxThreshold,
          newThreshold + 0.05
        );
        console.log('[Adaptive Learning] Too many false positives, increasing threshold');
      }
      
      // If too many false negatives, decrease threshold (be more aggressive)
      if (falseNegativeRate > 0.1) {
        newThreshold = Math.max(
          this.learningConfig.minThreshold,
          newThreshold - 0.05
        );
        console.log('[Adaptive Learning] Too many false negatives, decreasing threshold');
      }
      
      // If accuracy is good, move toward target
      if (currentAccuracy >= targetAccuracy) {
        const targetThreshold = this.learningConfig.baseThreshold;
        newThreshold = newThreshold * 0.9 + targetThreshold * 0.1; // Gradual adjustment
        console.log('[Adaptive Learning] Accuracy good, adjusting toward baseline');
      }
      
      // Update threshold if changed
      if (newThreshold !== this.learningConfig.currentThreshold) {
        this.learningConfig.currentThreshold = newThreshold;
        await this.saveConfiguration();
        
        console.log(`[Adaptive Learning] ✓ Threshold adjusted: ${this.learningConfig.currentThreshold.toFixed(3)}`);
      } else {
        console.log('[Adaptive Learning] Threshold unchanged');
      }
      
      return { success: true, threshold: newThreshold };
      
    } catch (error) {
      console.error('[Adaptive Learning] Threshold adjustment error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Update accuracy metrics from feedback
   */
  static async updateAccuracyMetrics(feedback) {
    let falsePositives = 0;
    let falseNegatives = 0;
    let totalFeedback = feedback.length;
    
    for (const item of feedback) {
      if (item.feedbackType === 'incorrect') {
        if (item.detectedThreatLevel === 'dangerous' || item.detectedThreatLevel === 'suspicious') {
          falsePositives++; // We said threat, but it was safe
        } else {
          falseNegatives++; // We said safe, but it was threat
        }
      }
    }
    
    this.learningConfig.falsePositiveRate = totalFeedback > 0 ? falsePositives / totalFeedback : 0;
    this.learningConfig.falseNegativeRate = totalFeedback > 0 ? falseNegatives / totalFeedback : 0;
    
    await this.saveConfiguration();
  }
  
  /**
   * FEATURE 3: Behavioral Pattern Recognition
   * Learns patterns from detected threats
   */
  static async initializePatternRecognition() {
    try {
      console.log('[Adaptive Learning] Initializing pattern recognition...');
      
      // Load existing patterns
      const result = await chrome.storage.local.get('learnedPatterns');
      
      if (result.learnedPatterns) {
        this.learningConfig.patternCache = new Map(Object.entries(result.learnedPatterns));
        console.log(`[Adaptive Learning] Loaded ${this.learningConfig.patternCache.size} learned patterns`);
      }
      
      return { success: true };
    } catch (error) {
      console.error('[Adaptive Learning] Pattern recognition init error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Learn new pattern from threat detection
   */
  static async learnPattern(url, threatFeatures) {
    try {
      // Extract pattern signature
      const pattern = this.extractPatternSignature(url, threatFeatures);
      
      if (!pattern) return;
      
      // Track pattern occurrence
      const currentCount = this.learningConfig.patternCache.get(pattern) || 0;
      const newCount = currentCount + 1;
      
      this.learningConfig.patternCache.set(pattern, newCount);
      
      // If pattern occurs frequently, save it as a learned pattern
      if (newCount >= this.learningConfig.minPatternOccurrences) {
        console.log(`[Adaptive Learning] 🎯 New pattern learned: ${pattern} (${newCount} occurrences)`);
        
        // Save learned patterns
        await chrome.storage.local.set({
          learnedPatterns: Object.fromEntries(this.learningConfig.patternCache)
        });
        
        return { success: true, pattern, occurrences: newCount };
      }
      
      return { success: true, pattern, occurrences: newCount, learned: false };
      
    } catch (error) {
      console.error('[Adaptive Learning] Pattern learning error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Extract pattern signature from URL and features
   */
  static extractPatternSignature(url, features) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      // Extract key pattern elements
      const patterns = [];
      
      // Domain patterns
      if (domain.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
        patterns.push('ip-address');
      }
      
      if (domain.split('.').length > 3) {
        patterns.push('subdomain-heavy');
      }
      
      // TLD patterns
      const tld = domain.split('.').pop();
      if (['tk', 'ml', 'ga', 'cf', 'gq'].includes(tld)) {
        patterns.push(`suspicious-tld-${tld}`);
      }
      
      // URL structure patterns
      if (urlObj.pathname.includes('login')) {
        patterns.push('login-page');
      }
      
      if (urlObj.pathname.includes('verify')) {
        patterns.push('verify-page');
      }
      
      if (urlObj.searchParams.toString().length > 100) {
        patterns.push('long-query');
      }
      
      // Feature patterns
      if (features && Array.isArray(features)) {
        features.forEach(feature => {
          if (feature.type) {
            patterns.push(`feature-${feature.type}`);
          }
        });
      }
      
      // Create composite pattern signature
      return patterns.length > 0 ? patterns.sort().join('|') : null;
      
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Check if URL matches learned patterns
   */
  static async checkLearnedPatterns(url, features) {
    const pattern = this.extractPatternSignature(url, features);
    
    if (!pattern) return { matched: false };
    
    const occurrences = this.learningConfig.patternCache.get(pattern) || 0;
    
    if (occurrences >= this.learningConfig.minPatternOccurrences) {
      return {
        matched: true,
        pattern,
        occurrences,
        confidence: Math.min(0.95, 0.5 + (occurrences * 0.05))
      };
    }
    
    return { matched: false };
  }
  
  /**
   * FEATURE 4: Behavioral Learning
   * Learns from user behavior and preferences
   */
  static startBehavioralLearning() {
    console.log('[Adaptive Learning] Starting behavioral learning...');
    
    // Monitor user interactions
    this.monitorUserBehavior();
    
    // Periodically analyze behavior patterns
    setInterval(() => {
      this.analyzeBehaviorPatterns();
    }, 3600000); // Every hour
  }
  
  /**
   * Monitor user behavior
   */
  static monitorUserBehavior() {
    // This will be called when user interacts with detections
    // Track which domains user trusts/distrusts
  }
  
  /**
   * Learn from user's domain interactions
   */
  static async learnFromUserInteraction(domain, action) {
    try {
      // Track user behavior
      const behaviorKey = `behavior-${domain}`;
      const currentBehavior = this.learningConfig.userBehaviorPatterns.get(behaviorKey) || {
        domain,
        trustCount: 0,
        distrustCount: 0,
        lastInteraction: Date.now()
      };
      
      // Update behavior based on action
      if (action === 'trust' || action === 'whitelist') {
        currentBehavior.trustCount++;
        
        // If user consistently trusts this domain, auto-whitelist
        if (currentBehavior.trustCount >= 3) {
          this.learningConfig.trustedDomains.add(domain);
          console.log(`[Adaptive Learning] 🎓 Learned to trust: ${domain}`);
        }
      } else if (action === 'distrust' || action === 'blacklist') {
        currentBehavior.distrustCount++;
        
        // If user consistently distrusts this domain, auto-blacklist
        if (currentBehavior.distrustCount >= 2) {
          this.learningConfig.suspiciousDomains.add(domain);
          console.log(`[Adaptive Learning] 🎓 Learned to distrust: ${domain}`);
        }
      }
      
      currentBehavior.lastInteraction = Date.now();
      this.learningConfig.userBehaviorPatterns.set(behaviorKey, currentBehavior);
      
      await this.saveConfiguration();
      
      return { success: true };
      
    } catch (error) {
      console.error('[Adaptive Learning] Behavior learning error:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Analyze behavior patterns
   */
  static async analyzeBehaviorPatterns() {
    try {
      console.log('[Adaptive Learning] Analyzing behavior patterns...');
      
      // Clean up old behavior data (older than 30 days)
      const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
      
      for (const [key, behavior] of this.learningConfig.userBehaviorPatterns.entries()) {
        if (behavior.lastInteraction < thirtyDaysAgo) {
          this.learningConfig.userBehaviorPatterns.delete(key);
        }
      }
      
      await this.saveConfiguration();
      
      console.log(`[Adaptive Learning] Behavior analysis complete. Tracking ${this.learningConfig.userBehaviorPatterns.size} domains`);
      
    } catch (error) {
      console.error('[Adaptive Learning] Behavior analysis error:', error);
    }
  }
  
  /**
   * Get current adaptive threshold
   */
  static getCurrentThreshold() {
    return this.learningConfig.currentThreshold;
  }
  
  /**
   * Check if domain is trusted by behavioral learning
   */
  static isTrustedByBehavior(domain) {
    return this.learningConfig.trustedDomains.has(domain);
  }
  
  /**
   * Check if domain is suspicious by behavioral learning
   */
  static isSuspiciousByBehavior(domain) {
    return this.learningConfig.suspiciousDomains.has(domain);
  }
  
  /**
   * Get learning statistics
   */
  static async getLearningStat() {
    return {
      lastRetraining: this.learningConfig.lastRetraining,
      currentThreshold: this.learningConfig.currentThreshold,
      falsePositiveRate: this.learningConfig.falsePositiveRate,
      falseNegativeRate: this.learningConfig.falseNegativeRate,
      accuracy: 1 - (this.learningConfig.falsePositiveRate + this.learningConfig.falseNegativeRate),
      learnedPatterns: this.learningConfig.patternCache.size,
      trustedDomains: this.learningConfig.trustedDomains.size,
      suspiciousDomains: this.learningConfig.suspiciousDomains.size,
      behaviorPatterns: this.learningConfig.userBehaviorPatterns.size
    };
  }
}

export default AdaptiveLearningEngine;
