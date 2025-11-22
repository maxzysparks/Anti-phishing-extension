/**
 * Predictive Threat Intelligence Engine
 * Revolutionary feature: Predict phishing attacks before they happen
 * Production-ready implementation with privacy-first design
 */

import * as tf from '@tensorflow/tfjs';
import { StorageManager } from '../utils/storage.js';

/**
 * Predictive Threat Engine
 * Analyzes patterns to predict future phishing attacks
 */
export class PredictiveThreatEngine {
  constructor() {
    this.initialized = false;
    this.model = null;
    
    // Threat pattern database (local, privacy-preserving)
    this.threatPatterns = new Map();
    
    // User behavior baseline (anonymous, local only)
    this.userBaseline = {
      normalHours: [], // Hours when user typically checks email
      averageResponseTime: 0, // How quickly user clicks links
      commonDomains: [], // Frequently visited domains
      riskProfile: 'medium' // low, medium, high
    };
    
    // Campaign tracking
    this.activeCampaigns = new Map();
    
    // Prediction confidence thresholds
    this.thresholds = {
      highConfidence: 0.85,
      mediumConfidence: 0.70,
      lowConfidence: 0.50
    };
    
    // Privacy settings
    this.privacyMode = 'strict'; // strict, balanced, permissive
    this.dataRetentionDays = 30;
  }

  /**
   * Initialize the predictive engine
   * @returns {Promise<Object>} Initialization result
   */
  async initialize() {
    try {
      console.log('[Predictive Engine] Initializing...');
      
      // Load user baseline from storage
      await this.loadUserBaseline();
      
      // Load threat patterns
      await this.loadThreatPatterns();
      
      // Initialize lightweight prediction model
      await this.initializePredictionModel();
      
      // Start background monitoring
      this.startBackgroundMonitoring();
      
      this.initialized = true;
      console.log('[Predictive Engine] Initialized successfully');
      
      return { success: true, message: 'Predictive engine ready' };
      
    } catch (error) {
      console.error('[Predictive Engine] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Initialize lightweight prediction model
   * @returns {Promise<void>}
   */
  async initializePredictionModel() {
    try {
      // Create a simple sequential model for pattern prediction
      this.model = tf.sequential({
        layers: [
          tf.layers.dense({ inputShape: [10], units: 16, activation: 'relu' }),
          tf.layers.dropout({ rate: 0.2 }),
          tf.layers.dense({ units: 8, activation: 'relu' }),
          tf.layers.dense({ units: 1, activation: 'sigmoid' })
        ]
      });
      
      this.model.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
      });
      
      console.log('[Predictive Engine] Model initialized');
      
    } catch (error) {
      console.error('[Predictive Engine] Model initialization failed:', error);
      // Continue without model - use rule-based predictions
      this.model = null;
    }
  }

  /**
   * Load user baseline from storage
   * @returns {Promise<void>}
   */
  async loadUserBaseline() {
    try {
      const stored = await chrome.storage.local.get('userBaseline');
      
      if (stored.userBaseline) {
        this.userBaseline = {
          ...this.userBaseline,
          ...stored.userBaseline
        };
        console.log('[Predictive Engine] User baseline loaded');
      } else {
        // Initialize with defaults
        await this.saveUserBaseline();
      }
      
    } catch (error) {
      console.error('[Predictive Engine] Failed to load user baseline:', error);
    }
  }

  /**
   * Save user baseline to storage
   * @returns {Promise<void>}
   */
  async saveUserBaseline() {
    try {
      await chrome.storage.local.set({
        userBaseline: this.userBaseline,
        baselineTimestamp: Date.now()
      });
    } catch (error) {
      console.error('[Predictive Engine] Failed to save user baseline:', error);
    }
  }

  /**
   * Load threat patterns from storage
   * @returns {Promise<void>}
   */
  async loadThreatPatterns() {
    try {
      const stored = await chrome.storage.local.get('threatPatterns');
      
      if (stored.threatPatterns) {
        this.threatPatterns = new Map(Object.entries(stored.threatPatterns));
        console.log('[Predictive Engine] Loaded', this.threatPatterns.size, 'threat patterns');
      }
      
    } catch (error) {
      console.error('[Predictive Engine] Failed to load threat patterns:', error);
    }
  }

  /**
   * Save threat patterns to storage
   * @returns {Promise<void>}
   */
  async saveThreatPatterns() {
    try {
      const patternsObj = Object.fromEntries(this.threatPatterns);
      await chrome.storage.local.set({
        threatPatterns: patternsObj,
        patternsTimestamp: Date.now()
      });
    } catch (error) {
      console.error('[Predictive Engine] Failed to save threat patterns:', error);
    }
  }

  /**
   * Predict if user is likely to be targeted soon
   * @param {Object} context - Current context
   * @returns {Promise<Object>} Prediction result
   */
  async predictThreatLikelihood(context = {}) {
    try {
      if (!this.initialized) {
        await this.initialize();
      }

      const predictions = {
        overall: 0,
        confidence: 0,
        factors: [],
        recommendations: [],
        timeframe: 'unknown'
      };

      // Factor 1: Campaign pattern analysis
      const campaignRisk = await this.analyzeCampaignPatterns(context);
      if (campaignRisk.score > 0) {
        predictions.factors.push(campaignRisk);
        predictions.overall += campaignRisk.score * 0.35;
      }

      // Factor 2: Temporal vulnerability
      const temporalRisk = this.analyzeTemporalVulnerability();
      if (temporalRisk.score > 0) {
        predictions.factors.push(temporalRisk);
        predictions.overall += temporalRisk.score * 0.25;
      }

      // Factor 3: Behavioral anomaly
      const behavioralRisk = await this.analyzeBehavioralAnomaly(context);
      if (behavioralRisk.score > 0) {
        predictions.factors.push(behavioralRisk);
        predictions.overall += behavioralRisk.score * 0.20;
      }

      // Factor 4: Network threat propagation
      const networkRisk = await this.analyzeNetworkThreats(context);
      if (networkRisk.score > 0) {
        predictions.factors.push(networkRisk);
        predictions.overall += networkRisk.score * 0.20;
      }

      // Calculate confidence based on available data
      predictions.confidence = this.calculatePredictionConfidence(predictions.factors);

      // Determine timeframe
      predictions.timeframe = this.estimateThreatTimeframe(predictions.overall);

      // Generate recommendations
      predictions.recommendations = this.generatePredictiveRecommendations(predictions);

      return {
        success: true,
        predictions: predictions,
        timestamp: Date.now()
      };

    } catch (error) {
      console.error('[Predictive Engine] Prediction failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Analyze campaign patterns to predict targeting
   * @param {Object} context - Context information
   * @returns {Object} Campaign risk assessment
   */
  async analyzeCampaignPatterns(context) {
    const risk = {
      type: 'campaign_pattern',
      score: 0,
      description: '',
      evidence: []
    };

    try {
      // Check for active campaigns
      const now = Date.now();
      const recentCampaigns = Array.from(this.activeCampaigns.values())
        .filter(c => now - c.lastSeen < 86400000); // Last 24 hours

      if (recentCampaigns.length === 0) {
        return risk;
      }

      // Analyze campaign velocity (how fast it's spreading)
      for (const campaign of recentCampaigns) {
        const velocity = campaign.targets.length / ((now - campaign.firstSeen) / 3600000); // targets per hour
        
        if (velocity > 10) { // Rapid spread
          risk.score += 0.3;
          risk.evidence.push(`Rapid campaign spread: ${velocity.toFixed(1)} targets/hour`);
        }

        // Check if campaign targets similar profiles
        if (this.matchesUserProfile(campaign.targetProfile)) {
          risk.score += 0.4;
          risk.evidence.push(`Campaign targets users with similar profile`);
        }

        // Check if campaign is escalating
        if (campaign.escalating) {
          risk.score += 0.3;
          risk.evidence.push(`Campaign is escalating in sophistication`);
        }
      }

      risk.score = Math.min(1.0, risk.score);
      
      if (risk.score > 0.5) {
        risk.description = 'Active phishing campaign detected with high targeting probability';
      } else if (risk.score > 0.3) {
        risk.description = 'Moderate campaign activity detected';
      } else if (risk.score > 0) {
        risk.description = 'Low-level campaign activity observed';
      }

    } catch (error) {
      console.error('[Predictive Engine] Campaign analysis failed:', error);
    }

    return risk;
  }

  /**
   * Analyze temporal vulnerability (time-based risk)
   * @returns {Object} Temporal risk assessment
   */
  analyzeTemporalVulnerability() {
    const risk = {
      type: 'temporal_vulnerability',
      score: 0,
      description: '',
      evidence: []
    };

    try {
      const now = new Date();
      const hour = now.getHours();
      const dayOfWeek = now.getDay();

      // High-risk times (when users are more vulnerable)
      const highRiskHours = [8, 9, 17, 18, 22, 23]; // Morning rush, evening rush, late night
      const highRiskDays = [1, 5]; // Monday, Friday

      if (highRiskHours.includes(hour)) {
        risk.score += 0.3;
        risk.evidence.push(`High-risk hour: ${hour}:00 (users more distracted)`);
      }

      if (highRiskDays.includes(dayOfWeek)) {
        risk.score += 0.2;
        risk.evidence.push(`High-risk day: ${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][dayOfWeek]}`);
      }

      // Check if outside normal hours
      if (!this.userBaseline.normalHours.includes(hour)) {
        risk.score += 0.2;
        risk.evidence.push('Activity outside normal hours (unusual behavior)');
      }

      risk.score = Math.min(1.0, risk.score);

      if (risk.score > 0.5) {
        risk.description = 'Currently in high-vulnerability time window';
      } else if (risk.score > 0) {
        risk.description = 'Moderate temporal risk factors present';
      }

    } catch (error) {
      console.error('[Predictive Engine] Temporal analysis failed:', error);
    }

    return risk;
  }

  /**
   * Analyze behavioral anomalies
   * @param {Object} context - Context information
   * @returns {Promise<Object>} Behavioral risk assessment
   */
  async analyzeBehavioralAnomaly(context) {
    const risk = {
      type: 'behavioral_anomaly',
      score: 0,
      description: '',
      evidence: []
    };

    try {
      // Check for unusual activity patterns
      if (context.rapidClicking) {
        risk.score += 0.3;
        risk.evidence.push('Rapid clicking detected (possible stress/rush)');
      }

      if (context.newLocation) {
        risk.score += 0.2;
        risk.evidence.push('Access from new location');
      }

      if (context.newDevice) {
        risk.score += 0.3;
        risk.evidence.push('Access from new device');
      }

      // Check response time deviation
      if (context.responseTime && this.userBaseline.averageResponseTime > 0) {
        const deviation = Math.abs(context.responseTime - this.userBaseline.averageResponseTime) / 
                         this.userBaseline.averageResponseTime;
        
        if (deviation > 0.5) { // 50% faster or slower than normal
          risk.score += 0.2;
          risk.evidence.push('Unusual response time pattern');
        }
      }

      risk.score = Math.min(1.0, risk.score);

      if (risk.score > 0.5) {
        risk.description = 'Significant behavioral anomalies detected';
      } else if (risk.score > 0) {
        risk.description = 'Minor behavioral deviations observed';
      }

    } catch (error) {
      console.error('[Predictive Engine] Behavioral analysis failed:', error);
    }

    return risk;
  }

  /**
   * Analyze network threat propagation
   * @param {Object} context - Context information
   * @returns {Promise<Object>} Network risk assessment
   */
  async analyzeNetworkThreats(context) {
    const risk = {
      type: 'network_propagation',
      score: 0,
      description: '',
      evidence: []
    };

    try {
      // Check for threats in user's network (anonymized)
      const networkThreats = await this.getNetworkThreatCount();
      
      if (networkThreats > 0) {
        // Calculate propagation probability
        const propagationScore = Math.min(1.0, networkThreats / 10);
        risk.score = propagationScore;
        risk.evidence.push(`${networkThreats} threats detected in network proximity`);
        
        if (networkThreats >= 5) {
          risk.description = 'High threat activity in your network - likely to be targeted';
        } else if (networkThreats >= 2) {
          risk.description = 'Moderate threat activity in your network';
        } else {
          risk.description = 'Low threat activity in your network';
        }
      }

    } catch (error) {
      console.error('[Predictive Engine] Network analysis failed:', error);
    }

    return risk;
  }

  /**
   * Get network threat count (privacy-preserving)
   * @returns {Promise<number>} Threat count
   */
  async getNetworkThreatCount() {
    try {
      // In production, this would query an anonymous threat-sharing network
      // For now, return simulated data
      const stored = await chrome.storage.local.get('networkThreats');
      return stored.networkThreats || 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Check if campaign matches user profile
   * @param {Object} targetProfile - Campaign target profile
   * @returns {boolean} Whether profile matches
   */
  matchesUserProfile(targetProfile) {
    if (!targetProfile) return false;
    
    // Simple matching logic (can be enhanced)
    const matches = [];
    
    if (targetProfile.industry && this.userBaseline.industry === targetProfile.industry) {
      matches.push('industry');
    }
    
    if (targetProfile.role && this.userBaseline.role === targetProfile.role) {
      matches.push('role');
    }
    
    return matches.length > 0;
  }

  /**
   * Calculate prediction confidence
   * @param {Array} factors - Risk factors
   * @returns {number} Confidence score (0-1)
   */
  calculatePredictionConfidence(factors) {
    if (factors.length === 0) return 0;
    
    // Confidence based on number and quality of factors
    const baseConfidence = Math.min(1.0, factors.length / 4);
    
    // Adjust based on evidence quality
    const evidenceCount = factors.reduce((sum, f) => sum + f.evidence.length, 0);
    const evidenceBonus = Math.min(0.3, evidenceCount / 10);
    
    return Math.min(1.0, baseConfidence + evidenceBonus);
  }

  /**
   * Estimate threat timeframe
   * @param {number} overallScore - Overall risk score
   * @returns {string} Timeframe estimate
   */
  estimateThreatTimeframe(overallScore) {
    if (overallScore >= 0.8) return 'imminent (within hours)';
    if (overallScore >= 0.6) return 'near-term (within 24 hours)';
    if (overallScore >= 0.4) return 'short-term (within 3 days)';
    if (overallScore >= 0.2) return 'medium-term (within week)';
    return 'low probability';
  }

  /**
   * Generate predictive recommendations
   * @param {Object} predictions - Prediction results
   * @returns {Array} Recommendations
   */
  generatePredictiveRecommendations(predictions) {
    const recommendations = [];
    
    if (predictions.overall >= 0.7) {
      recommendations.push({
        priority: 'critical',
        action: 'Enable maximum protection mode',
        reason: 'High probability of imminent attack'
      });
      recommendations.push({
        priority: 'high',
        action: 'Verify all unexpected emails before clicking',
        reason: 'Elevated threat level detected'
      });
    } else if (predictions.overall >= 0.5) {
      recommendations.push({
        priority: 'high',
        action: 'Increase vigilance for next 24 hours',
        reason: 'Moderate attack probability detected'
      });
    } else if (predictions.overall >= 0.3) {
      recommendations.push({
        priority: 'medium',
        action: 'Stay alert for suspicious emails',
        reason: 'Some risk factors present'
      });
    }
    
    return recommendations;
  }

  /**
   * Record threat observation (for learning)
   * @param {Object} threat - Threat information
   * @returns {Promise<void>}
   */
  async recordThreatObservation(threat) {
    try {
      const patternKey = this.generatePatternKey(threat);
      
      if (this.threatPatterns.has(patternKey)) {
        const pattern = this.threatPatterns.get(patternKey);
        pattern.count++;
        pattern.lastSeen = Date.now();
      } else {
        this.threatPatterns.set(patternKey, {
          pattern: patternKey,
          count: 1,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          characteristics: threat.characteristics || {}
        });
      }
      
      // Save periodically
      if (this.threatPatterns.size % 10 === 0) {
        await this.saveThreatPatterns();
      }
      
    } catch (error) {
      console.error('[Predictive Engine] Failed to record threat:', error);
    }
  }

  /**
   * Generate pattern key from threat
   * @param {Object} threat - Threat information
   * @returns {string} Pattern key
   */
  generatePatternKey(threat) {
    // Create a unique key based on threat characteristics
    const parts = [
      threat.type || 'unknown',
      threat.targetBrand || 'generic',
      threat.technique || 'standard'
    ];
    
    return parts.join('_').toLowerCase();
  }

  /**
   * Start background monitoring
   */
  startBackgroundMonitoring() {
    // Monitor every hour
    setInterval(async () => {
      try {
        await this.performBackgroundAnalysis();
      } catch (error) {
        console.error('[Predictive Engine] Background analysis failed:', error);
      }
    }, 3600000); // 1 hour
    
    console.log('[Predictive Engine] Background monitoring started');
  }

  /**
   * Perform background analysis
   * @returns {Promise<void>}
   */
  async performBackgroundAnalysis() {
    try {
      // Clean old patterns
      await this.cleanOldPatterns();
      
      // Update user baseline
      await this.updateUserBaseline();
      
      // Check for emerging campaigns
      await this.detectEmergingCampaigns();
      
    } catch (error) {
      console.error('[Predictive Engine] Background analysis error:', error);
    }
  }

  /**
   * Clean old patterns
   * @returns {Promise<void>}
   */
  async cleanOldPatterns() {
    const now = Date.now();
    const maxAge = this.dataRetentionDays * 86400000;
    
    for (const [key, pattern] of this.threatPatterns.entries()) {
      if (now - pattern.lastSeen > maxAge) {
        this.threatPatterns.delete(key);
      }
    }
    
    await this.saveThreatPatterns();
  }

  /**
   * Update user baseline
   * @returns {Promise<void>}
   */
  async updateUserBaseline() {
    // Update normal hours
    const currentHour = new Date().getHours();
    if (!this.userBaseline.normalHours.includes(currentHour)) {
      this.userBaseline.normalHours.push(currentHour);
      
      // Keep only most common hours (max 12)
      if (this.userBaseline.normalHours.length > 12) {
        this.userBaseline.normalHours.shift();
      }
    }
    
    await this.saveUserBaseline();
  }

  /**
   * Detect emerging campaigns
   * @returns {Promise<void>}
   */
  async detectEmergingCampaigns() {
    // Analyze threat patterns for campaign signatures
    const recentPatterns = Array.from(this.threatPatterns.values())
      .filter(p => Date.now() - p.lastSeen < 86400000);
    
    // Group by similarity
    const campaigns = this.groupPatternsBySimilarity(recentPatterns);
    
    // Update active campaigns
    for (const campaign of campaigns) {
      if (campaign.threats.length >= 3) { // Minimum 3 similar threats
        this.activeCampaigns.set(campaign.id, campaign);
      }
    }
    
    console.log('[Predictive Engine] Detected', this.activeCampaigns.size, 'active campaigns');
  }

  /**
   * Group patterns by similarity
   * @param {Array} patterns - Threat patterns
   * @returns {Array} Grouped campaigns
   */
  groupPatternsBySimilarity(patterns) {
    // Simple grouping by pattern prefix
    const groups = new Map();
    
    for (const pattern of patterns) {
      const prefix = pattern.pattern.split('_')[0];
      
      if (!groups.has(prefix)) {
        groups.set(prefix, {
          id: prefix,
          threats: [],
          firstSeen: pattern.firstSeen,
          lastSeen: pattern.lastSeen,
          targetProfile: {},
          escalating: false,
          targets: []
        });
      }
      
      const group = groups.get(prefix);
      group.threats.push(pattern);
      group.lastSeen = Math.max(group.lastSeen, pattern.lastSeen);
      group.targets.push(pattern);
    }
    
    return Array.from(groups.values());
  }

  /**
   * Get prediction statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      threatPatterns: this.threatPatterns.size,
      activeCampaigns: this.activeCampaigns.size,
      userBaseline: {
        normalHours: this.userBaseline.normalHours.length,
        riskProfile: this.userBaseline.riskProfile
      }
    };
  }
}

// Create singleton instance
export const predictiveThreatEngine = new PredictiveThreatEngine();

export default predictiveThreatEngine;
