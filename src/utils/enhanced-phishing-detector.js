/**
 * Enhanced Phishing Detector with World-Class AI/ML Features
 * Integrates all advanced detection capabilities
 */

import { analyzeURL } from './url-parser.js';
import { StorageManager } from './storage.js';
import { NotificationManager } from './notifications.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { reputationScorer } from './reputation-scorer.js';
import { advancedNLP } from '../ml/advanced-nlp.js';
import { logoDetector } from '../ml/logo-detector.js';
import { explainableAI } from './explainable-ai.js';
import { THREAT_LEVELS } from './constants.js';

/**
 * Enhanced Phishing Detection Engine
 * Combines multiple AI/ML models and threat intelligence sources
 */
export class EnhancedPhishingDetector {
  /**
   * Comprehensive link analysis with all world-class features
   * @param {string} url - URL to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Complete analysis with explanations
   */
  static async analyzeLink(url, options = {}) {
    try {
      console.log('[Enhanced APG] Starting comprehensive analysis:', url);

      // Phase 1: Get reputation score (aggregates multiple sources)
      const reputationResult = await reputationScorer.getReputationScore(url, options);
      
      if (!reputationResult.success) {
        return this.createErrorResult(url, reputationResult.error);
      }

      const reputation = reputationResult.report;

      // Phase 2: Content analysis (if provided)
      if (options.content) {
        const contentResult = await advancedNLP.analyzeText(options.content, {
          url: url,
          sender: options.sender
        });
        
        if (contentResult.success) {
          await reputationScorer.updateWithContent(url, options.content);
          reputation.contentAnalysis = contentResult;
        }
      }

      // Phase 3: Logo detection (if screenshot provided)
      if (options.screenshot) {
        const logoResult = await logoDetector.analyzeScreenshot(options.screenshot, url);
        
        if (logoResult.success) {
          await reputationScorer.updateWithScreenshot(url, options.screenshot);
          reputation.logoDetection = logoResult;
        }
      }

      // Phase 4: Generate explainable AI report
      const explanation = explainableAI.generateExplanation(reputation);

      // Phase 5: Determine final threat level
      const threatLevel = this.mapScoreToThreatLevel(reputation.overallScore);

      // Phase 6: Create comprehensive result
      const result = {
        url: url,
        timestamp: Date.now(),
        threatLevel: threatLevel,
        overallScore: reputation.overallScore,
        riskLevel: reputation.riskLevel,
        confidence: reputation.confidence,
        
        // Detailed scores
        scores: reputation.scores,
        
        // Analysis details
        details: reputation.details,
        
        // Explainable AI
        explanation: explanation,
        
        // Recommendation
        recommendation: reputation.recommendation,
        
        // Additional metadata
        analyzed: {
          reputation: true,
          content: !!options.content,
          logo: !!options.screenshot,
          nlp: !!reputation.contentAnalysis,
          safeBrowsing: !!reputation.details.safeBrowsing,
          phishTank: !!reputation.details.phishTank
        }
      };

      // Cache result
      await StorageManager.cacheThreat(url, result);

      // Update statistics
      await StorageManager.incrementScanned();
      if (threatLevel === THREAT_LEVELS.DANGEROUS) {
        await StorageManager.incrementBlocked();
        await NotificationManager.showThreatBlocked(url, threatLevel, explanation.riskFactors.length);
      }

      console.log('[Enhanced APG] Analysis complete:', {
        url,
        score: reputation.overallScore,
        risk: reputation.riskLevel,
        confidence: reputation.confidence
      });

      return result;

    } catch (error) {
      console.error('[Enhanced APG] Analysis error:', error);
      return this.createErrorResult(url, error.message);
    }
  }

  /**
   * Quick analysis (reputation only, no content/logo)
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} Quick analysis result
   */
  static async quickAnalyze(url) {
    return this.analyzeLink(url, { forceRefresh: false });
  }

  /**
   * Deep analysis (includes content and logo if available)
   * @param {string} url - URL to analyze
   * @param {string} content - Page/email content
   * @param {string} screenshot - Screenshot data URL
   * @returns {Promise<Object>} Deep analysis result
   */
  static async deepAnalyze(url, content, screenshot) {
    return this.analyzeLink(url, {
      content: content,
      screenshot: screenshot,
      forceRefresh: true
    });
  }

  /**
   * Batch analyze multiple URLs
   * @param {Array<string>} urls - URLs to analyze
   * @returns {Promise<Array>} Analysis results
   */
  static async analyzeLinks(urls) {
    const results = [];
    
    for (const url of urls) {
      const result = await this.quickAnalyze(url);
      results.push(result);
    }

    return results;
  }

  /**
   * Map reputation score to threat level
   * @param {number} score - Reputation score (0-100)
   * @returns {string} Threat level
   */
  static mapScoreToThreatLevel(score) {
    if (score >= 80) return THREAT_LEVELS.SAFE;
    if (score >= 60) return THREAT_LEVELS.UNKNOWN;
    if (score >= 40) return THREAT_LEVELS.SUSPICIOUS;
    return THREAT_LEVELS.DANGEROUS;
  }

  /**
   * Create error result
   * @param {string} url - URL
   * @param {string} error - Error message
   * @returns {Object} Error result
   */
  static createErrorResult(url, error) {
    return {
      url: url,
      timestamp: Date.now(),
      threatLevel: THREAT_LEVELS.UNKNOWN,
      overallScore: 50,
      riskLevel: 'unknown',
      confidence: 0,
      error: error,
      recommendation: {
        action: 'caution',
        message: 'Analysis incomplete. Proceed with caution.',
        color: '#ffc107',
        icon: '⚠'
      }
    };
  }

  /**
   * Format analysis for display
   * @param {Object} analysis - Analysis result
   * @returns {Object} Formatted result
   */
  static formatAnalysis(analysis) {
    return {
      ...analysis,
      color: this.getThreatColor(analysis.threatLevel),
      icon: this.getThreatIcon(analysis.threatLevel),
      description: this.getThreatDescription(analysis.threatLevel),
      scorePercentage: analysis.overallScore,
      riskFactorCount: analysis.explanation?.riskFactors?.length || 0,
      safetyIndicatorCount: analysis.explanation?.safetyIndicators?.length || 0
    };
  }

  /**
   * Get threat color
   * @param {string} threatLevel - Threat level
   * @returns {string} Color code
   */
  static getThreatColor(threatLevel) {
    switch (threatLevel) {
      case THREAT_LEVELS.SAFE:
        return '#28a745';
      case THREAT_LEVELS.SUSPICIOUS:
        return '#ffc107';
      case THREAT_LEVELS.DANGEROUS:
        return '#dc3545';
      default:
        return '#6c757d';
    }
  }

  /**
   * Get threat icon
   * @param {string} threatLevel - Threat level
   * @returns {string} Icon
   */
  static getThreatIcon(threatLevel) {
    switch (threatLevel) {
      case THREAT_LEVELS.SAFE:
        return '✓';
      case THREAT_LEVELS.SUSPICIOUS:
        return '⚠';
      case THREAT_LEVELS.DANGEROUS:
        return '✕';
      default:
        return '?';
    }
  }

  /**
   * Get threat description
   * @param {string} threatLevel - Threat level
   * @returns {string} Description
   */
  static getThreatDescription(threatLevel) {
    switch (threatLevel) {
      case THREAT_LEVELS.SAFE:
        return 'This link appears to be safe';
      case THREAT_LEVELS.SUSPICIOUS:
        return 'This link has suspicious characteristics';
      case THREAT_LEVELS.DANGEROUS:
        return 'This link is likely a phishing attempt';
      default:
        return 'This link requires careful review';
    }
  }

  /**
   * Get detailed explanation for user
   * @param {Object} analysis - Analysis result
   * @returns {string} Human-readable explanation
   */
  static getDetailedExplanation(analysis) {
    if (!analysis.explanation) {
      return 'Analysis incomplete';
    }

    const { summary, riskFactors, safetyIndicators, recommendations } = analysis.explanation;
    
    let text = `${summary}\n\n`;

    if (riskFactors.length > 0) {
      text += 'Risk Factors:\n';
      riskFactors.forEach((factor, i) => {
        text += `${i + 1}. ${factor.icon} ${factor.description}\n`;
      });
      text += '\n';
    }

    if (safetyIndicators.length > 0) {
      text += 'Safety Indicators:\n';
      safetyIndicators.forEach((indicator, i) => {
        text += `${i + 1}. ${indicator.icon} ${indicator.description}\n`;
      });
      text += '\n';
    }

    if (recommendations.length > 0) {
      text += 'Recommendations:\n';
      recommendations.forEach((rec, i) => {
        text += `${i + 1}. ${rec.icon} ${rec.action}: ${rec.reason}\n`;
      });
    }

    return text;
  }
}

export default EnhancedPhishingDetector;
