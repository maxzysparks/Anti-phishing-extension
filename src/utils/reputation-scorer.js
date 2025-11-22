/**
 * Real-time URL Reputation Scoring System
 * Aggregates multiple threat intelligence sources and ML models
 */

import { checkUrlSafety, getThreatReport } from './safe-browsing.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { advancedNLP } from '../ml/advanced-nlp.js';
import { logoDetector } from '../ml/logo-detector.js';
import { URLParser } from './url-parser.js';

/**
 * Reputation Scorer
 * Combines multiple data sources to generate comprehensive URL reputation scores
 */
export class ReputationScorer {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 3600000; // 1 hour
    
    // Scoring weights for different factors
    this.weights = {
      safeBrowsing: 0.25,
      phishTank: 0.20,
      urlAnalysis: 0.15,
      domainAge: 0.10,
      sslCertificate: 0.10,
      contentAnalysis: 0.10,
      logoDetection: 0.10
    };
  }

  /**
   * Get comprehensive reputation score for URL
   * @param {string} url - URL to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Reputation score and details
   */
  async getReputationScore(url, options = {}) {
    try {
      // Check cache first
      const cached = this.getFromCache(url);
      if (cached && !options.forceRefresh) {
        return cached;
      }

      console.log('[Reputation Scorer] Analyzing:', url);

      // Run all analyses in parallel
      const [
        safeBrowsingResult,
        phishTankResult,
        urlAnalysisResult,
        domainInfoResult,
        sslResult
      ] = await Promise.allSettled([
        this.checkSafeBrowsing(url),
        this.checkPhishTank(url),
        this.analyzeURL(url),
        this.getDomainInfo(url),
        this.checkSSL(url)
      ]);

      // Extract results
      const safeBrowsing = safeBrowsingResult.status === 'fulfilled' ? safeBrowsingResult.value : null;
      const phishTank = phishTankResult.status === 'fulfilled' ? phishTankResult.value : null;
      const urlAnalysis = urlAnalysisResult.status === 'fulfilled' ? urlAnalysisResult.value : null;
      const domainInfo = domainInfoResult.status === 'fulfilled' ? domainInfoResult.value : null;
      const ssl = sslResult.status === 'fulfilled' ? sslResult.value : null;

      // Calculate individual scores
      const scores = {
        safeBrowsing: this.scoreSafeBrowsing(safeBrowsing),
        phishTank: this.scorePhishTank(phishTank),
        urlAnalysis: this.scoreURLAnalysis(urlAnalysis),
        domainAge: this.scoreDomainAge(domainInfo),
        sslCertificate: this.scoreSSL(ssl),
        contentAnalysis: 0, // Will be updated if content is provided
        logoDetection: 0 // Will be updated if screenshot is provided
      };

      // Calculate weighted overall score
      const overallScore = this.calculateOverallScore(scores);

      // Determine risk level
      const riskLevel = this.getRiskLevel(overallScore);

      // Generate detailed report
      const report = {
        url: url,
        timestamp: Date.now(),
        overallScore: overallScore,
        riskLevel: riskLevel,
        scores: scores,
        details: {
          safeBrowsing: safeBrowsing,
          phishTank: phishTank,
          urlAnalysis: urlAnalysis,
          domainInfo: domainInfo,
          ssl: ssl
        },
        recommendation: this.getRecommendation(overallScore, riskLevel),
        confidence: this.calculateConfidence(scores)
      };

      // Cache the result
      this.addToCache(url, report);

      return {
        success: true,
        report: report
      };

    } catch (error) {
      console.error('[Reputation Scorer] Error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Check Google Safe Browsing
   * @param {string} url - URL to check
   * @returns {Promise<Object>} Safe Browsing result
   */
  async checkSafeBrowsing(url) {
    try {
      const result = await getThreatReport(url);
      return result;
    } catch (error) {
      console.error('[Reputation Scorer] Safe Browsing error:', error);
      return null;
    }
  }

  /**
   * Check PhishTank database
   * @param {string} url - URL to check
   * @returns {Promise<Object>} PhishTank result
   */
  async checkPhishTank(url) {
    try {
      const result = await ThreatIntelligence.checkURL(url);
      return result;
    } catch (error) {
      console.error('[Reputation Scorer] PhishTank error:', error);
      return null;
    }
  }

  /**
   * Analyze URL structure
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} URL analysis result
   */
  async analyzeURL(url) {
    try {
      const parsed = URLParser.parse(url);
      const suspicious = URLParser.detectSuspiciousPatterns(url);
      
      return {
        parsed: parsed,
        suspicious: suspicious,
        score: suspicious.score
      };
    } catch (error) {
      console.error('[Reputation Scorer] URL analysis error:', error);
      return null;
    }
  }

  /**
   * Get domain information
   * @param {string} url - URL to check
   * @returns {Promise<Object>} Domain info
   */
  async getDomainInfo(url) {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname;
      
      // In production, query WHOIS API or domain age service
      // For now, return basic info
      return {
        domain: domain,
        age: null, // Would be fetched from WHOIS
        registrar: null,
        isNewDomain: false // Would be determined from age
      };
    } catch (error) {
      console.error('[Reputation Scorer] Domain info error:', error);
      return null;
    }
  }

  /**
   * Check SSL certificate
   * @param {string} url - URL to check
   * @returns {Promise<Object>} SSL info
   */
  async checkSSL(url) {
    try {
      const parsed = new URL(url);
      
      return {
        hasSSL: parsed.protocol === 'https:',
        valid: parsed.protocol === 'https:', // Simplified
        issuer: null, // Would require certificate inspection
        expiryDate: null
      };
    } catch (error) {
      console.error('[Reputation Scorer] SSL check error:', error);
      return null;
    }
  }

  /**
   * Analyze page content
   * @param {string} url - URL
   * @param {string} content - Page content
   * @returns {Promise<Object>} Content analysis
   */
  async analyzeContent(url, content) {
    try {
      const nlpResult = await advancedNLP.analyzeText(content);
      return nlpResult;
    } catch (error) {
      console.error('[Reputation Scorer] Content analysis error:', error);
      return null;
    }
  }

  /**
   * Analyze screenshot for logo detection
   * @param {string} url - URL
   * @param {string} screenshot - Screenshot data URL
   * @returns {Promise<Object>} Logo detection result
   */
  async analyzeScreenshot(url, screenshot) {
    try {
      const parsed = new URL(url);
      const result = await logoDetector.analyzeScreenshot(screenshot, parsed.hostname);
      return result;
    } catch (error) {
      console.error('[Reputation Scorer] Screenshot analysis error:', error);
      return null;
    }
  }

  /**
   * Score Safe Browsing result
   * @param {Object} result - Safe Browsing result
   * @returns {number} Score (0-1, higher is safer)
   */
  scoreSafeBrowsing(result) {
    if (!result) return 0.5; // Neutral if unavailable
    
    if (result.safe) return 1.0;
    
    // Score based on threat severity
    const severityScores = {
      'critical': 0.0,
      'high': 0.2,
      'medium': 0.4,
      'low': 0.6,
      'none': 1.0
    };
    
    return severityScores[result.highestSeverity] || 0.5;
  }

  /**
   * Score PhishTank result
   * @param {Object} result - PhishTank result
   * @returns {number} Score (0-1, higher is safer)
   */
  scorePhishTank(result) {
    if (!result) return 0.5;
    
    if (result.isPhishing) return 0.0;
    return 1.0;
  }

  /**
   * Score URL analysis
   * @param {Object} result - URL analysis result
   * @returns {number} Score (0-1, higher is safer)
   */
  scoreURLAnalysis(result) {
    if (!result) return 0.5;
    
    // Invert suspicious score (higher suspicious = lower safety)
    return 1.0 - result.score;
  }

  /**
   * Score domain age
   * @param {Object} result - Domain info
   * @returns {number} Score (0-1, higher is safer)
   */
  scoreDomainAge(result) {
    if (!result || !result.age) return 0.5;
    
    // Newer domains are more suspicious
    const ageInDays = result.age;
    
    if (ageInDays < 30) return 0.3;
    if (ageInDays < 90) return 0.5;
    if (ageInDays < 365) return 0.7;
    return 1.0;
  }

  /**
   * Score SSL certificate
   * @param {Object} result - SSL info
   * @returns {number} Score (0-1, higher is safer)
   */
  scoreSSL(result) {
    if (!result) return 0.5;
    
    if (!result.hasSSL) return 0.3;
    if (!result.valid) return 0.5;
    return 1.0;
  }

  /**
   * Calculate overall weighted score
   * @param {Object} scores - Individual scores
   * @returns {number} Overall score (0-100)
   */
  calculateOverallScore(scores) {
    let totalScore = 0;
    let totalWeight = 0;
    
    Object.keys(this.weights).forEach(key => {
      if (scores[key] !== undefined && scores[key] !== null) {
        totalScore += scores[key] * this.weights[key];
        totalWeight += this.weights[key];
      }
    });
    
    // Normalize to 0-100 scale
    const normalizedScore = totalWeight > 0 ? (totalScore / totalWeight) * 100 : 50;
    
    return Math.round(normalizedScore);
  }

  /**
   * Get risk level from score
   * @param {number} score - Overall score (0-100)
   * @returns {string} Risk level
   */
  getRiskLevel(score) {
    if (score >= 80) return 'safe';
    if (score >= 60) return 'low';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'high';
    return 'critical';
  }

  /**
   * Get recommendation based on score and risk level
   * @param {number} score - Overall score
   * @param {string} riskLevel - Risk level
   * @returns {Object} Recommendation
   */
  getRecommendation(score, riskLevel) {
    const recommendations = {
      'safe': {
        action: 'allow',
        message: 'This URL appears to be safe to visit',
        color: '#28a745',
        icon: '✓'
      },
      'low': {
        action: 'proceed',
        message: 'This URL appears mostly safe, but exercise normal caution',
        color: '#17a2b8',
        icon: 'ℹ'
      },
      'medium': {
        action: 'caution',
        message: 'This URL has some suspicious indicators. Proceed with caution',
        color: '#ffc107',
        icon: '⚠'
      },
      'high': {
        action: 'warn',
        message: 'This URL is likely dangerous. Avoid visiting unless absolutely necessary',
        color: '#fd7e14',
        icon: '⚠'
      },
      'critical': {
        action: 'block',
        message: 'This URL is highly dangerous. Do NOT visit this site',
        color: '#dc3545',
        icon: '✕'
      }
    };
    
    return recommendations[riskLevel] || recommendations['medium'];
  }

  /**
   * Calculate confidence in the score
   * @param {Object} scores - Individual scores
   * @returns {number} Confidence (0-100)
   */
  calculateConfidence(scores) {
    // Count how many data sources provided results
    const availableSources = Object.values(scores).filter(s => s !== null && s !== 0).length;
    const totalSources = Object.keys(scores).length;
    
    // Confidence based on data availability
    const confidence = (availableSources / totalSources) * 100;
    
    return Math.round(confidence);
  }

  /**
   * Update score with content analysis
   * @param {string} url - URL
   * @param {string} content - Page content
   * @returns {Promise<Object>} Updated report
   */
  async updateWithContent(url, content) {
    try {
      const cached = this.getFromCache(url);
      if (!cached) {
        return await this.getReputationScore(url);
      }
      
      const contentAnalysis = await this.analyzeContent(url, content);
      
      if (contentAnalysis && contentAnalysis.success) {
        cached.report.scores.contentAnalysis = 1.0 - contentAnalysis.phishingProbability;
        cached.report.details.contentAnalysis = contentAnalysis;
        
        // Recalculate overall score
        cached.report.overallScore = this.calculateOverallScore(cached.report.scores);
        cached.report.riskLevel = this.getRiskLevel(cached.report.overallScore);
        cached.report.recommendation = this.getRecommendation(
          cached.report.overallScore,
          cached.report.riskLevel
        );
        
        this.addToCache(url, cached.report);
      }
      
      return {
        success: true,
        report: cached.report
      };
      
    } catch (error) {
      console.error('[Reputation Scorer] Content update error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update score with screenshot analysis
   * @param {string} url - URL
   * @param {string} screenshot - Screenshot data URL
   * @returns {Promise<Object>} Updated report
   */
  async updateWithScreenshot(url, screenshot) {
    try {
      const cached = this.getFromCache(url);
      if (!cached) {
        return await this.getReputationScore(url);
      }
      
      const logoAnalysis = await this.analyzeScreenshot(url, screenshot);
      
      if (logoAnalysis && logoAnalysis.success) {
        const riskScore = logoAnalysis.overallRisk ? logoAnalysis.overallRisk.score : 0;
        cached.report.scores.logoDetection = 1.0 - riskScore;
        cached.report.details.logoDetection = logoAnalysis;
        
        // Recalculate overall score
        cached.report.overallScore = this.calculateOverallScore(cached.report.scores);
        cached.report.riskLevel = this.getRiskLevel(cached.report.overallScore);
        cached.report.recommendation = this.getRecommendation(
          cached.report.overallScore,
          cached.report.riskLevel
        );
        
        this.addToCache(url, cached.report);
      }
      
      return {
        success: true,
        report: cached.report
      };
      
    } catch (error) {
      console.error('[Reputation Scorer] Screenshot update error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get from cache
   * @param {string} url - URL
   * @returns {Object|null} Cached result
   */
  getFromCache(url) {
    const cached = this.cache.get(url);
    
    if (!cached) return null;
    
    // Check if cache is expired
    if (Date.now() - cached.timestamp > this.cacheTimeout) {
      this.cache.delete(url);
      return null;
    }
    
    return cached;
  }

  /**
   * Add to cache
   * @param {string} url - URL
   * @param {Object} report - Report to cache
   */
  addToCache(url, report) {
    this.cache.set(url, {
      report: report,
      timestamp: Date.now()
    });
    
    // Limit cache size
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache stats
   */
  getCacheStats() {
    return {
      size: this.cache.size,
      maxSize: 1000,
      timeout: this.cacheTimeout
    };
  }
}

// Create singleton instance
export const reputationScorer = new ReputationScorer();

export default reputationScorer;
