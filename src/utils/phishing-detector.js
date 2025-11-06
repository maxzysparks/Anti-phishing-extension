import { analyzeURL } from './url-parser.js';
import { StorageManager } from './storage.js';
import { NotificationManager } from './notifications.js';
import { AnalyticsManager } from './analytics.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { SSLValidator } from './ssl-validator.js';
import { PatternDetector } from '../ml/pattern-detector.js';
import { THREAT_LEVELS, PHISHING_KEYWORDS, SPAM_INDICATORS } from './constants.js';

/**
 * Main phishing detection engine
 */
export class PhishingDetector {
  /**
   * Analyze a URL for phishing threats
   */
  static async analyzeLink(url, context) {
    try {
      // Check cache first with age validation
      const cached = await StorageManager.getCachedThreat(url);
      if (cached && this.isCacheValid(cached)) {
        // CRITICAL: Re-verify cached dangerous/suspicious URLs periodically
        if (cached.threatLevel === THREAT_LEVELS.DANGEROUS || 
            cached.threatLevel === THREAT_LEVELS.SUSPICIOUS) {
          const cacheAge = Date.now() - cached.timestamp;
          // Re-analyze dangerous links after 1 hour, suspicious after 6 hours
          const maxAge = cached.threatLevel === THREAT_LEVELS.DANGEROUS ? 3600000 : 21600000;
          
          if (cacheAge > maxAge) {
            console.log('[APG] Re-analyzing cached threat due to age:', url);
            // Don't return cached, continue to full analysis
          } else {
            return cached;
          }
        } else {
          return cached;
        }
      }

      // Check whitelist with validation
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      if (await StorageManager.isWhitelisted(domain)) {
        // SECURITY: Verify domain still resolves and has valid certificate
        const isStillSafe = await this.verifyWhitelistedDomain(domain);
        
        if (!isStillSafe) {
          console.warn('[APG] Whitelisted domain failed verification:', domain);
          // Remove from whitelist
          await StorageManager.removeFromWhitelist(domain);
          // Continue to full analysis
        } else {
          const result = {
            url,
            domain,
            threatLevel: THREAT_LEVELS.SAFE,
            issues: [],
            isWhitelisted: true,
            timestamp: Date.now(),
            verified: true
          };
          await StorageManager.cacheThreat(url, result);
          return result;
        }
      }

      // Check blacklist
      if (await StorageManager.isBlacklisted(domain)) {
        const result = {
          url,
          domain,
          threatLevel: THREAT_LEVELS.DANGEROUS,
          issues: [{ type: 'blacklisted', severity: 'high', message: 'Domain is in your blacklist' }],
          isBlacklisted: true,
          timestamp: Date.now()
        };
        await StorageManager.cacheThreat(url, result);
        await StorageManager.incrementBlocked();
        return result;
      }

      // ENHANCED: Check PhishTank threat intelligence database
      const phishTankResult = await ThreatIntelligence.checkPhishTank(url);
      if (phishTankResult.found) {
        const result = {
          url,
          domain,
          threatLevel: THREAT_LEVELS.DANGEROUS,
          issues: [{
            type: 'phishtank_match',
            severity: 'high',
            message: `Known phishing site (verified by ${phishTankResult.source}${phishTankResult.verified ? ' - VERIFIED' : ''})`
          }],
          isPhishTankMatch: true,
          phishTankVerified: phishTankResult.verified,
          timestamp: Date.now()
        };
        await StorageManager.cacheThreat(url, result);
        await StorageManager.incrementBlocked();
        
        // Show immediate notification for PhishTank matches
        await NotificationManager.showThreatBlocked(url, result.threatLevel, 1);
        
        return result;
      }

      // Perform local analysis
      const analysis = analyzeURL(url);
      
      // ENHANCED: ML pattern detection
      const mlAnalysis = PatternDetector.analyze(url);
      if (mlAnalysis.score > 0) {
        analysis.mlScore = mlAnalysis.score;
        analysis.mlConfidence = mlAnalysis.confidence;
        analysis.mlClassification = mlAnalysis.classification;
        
        // Add ML-detected patterns as issues
        if (mlAnalysis.patterns && mlAnalysis.patterns.length > 0) {
          mlAnalysis.patterns.forEach(pattern => {
            analysis.issues.push({
              type: 'ml_pattern',
              severity: pattern.score > 10 ? 'high' : 'medium',
              message: `ML detected: ${pattern.description}`,
              mlScore: pattern.score
            });
          });
        }
        
        // Add general ML warning if score is high
        if (mlAnalysis.score >= 15) {
          analysis.issues.push({
            type: 'ml_high_risk',
            severity: 'high',
            message: `ML detected high-risk patterns (confidence: ${(mlAnalysis.confidence * 100).toFixed(0)}%)`,
            mlScore: mlAnalysis.score
          });
        }
      }
      
      // ENHANCED: SSL/TLS validation
      const sslValidation = SSLValidator.validateURL(url);
      if (sslValidation.issues.length > 0) {
        sslValidation.issues.forEach(issue => {
          analysis.issues.push(issue);
        });
      }
      
      // ENHANCED: Check email context for phishing/spam keywords
      const contextScore = this.analyzeContext(context || url);
      if (contextScore > 0) {
        // Determine severity based on score
        let severity = 'low';
        let message = 'Link appears in suspicious context';
        
        if (contextScore >= 9) {
          severity = 'high';
          message = 'SPAM: Multiple spam indicators detected in email';
        } else if (contextScore >= 5) {
          severity = 'high';
          message = 'Link appears in highly suspicious context with spam indicators';
        } else if (contextScore >= 3) {
          severity = 'medium';
          message = 'Link appears in suspicious phishing context';
        }
        
        analysis.issues.push({
          type: 'suspicious_context',
          severity: severity,
          message: message
        });
      }
      
      // Store context score for threat calculation
      analysis.contextScore = contextScore;

      // Update threat level based on all factors
      analysis.threatLevel = this.calculateFinalThreatLevel(analysis);

      // Cache the result
      await StorageManager.cacheThreat(url, analysis);
      
      // Update statistics
      await StorageManager.incrementScanned();
      if (analysis.threatLevel === THREAT_LEVELS.DANGEROUS) {
        await StorageManager.incrementBlocked();
        
        // Show notification for dangerous threats
        await NotificationManager.showThreatBlocked(
          url, 
          analysis.threatLevel, 
          analysis.issues.length
        );
      } else if (analysis.threatLevel === THREAT_LEVELS.SUSPICIOUS && contextScore >= 5) {
        // Show notification for high-scoring suspicious links
        await NotificationManager.showThreatBlocked(
          url, 
          analysis.threatLevel, 
          analysis.issues.length
        );
      }
      
      // Record threat in analytics
      const issueTypes = analysis.issues.map(issue => issue.type);
      await AnalyticsManager.recordThreat(analysis.threatLevel, issueTypes);

      return analysis;
    } catch (error) {
      console.error('Error analyzing link:', error);
      return {
        url,
        threatLevel: THREAT_LEVELS.UNKNOWN,
        issues: [{ type: 'error', severity: 'low', message: 'Analysis failed' }],
        error: error.message
      };
    }
  }

  /**
   * Check if cached result is still valid
   */
  static isCacheValid(cached) {
    if (!cached || !cached.timestamp) return false;
    
    const age = Date.now() - cached.timestamp;
    const maxAge = 86400000; // 24 hours default
    
    // Dangerous URLs expire faster
    if (cached.threatLevel === THREAT_LEVELS.DANGEROUS) {
      return age < 3600000; // 1 hour for dangerous
    }
    
    return age < maxAge;
  }

  /**
   * Verify whitelisted domain is still safe
   */
  static async verifyWhitelistedDomain(domain) {
    try {
      // Basic verification: check if domain still exists and is accessible
      // In a real implementation, this would check SSL certificates, DNS, etc.
      
      // For now, perform a quick analysis to ensure no obvious red flags
      const testUrl = `https://${domain}`;
      const analysis = analyzeURL(testUrl);
      
      // If analysis shows high-severity issues, domain may be compromised
      const highSeverityIssues = analysis.issues.filter(i => i.severity === 'high');
      
      return highSeverityIssues.length === 0;
    } catch (error) {
      console.error('Error verifying whitelisted domain:', error);
      return false; // Fail secure
    }
  }

  /**
   * Analyze surrounding text for phishing keywords
   * ENHANCED: More aggressive scoring for spam
   */
  static analyzeContext(text) {
    if (!text) return 0;
    
    const lowerText = text.toLowerCase();
    let score = 0;
    let spamScore = 0;

    // Check for phishing keywords (weight: 1)
    for (const keyword of PHISHING_KEYWORDS) {
      if (lowerText.includes(keyword)) {
        score++;
      }
    }

    // Check for SPAM indicators (weight: 3 - very high!)
    for (const spamWord of SPAM_INDICATORS) {
      if (lowerText.includes(spamWord)) {
        spamScore += 3;
      }
    }

    // Combined score with spam weight
    const totalScore = score + spamScore;
    
    // Log aggressive spam detection
    if (spamScore > 0) {
      console.warn(`[APG] SPAM indicators found! Score: ${spamScore}, Total: ${totalScore}`);
    }

    return totalScore;
  }

  /**
   * Calculate final threat level considering all factors
   * ENHANCED: More aggressive for spam context
   */
  static calculateFinalThreatLevel(analysis) {
    const { issues, isLegitimate, contextScore } = analysis;

    if (isLegitimate) {
      return THREAT_LEVELS.SAFE;
    }

    const highCount = issues.filter(i => i.severity === 'high').length;
    const mediumCount = issues.filter(i => i.severity === 'medium').length;
    const lowCount = issues.filter(i => i.severity === 'low').length;

    // Base scoring system
    let score = (highCount * 3) + (mediumCount * 2) + lowCount;
    
    // CRITICAL: Add context score (makes spam detection aggressive)
    if (contextScore) {
      score += contextScore;
    }

    // AGGRESSIVE: High context score alone can mark as dangerous
    if (contextScore >= 9) { // 3+ SPAM indicators
      console.warn(`[APG] DANGEROUS: High spam context score: ${contextScore}`);
      return THREAT_LEVELS.DANGEROUS;
    }
    
    if (contextScore >= 5) { // Multiple phishing keywords or 1-2 spam indicators
      console.warn(`[APG] SUSPICIOUS: Elevated spam context score: ${contextScore}`);
      return THREAT_LEVELS.SUSPICIOUS;
    }

    // Original scoring logic with lower thresholds
    if (score >= 5 || highCount >= 2) {
      return THREAT_LEVELS.DANGEROUS;
    } else if (score >= 2 || highCount >= 1 || mediumCount >= 2) {
      return THREAT_LEVELS.SUSPICIOUS;
    } else if (issues.length > 0) {
      return THREAT_LEVELS.SUSPICIOUS;
    }

    return THREAT_LEVELS.UNKNOWN;
  }

  /**
   * Batch analyze multiple URLs
   */
  static async analyzeLinks(urls) {
    const results = [];
    
    for (const url of urls) {
      const analysis = await this.analyzeLink(url);
      results.push(analysis);
    }

    return results;
  }

  /**
   * Get threat color for UI display
   */
  static getThreatColor(threatLevel) {
    switch (threatLevel) {
      case THREAT_LEVELS.SAFE:
        return '#28a745'; // Green
      case THREAT_LEVELS.SUSPICIOUS:
        return '#ffc107'; // Yellow
      case THREAT_LEVELS.DANGEROUS:
        return '#dc3545'; // Red
      default:
        return '#6c757d'; // Gray
    }
  }

  /**
   * Get threat icon for UI display
   */
  static getThreatIcon(threatLevel) {
    switch (threatLevel) {
      case THREAT_LEVELS.SAFE:
        return '✓'; // Check mark
      case THREAT_LEVELS.SUSPICIOUS:
        return '⚠'; // Warning
      case THREAT_LEVELS.DANGEROUS:
        return '✕'; // X mark
      default:
        return '?'; // Question mark
    }
  }

  /**
   * Get human-readable threat description
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
        return 'This link could not be fully analyzed';
    }
  }

  /**
   * Format analysis results for display
   */
  static formatAnalysis(analysis) {
    return {
      ...analysis,
      color: this.getThreatColor(analysis.threatLevel),
      icon: this.getThreatIcon(analysis.threatLevel),
      description: this.getThreatDescription(analysis.threatLevel),
      issueCount: analysis.issues.length,
      highSeverityCount: analysis.issues.filter(i => i.severity === 'high').length,
      mediumSeverityCount: analysis.issues.filter(i => i.severity === 'medium').length
    };
  }
}
