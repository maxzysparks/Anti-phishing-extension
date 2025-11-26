import { analyzeURL } from './url-parser.js';
import { StorageManager } from './storage.js';
import { NotificationManager } from './notifications.js';
import { AnalyticsManager } from './analytics.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { SSLValidator } from './ssl-validator.js';
import { PatternDetector } from '../ml/pattern-detector.js';
import { THREAT_LEVELS, PHISHING_KEYWORDS, SPAM_INDICATORS, LEGITIMATE_DOMAINS, LEGITIMATE_TRACKING_DOMAINS } from './constants.js';
import { p2pThreatNetwork } from '../network/p2p-threat-network.js';
import { GraphNeuralNetwork } from '../ml/graph-neural-network.js';
import { distributedThreatDB } from '../network/distributed-threat-db.js';

/**
 * Main phishing detection engine
 */
export class PhishingDetector {
  /**
   * Analyze a URL for phishing threats
   * CRITICAL FIX #5: Offline fallback support
   */
  static async analyzeLink(url, context) {
    try {
      // CRITICAL FIX #5: Check if offline
      const isOffline = !navigator.onLine;
      
      if (isOffline) {
        console.warn('[APG] Offline mode detected - using cached data and heuristics only');
      }
      
      // Check cache first with age validation
      const cached = await StorageManager.getCachedThreat(url);
      if (cached && this.isCacheValid(cached)) {
        // CRITICAL: Re-verify cached dangerous/suspicious URLs periodically
        if (cached.threatLevel === THREAT_LEVELS.DANGEROUS || 
            cached.threatLevel === THREAT_LEVELS.SUSPICIOUS) {
          const cacheAge = Date.now() - cached.timestamp;
          // Re-analyze dangerous links after 1 hour, suspicious after 6 hours
          const maxAge = cached.threatLevel === THREAT_LEVELS.DANGEROUS ? 3600000 : 21600000;
          
          if (cacheAge > maxAge && !isOffline) {
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
      
      // ENHANCED: Check if domain is in legitimate domains list
      const isLegitimate = this.isLegitimateService(domain);
      
      if (isLegitimate || await StorageManager.isWhitelisted(domain)) {
        // SECURITY: Verify domain still resolves and has valid certificate (skip if offline)
        const isStillSafe = isOffline ? true : await this.verifyWhitelistedDomain(domain);
        
        if (!isStillSafe && !isLegitimate) {
          console.warn('[APG] Whitelisted domain failed verification:', domain);
          // Remove from whitelist (but not if it's in legitimate list)
          await StorageManager.removeFromWhitelist(domain);
          // Continue to full analysis
        } else {
          const result = {
            url,
            domain,
            threatLevel: THREAT_LEVELS.SAFE,
            issues: [],
            isWhitelisted: true,
            isLegitimate: isLegitimate,
            timestamp: Date.now(),
            verified: !isOffline,
            offline: isOffline
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
          timestamp: Date.now(),
          offline: isOffline
        };
        await StorageManager.cacheThreat(url, result);
        await StorageManager.incrementBlocked();
        return result;
      }

      // CRITICAL FIX #5: Skip PhishTank check if offline
      if (!isOffline) {
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
            timestamp: Date.now(),
            offline: false
          };
          await StorageManager.cacheThreat(url, result);
          await StorageManager.incrementBlocked();
          
          // PHASE 4: Share threat with P2P network
          try {
            await p2pThreatNetwork.shareThreat({
              url: url,
              type: 'phishing',
              severity: 'critical',
              source: 'phishtank',
              verified: phishTankResult.verified
            });
          } catch (p2pError) {
            console.warn('[P2P] Failed to share threat:', p2pError.message);
          }
          
          // Show immediate notification for PhishTank matches
          await NotificationManager.showThreatBlocked(url, result.threatLevel, 1);
          
          return result;
        }
        
        // PHASE 4: Check P2P network for community-reported threats
        try {
          const networkThreatCount = await p2pThreatNetwork.getNetworkThreatCount({
            timeWindow: 86400000 // Last 24 hours
          });
          
          if (networkThreatCount > 0) {
            console.log(`[P2P] Network has ${networkThreatCount} recent threats`);
          }
        } catch (p2pError) {
          console.warn('[P2P] Network query failed:', p2pError.message);
        }
      }

      // Perform local analysis (works offline)
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
      analysis.offline = isOffline;

      // Update threat level based on all factors
      analysis.threatLevel = this.calculateFinalThreatLevel(analysis);
      
      // Add offline warning if applicable
      if (isOffline) {
        analysis.issues.push({
          type: 'offline_analysis',
          severity: 'low',
          message: 'Analysis performed offline - limited threat intelligence available'
        });
      }

      // Cache the result
      await StorageManager.cacheThreat(url, analysis);
      
      // Update statistics
      await StorageManager.incrementScanned();
      if (analysis.threatLevel === THREAT_LEVELS.DANGEROUS) {
        await StorageManager.incrementBlocked();
        
        // PHASE 4: Share dangerous threat with P2P network and distributed DB
        if (!isOffline) {
          try {
            // Share with P2P network
            await p2pThreatNetwork.shareThreat({
              url: url,
              type: 'phishing',
              severity: 'high',
              confidence: analysis.mlConfidence || analysis.confidence,
              techniques: analysis.issues.map(i => i.type)
            });
            
            // Add to distributed threat database
            await distributedThreatDB.addThreat({
              url: url,
              domain: domain,
              type: 'phishing',
              severity: 'high',
              timestamp: Date.now(),
              issues: analysis.issues,
              mlScore: analysis.mlScore
            });
            
            console.log('[Phase 4] Threat shared with network and distributed DB');
          } catch (phase4Error) {
            console.warn('[Phase 4] Failed to share threat:', phase4Error.message);
          }
        }
        
        // Show notification for dangerous threats (with deduplication)
        await NotificationManager.showThreatBlocked(
          url, 
          analysis.threatLevel, 
          analysis.issues.length
        );
      } else if (analysis.threatLevel === THREAT_LEVELS.SUSPICIOUS && contextScore >= 12) {
        // FIXED: Only show notification for extremely high-scoring suspicious links (raised threshold from 7 to 12)
        // This means 4+ SPAM indicators must be present before notifying on suspicious links
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
   * Check if domain is a known legitimate service
   */
  static isLegitimateService(domain) {
    if (!domain) return false;
    
    const lowerDomain = domain.toLowerCase();
    
    // Check exact match in legitimate domains
    if (LEGITIMATE_DOMAINS.includes(lowerDomain)) {
      return true;
    }
    
    // Check if it's a subdomain of a legitimate domain
    for (const legitDomain of LEGITIMATE_DOMAINS) {
      if (lowerDomain.endsWith('.' + legitDomain) || lowerDomain === legitDomain) {
        return true;
      }
    }
    
    // Check legitimate tracking domains (partial matches)
    for (const trackingPattern of LEGITIMATE_TRACKING_DOMAINS) {
      if (trackingPattern.endsWith('.')) {
        // Pattern like "email." - check if domain starts with it
        if (lowerDomain.startsWith(trackingPattern)) {
          return true;
        }
      } else if (lowerDomain === trackingPattern || lowerDomain.endsWith('.' + trackingPattern)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Analyze surrounding text for phishing keywords
   * ENHANCED: Smarter scoring that considers legitimate marketing
   */
  static analyzeContext(text) {
    if (!text) return 0;
    
    const lowerText = text.toLowerCase();
    let phishingScore = 0;
    let spamScore = 0;
    let legitimateMarketingIndicators = 0;

    // Check for legitimate marketing indicators (reduces false positives)
    const legitMarketingWords = [
      'unsubscribe', 'preferences', 'manage subscription', 'opt out',
      'privacy policy', 'terms of service', 'contact us',
      'newsletter', 'update', 'deals', 'sale', 'offer',
      'view in browser', 'email preferences', 'notification settings'
    ];
    
    for (const word of legitMarketingWords) {
      if (lowerText.includes(word)) {
        legitimateMarketingIndicators++;
      }
    }

    // Check for phishing keywords (weight: 1, but reduced if legitimate marketing detected)
    for (const keyword of PHISHING_KEYWORDS) {
      if (lowerText.includes(keyword)) {
        phishingScore++;
      }
    }

    // Check for SPAM indicators (weight: 3 - very high!)
    for (const spamWord of SPAM_INDICATORS) {
      if (lowerText.includes(spamWord)) {
        spamScore += 3;
      }
    }

    // SMART ADJUSTMENT: If legitimate marketing indicators present, reduce phishing score significantly
    if (legitimateMarketingIndicators >= 2) {
      // This looks like a legitimate newsletter/marketing email
      phishingScore = Math.max(0, Math.floor(phishingScore * 0.2)); // Reduce by 80%
      spamScore = Math.max(0, Math.floor(spamScore * 0.3)); // Also reduce spam score by 70%
      console.log('[APG] Legitimate marketing email detected, reducing false positive score');
    } else if (legitimateMarketingIndicators >= 1) {
      // Some legitimate indicators, reduce score moderately
      phishingScore = Math.max(0, Math.floor(phishingScore * 0.5)); // Reduce by 50%
      console.log('[APG] Possible legitimate email detected, reducing score');
    }

    // Combined score with spam weight
    const totalScore = phishingScore + spamScore;
    
    // Log spam detection (only if significant)
    if (spamScore > 0) {
      console.warn(`[APG] SPAM indicators found! Spam: ${spamScore}, Phishing: ${phishingScore}, Total: ${totalScore}`);
    }

    return totalScore;
  }

  /**
   * Calculate final threat level considering all factors
   * ENHANCED: Balanced approach - aggressive on real threats, lenient on legitimate services
   */
  static calculateFinalThreatLevel(analysis) {
    const { issues, isLegitimate, contextScore, domain } = analysis;

    // CRITICAL: If domain is legitimate, don't flag based on context alone
    if (isLegitimate || this.isLegitimateService(domain)) {
      // Only flag legitimate domains if they have actual technical issues
      const technicalIssues = issues.filter(i => 
        i.type !== 'suspicious_context' && i.severity === 'high'
      );
      
      if (technicalIssues.length >= 2) {
        return THREAT_LEVELS.SUSPICIOUS; // Even legitimate domains can be compromised
      }
      
      return THREAT_LEVELS.SAFE;
    }

    const highCount = issues.filter(i => i.severity === 'high').length;
    const mediumCount = issues.filter(i => i.severity === 'medium').length;
    const lowCount = issues.filter(i => i.severity === 'low').length;

    // Base scoring system
    let score = (highCount * 3) + (mediumCount * 2) + lowCount;
    
    // Add context score but with significantly reduced weight to prevent false positives
    if (contextScore) {
      // Further reduce context weight - only add 30% of context score
      score += Math.floor(contextScore * 0.3);
    }

    // BALANCED: Very high context score can mark as dangerous (significantly raised thresholds)
    if (contextScore >= 15) { // 5+ SPAM indicators (raised from 12)
      console.warn(`[APG] DANGEROUS: Very high spam context score: ${contextScore}`);
      return THREAT_LEVELS.DANGEROUS;
    }
    
    if (contextScore >= 12) { // 4 SPAM indicators (raised from 9)
      console.warn(`[APG] SUSPICIOUS: High spam context score: ${contextScore}`);
      return THREAT_LEVELS.SUSPICIOUS;
    }

    // Original scoring logic with adjusted thresholds
    if (score >= 7 || highCount >= 3) { // Raised from 6 and 2
      return THREAT_LEVELS.DANGEROUS;
    } else if (score >= 4 || highCount >= 2 || mediumCount >= 3) { // Raised thresholds
      return THREAT_LEVELS.SUSPICIOUS;
    } else if (score >= 2 && issues.length > 0) { // Only flag if score is meaningful
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
