/**
 * ML-Inspired Pattern Detector
 * Uses heuristic scoring and pattern recognition (no external ML library needed)
 */

export class PatternDetector {
  /**
   * Extract features from URL for ML-style analysis
   */
  static extractFeatures(url) {
    try {
      const urlObj = new URL(url);
      
      return {
        // URL structure features
        urlLength: url.length,
        domainLength: urlObj.hostname.length,
        pathLength: urlObj.pathname.length,
        paramCount: urlObj.searchParams.size,
        
        // Character analysis
        digitCount: (url.match(/\d/g) || []).length,
        specialCharCount: (url.match(/[^a-zA-Z0-9]/g) || []).length,
        uppercaseCount: (url.match(/[A-Z]/g) || []).length,
        
        // Domain features
        subdomainCount: urlObj.hostname.split('.').length - 2,
        hasDash: urlObj.hostname.includes('-'),
        hasUnderscore: urlObj.hostname.includes('_'),
        
        // Suspicious patterns
        hasIP: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname),
        hasPort: urlObj.port !== '',
        hasAtSymbol: url.includes('@'),
        
        // Protocol
        isHTTPS: urlObj.protocol === 'https:',
        
        // TLD analysis
        tld: urlObj.hostname.split('.').pop(),
        isCommonTLD: ['com', 'org', 'net', 'edu', 'gov'].includes(urlObj.hostname.split('.').pop()),
        
        // Entropy (randomness measure)
        entropy: this.calculateEntropy(urlObj.hostname),
        
        // Suspicious keyword count in URL
        suspiciousKeywords: this.countSuspiciousKeywords(url)
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Calculate Shannon entropy (measure of randomness)
   */
  static calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Count suspicious keywords in URL
   */
  static countSuspiciousKeywords(url) {
    const keywords = [
      'login', 'signin', 'account', 'verify', 'secure', 'update',
      'confirm', 'banking', 'paypal', 'amazon', 'microsoft', 'apple',
      'password', 'suspended', 'locked', 'urgent', 'alert'
    ];
    
    const lowerUrl = url.toLowerCase();
    let count = 0;
    
    for (const keyword of keywords) {
      if (lowerUrl.includes(keyword)) {
        count++;
      }
    }
    
    return count;
  }

  /**
   * ML-style scoring using weighted features
   */
  static calculatePhishingScore(features) {
    if (!features) return 0;
    
    let score = 0;
    
    // Weights determined by common phishing patterns
    
    // Length anomalies (very long URLs are suspicious)
    if (features.urlLength > 75) score += 2;
    if (features.urlLength > 100) score += 3;
    if (features.domainLength > 30) score += 2;
    
    // Character anomalies
    if (features.digitCount > 8) score += 2;
    if (features.specialCharCount > 10) score += 2;
    if (features.uppercaseCount > features.domainLength * 0.5) score += 1;
    
    // Domain red flags
    if (features.subdomainCount > 3) score += 3;
    if (features.hasDash) score += 1;
    if (features.hasUnderscore) score += 2;
    
    // Critical red flags
    if (features.hasIP) score += 5;
    if (features.hasPort) score += 2;
    if (features.hasAtSymbol) score += 4;
    
    // Protocol
    if (!features.isHTTPS) score += 3;
    
    // TLD
    if (!features.isCommonTLD) score += 2;
    if (['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz'].includes(features.tld)) {
      score += 3; // Suspicious free TLDs
    }
    
    // Entropy (high entropy = random-looking domain)
    if (features.entropy > 4.5) score += 2;
    if (features.entropy > 5) score += 3;
    
    // Suspicious keywords
    score += features.suspiciousKeywords * 2;
    
    return Math.min(score, 100); // Cap at 100
  }

  /**
   * Classify based on score (ML-style classification)
   */
  static classify(score) {
    if (score >= 15) {
      return {
        classification: 'phishing',
        confidence: Math.min(score / 20, 1.0),
        threatLevel: 'DANGEROUS'
      };
    } else if (score >= 8) {
      return {
        classification: 'suspicious',
        confidence: score / 15,
        threatLevel: 'SUSPICIOUS'
      };
    } else if (score >= 4) {
      return {
        classification: 'potentially_suspicious',
        confidence: score / 10,
        threatLevel: 'SUSPICIOUS'
      };
    } else {
      return {
        classification: 'legitimate',
        confidence: 1 - (score / 10),
        threatLevel: 'SAFE'
      };
    }
  }

  /**
   * Advanced: Pattern matching against known phishing structures
   */
  static matchKnownPatterns(url) {
    const patterns = [
      // Pattern: Fake login pages
      {
        regex: /(login|signin).*\.(tk|ml|ga|cf|gq)/i,
        score: 10,
        description: 'Fake login page pattern'
      },
      // Pattern: IP address with login terms
      {
        regex: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(login|account|verify)/i,
        score: 15,
        description: 'IP-based phishing page'
      },
      // Pattern: Brand impersonation
      {
        regex: /(paypal|amazon|microsoft|apple|google).*\.(tk|ml|ga|xyz)/i,
        score: 12,
        description: 'Brand impersonation on suspicious TLD'
      },
      // Pattern: Multiple subdomains with common brands
      {
        regex: /[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.(paypal|amazon|microsoft)/i,
        score: 8,
        description: 'Suspicious subdomain structure'
      },
      // Pattern: Data collection page
      {
        regex: /(secure|verify|update).*\d{3,}/i,
        score: 6,
        description: 'Potential data collection page'
      }
    ];
    
    let totalScore = 0;
    const matches = [];
    
    for (const pattern of patterns) {
      if (pattern.regex.test(url)) {
        totalScore += pattern.score;
        matches.push({
          description: pattern.description,
          score: pattern.score
        });
      }
    }
    
    return {
      score: totalScore,
      matches: matches,
      hasMatch: matches.length > 0
    };
  }

  /**
   * Full ML-style analysis
   */
  static analyze(url) {
    // Extract features
    const features = this.extractFeatures(url);
    if (!features) {
      return {
        score: 0,
        classification: 'error',
        confidence: 0,
        features: null
      };
    }
    
    // Calculate base score
    const baseScore = this.calculatePhishingScore(features);
    
    // Pattern matching
    const patternMatch = this.matchKnownPatterns(url);
    
    // Combined score
    const totalScore = baseScore + patternMatch.score;
    
    // Classification
    const classification = this.classify(totalScore);
    
    return {
      score: totalScore,
      baseScore: baseScore,
      patternScore: patternMatch.score,
      classification: classification.classification,
      confidence: classification.confidence,
      threatLevel: classification.threatLevel,
      features: features,
      patterns: patternMatch.matches,
      analysis: {
        urlLength: features.urlLength > 75 ? 'suspicious' : 'normal',
        domainComplexity: features.subdomainCount > 2 ? 'high' : 'normal',
        hasIPAddress: features.hasIP,
        entropy: features.entropy > 4.5 ? 'high' : 'normal',
        suspiciousKeywords: features.suspiciousKeywords
      }
    };
  }

  /**
   * Learn from feedback (adaptive scoring)
   */
  static async updateWeights(url, actualThreat) {
    // In a real ML system, this would update model weights
    // For now, we store feedback for future analysis
    
    try {
      const feedback = {
        url: url,
        timestamp: Date.now(),
        actualThreat: actualThreat,
        features: this.extractFeatures(url)
      };
      
      // Store in chrome storage for pattern analysis
      const stored = await chrome.storage.local.get('mlFeedback');
      const feedbackList = stored.mlFeedback || [];
      
      feedbackList.push(feedback);
      
      // Keep last 1000 feedback items
      if (feedbackList.length > 1000) {
        feedbackList.shift();
      }
      
      await chrome.storage.local.set({ mlFeedback: feedbackList });
      
      return { success: true };
    } catch (error) {
      console.error('[ML] Error storing feedback:', error);
      return { success: false };
    }
  }

  /**
   * Get model statistics
   */
  static async getModelStats() {
    try {
      const stored = await chrome.storage.local.get('mlFeedback');
      const feedbackList = stored.mlFeedback || [];
      
      const phishingCount = feedbackList.filter(f => f.actualThreat === 'DANGEROUS').length;
      const suspiciousCount = feedbackList.filter(f => f.actualThreat === 'SUSPICIOUS').length;
      const safeCount = feedbackList.filter(f => f.actualThreat === 'SAFE').length;
      
      return {
        totalSamples: feedbackList.length,
        phishing: phishingCount,
        suspicious: suspiciousCount,
        safe: safeCount,
        accuracy: feedbackList.length > 0 ? 
          ((phishingCount + safeCount) / feedbackList.length * 100).toFixed(1) : 0
      };
    } catch (error) {
      return {
        totalSamples: 0,
        error: error.message
      };
    }
  }
}
