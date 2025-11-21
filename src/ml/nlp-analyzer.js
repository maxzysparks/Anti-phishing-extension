/**
 * NLP Analyzer for Email Content Analysis
 * Uses Universal Sentence Encoder for semantic analysis
 */

import * as use from '@tensorflow-models/universal-sentence-encoder';

export class NLPAnalyzer {
  constructor() {
    this.model = null;
    this.isInitialized = false;
    this.isLoading = false;
  }

  /**
   * Initialize Universal Sentence Encoder model
   */
  async initialize() {
    if (this.isInitialized) {
      return { success: true, message: 'Already initialized' };
    }

    if (this.isLoading) {
      return { success: false, message: 'Already loading' };
    }

    try {
      this.isLoading = true;
      console.log('[NLP] Loading Universal Sentence Encoder...');

      this.model = await use.load();
      
      this.isInitialized = true;
      this.isLoading = false;

      console.log('[NLP] Model loaded successfully');
      return { success: true, message: 'Initialized successfully' };
    } catch (error) {
      console.error('[NLP] Initialization error:', error);
      this.isLoading = false;
      return { success: false, message: 'Failed to initialize', error: error.message };
    }
  }

  /**
   * Analyze email content for phishing indicators
   */
  async analyzeEmailContent(emailText, subject = '') {
    if (!this.isInitialized) {
      await this.initialize();
    }

    try {
      const fullText = `${subject} ${emailText}`.toLowerCase();

      // Heuristic analysis
      const heuristicScore = this.heuristicAnalysis(fullText);

      // Semantic analysis using embeddings
      let semanticScore = 0;
      if (this.model) {
        semanticScore = await this.semanticAnalysis(fullText);
      }

      // Combined analysis
      const totalScore = heuristicScore.score + semanticScore;
      const classification = this.classifyEmailThreat(totalScore);

      return {
        score: totalScore,
        heuristicScore: heuristicScore.score,
        semanticScore: semanticScore,
        classification: classification.level,
        confidence: classification.confidence,
        indicators: heuristicScore.indicators,
        analysis: {
          urgency: heuristicScore.urgency,
          socialEngineering: heuristicScore.socialEngineering,
          brandMention: heuristicScore.brandMention,
          suspiciousRequests: heuristicScore.suspiciousRequests
        }
      };
    } catch (error) {
      console.error('[NLP] Analysis error:', error);
      return {
        score: 0,
        classification: 'unknown',
        confidence: 0,
        error: error.message
      };
    }
  }

  /**
   * Heuristic-based analysis of email content
   */
  heuristicAnalysis(text) {
    let score = 0;
    const indicators = [];

    // Urgency indicators
    const urgencyWords = [
      'urgent', 'immediately', 'act now', 'limited time', 'expires',
      'hurry', 'quick', 'asap', 'deadline', 'last chance', 'final notice'
    ];
    let urgencyCount = 0;
    urgencyWords.forEach(word => {
      if (text.includes(word)) {
        urgencyCount++;
        score += 2;
      }
    });
    if (urgencyCount > 0) {
      indicators.push({ type: 'urgency', count: urgencyCount, severity: 'medium' });
    }

    // Threat/fear indicators
    const threatWords = [
      'suspended', 'locked', 'blocked', 'unauthorized', 'security alert',
      'unusual activity', 'verify', 'confirm', 'action required', 'warning'
    ];
    let threatCount = 0;
    threatWords.forEach(word => {
      if (text.includes(word)) {
        threatCount++;
        score += 3;
      }
    });
    if (threatCount > 0) {
      indicators.push({ type: 'threat', count: threatCount, severity: 'high' });
    }

    // Financial/credential requests
    const financialWords = [
      'password', 'credit card', 'bank account', 'social security',
      'ssn', 'pin', 'cvv', 'account number', 'routing number',
      'payment', 'refund', 'tax', 'invoice', 'billing'
    ];
    let financialCount = 0;
    financialWords.forEach(word => {
      if (text.includes(word)) {
        financialCount++;
        score += 4;
      }
    });
    if (financialCount > 0) {
      indicators.push({ type: 'financial', count: financialCount, severity: 'high' });
    }

    // Brand impersonation
    const brands = [
      'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
      'netflix', 'bank of america', 'wells fargo', 'chase', 'irs',
      'fedex', 'ups', 'dhl', 'usps'
    ];
    let brandCount = 0;
    brands.forEach(brand => {
      if (text.includes(brand)) {
        brandCount++;
        score += 2;
      }
    });
    if (brandCount > 0) {
      indicators.push({ type: 'brand_mention', count: brandCount, severity: 'medium' });
    }

    // Suspicious requests
    const requestWords = [
      'click here', 'verify your account', 'confirm your identity',
      'update your information', 'download attachment', 'open attachment',
      'reset password', 'validate', 'reactivate'
    ];
    let requestCount = 0;
    requestWords.forEach(word => {
      if (text.includes(word)) {
        requestCount++;
        score += 3;
      }
    });
    if (requestCount > 0) {
      indicators.push({ type: 'suspicious_request', count: requestCount, severity: 'high' });
    }

    // Grammar/spelling issues (simple check)
    const grammarIssues = this.detectGrammarIssues(text);
    if (grammarIssues > 0) {
      score += grammarIssues;
      indicators.push({ type: 'grammar_issues', count: grammarIssues, severity: 'low' });
    }

    // Excessive punctuation
    const excessivePunctuation = (text.match(/[!?]{2,}/g) || []).length;
    if (excessivePunctuation > 0) {
      score += excessivePunctuation * 2;
      indicators.push({ type: 'excessive_punctuation', count: excessivePunctuation, severity: 'low' });
    }

    return {
      score: Math.min(score, 50), // Cap at 50
      indicators: indicators,
      urgency: urgencyCount > 0,
      socialEngineering: threatCount > 0,
      brandMention: brandCount > 0,
      suspiciousRequests: requestCount > 0
    };
  }

  /**
   * Detect basic grammar issues
   */
  detectGrammarIssues(text) {
    let issues = 0;

    // Multiple spaces
    if (/\s{3,}/.test(text)) issues++;

    // Missing spaces after punctuation
    if (/[.!?][a-z]/i.test(text)) issues++;

    // Excessive capitalization
    const words = text.split(/\s+/);
    const capsWords = words.filter(w => w.length > 2 && w === w.toUpperCase());
    if (capsWords.length > words.length * 0.3) issues += 2;

    return issues;
  }

  /**
   * Semantic analysis using sentence embeddings
   */
  async semanticAnalysis(text) {
    if (!this.model) {
      return 0;
    }

    try {
      // Known phishing phrases for comparison
      const phishingPhrases = [
        'verify your account immediately or it will be suspended',
        'urgent security alert your account has been compromised',
        'click here to claim your refund before it expires',
        'confirm your identity to prevent account closure',
        'unusual activity detected update your password now'
      ];

      // Legitimate phrases for comparison
      const legitimatePhrases = [
        'thank you for your recent purchase',
        'your order has been shipped',
        'meeting scheduled for next week',
        'please review the attached document',
        'newsletter subscription confirmation'
      ];

      // Get embeddings
      const textEmbedding = await this.model.embed([text]);
      const phishingEmbeddings = await this.model.embed(phishingPhrases);
      const legitimateEmbeddings = await this.model.embed(legitimatePhrases);

      // Calculate similarity scores
      const phishingSimilarity = await this.calculateAverageSimilarity(
        textEmbedding,
        phishingEmbeddings
      );
      const legitimateSimilarity = await this.calculateAverageSimilarity(
        textEmbedding,
        legitimateEmbeddings
      );

      // Clean up tensors
      textEmbedding.dispose();
      phishingEmbeddings.dispose();
      legitimateEmbeddings.dispose();

      // Score based on similarity difference
      const similarityDiff = phishingSimilarity - legitimateSimilarity;
      const semanticScore = Math.max(0, similarityDiff * 30); // Scale to 0-30

      console.log('[NLP] Semantic analysis:', {
        phishingSimilarity: phishingSimilarity.toFixed(3),
        legitimateSimilarity: legitimateSimilarity.toFixed(3),
        score: semanticScore.toFixed(2)
      });

      return semanticScore;
    } catch (error) {
      console.error('[NLP] Semantic analysis error:', error);
      return 0;
    }
  }

  /**
   * Calculate average cosine similarity between embeddings
   */
  async calculateAverageSimilarity(embedding1, embedding2) {
    const similarity = await this.cosineSimilarity(embedding1, embedding2);
    const avgSimilarity = similarity.reduce((a, b) => a + b, 0) / similarity.length;
    return avgSimilarity;
  }

  /**
   * Calculate cosine similarity between embeddings
   */
  async cosineSimilarity(embedding1, embedding2) {
    const dotProduct = embedding1.matMul(embedding2.transpose());
    const similarities = await dotProduct.data();
    dotProduct.dispose();
    return Array.from(similarities);
  }

  /**
   * Classify email threat level
   */
  classifyEmailThreat(score) {
    if (score >= 25) {
      return {
        level: 'dangerous',
        confidence: Math.min(score / 30, 1.0),
        description: 'High probability of phishing attempt'
      };
    } else if (score >= 15) {
      return {
        level: 'suspicious',
        confidence: score / 25,
        description: 'Suspicious email content detected'
      };
    } else if (score >= 8) {
      return {
        level: 'potentially_suspicious',
        confidence: score / 15,
        description: 'Some suspicious indicators present'
      };
    } else {
      return {
        level: 'safe',
        confidence: 1 - (score / 10),
        description: 'Email appears legitimate'
      };
    }
  }

  /**
   * Analyze sender information
   */
  analyzeSender(senderEmail, senderName, displayedDomain) {
    let score = 0;
    const issues = [];

    try {
      // Extract domain from email
      const emailDomain = senderEmail.split('@')[1]?.toLowerCase();

      // Check if sender name matches domain
      if (senderName && emailDomain) {
        const nameLower = senderName.toLowerCase();
        
        // Check for brand impersonation
        const brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank'];
        brands.forEach(brand => {
          if (nameLower.includes(brand) && !emailDomain.includes(brand)) {
            score += 5;
            issues.push({
              type: 'brand_mismatch',
              message: `Sender name mentions "${brand}" but email domain doesn't match`,
              severity: 'high'
            });
          }
        });
      }

      // Check for suspicious TLDs
      const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'];
      const tld = emailDomain?.split('.').pop();
      if (suspiciousTLDs.includes(tld)) {
        score += 3;
        issues.push({
          type: 'suspicious_tld',
          message: `Suspicious top-level domain: .${tld}`,
          severity: 'medium'
        });
      }

      // Check for lookalike domains
      if (displayedDomain && emailDomain && displayedDomain !== emailDomain) {
        score += 4;
        issues.push({
          type: 'domain_mismatch',
          message: 'Email domain differs from displayed domain',
          severity: 'high'
        });
      }

      return {
        score: score,
        issues: issues,
        isSuspicious: score > 5
      };
    } catch (error) {
      console.error('[NLP] Sender analysis error:', error);
      return { score: 0, issues: [], isSuspicious: false };
    }
  }

  /**
   * Dispose model and free memory
   */
  dispose() {
    if (this.model) {
      this.model = null;
    }
    this.isInitialized = false;
  }
}

// Singleton instance
export const nlpAnalyzer = new NLPAnalyzer();
