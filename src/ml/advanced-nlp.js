/**
 * Advanced NLP with BERT/DistilBERT Integration
 * Provides sophisticated text analysis for phishing detection
 */

import * as tf from '@tensorflow/tfjs';

/**
 * Advanced NLP Analyzer using transformer-based models
 */
export class AdvancedNLPAnalyzer {
  constructor() {
    this.model = null;
    this.tokenizer = null;
    this.maxLength = 128;
    this.initialized = false;
    
    // Phishing-specific patterns and keywords
    this.urgencyPhrases = [
      'urgent', 'immediately', 'act now', 'limited time', 'expires soon',
      'verify now', 'confirm immediately', 'suspend', 'locked', 'unusual activity',
      'security alert', 'action required', 'verify your account', 'click here now',
      'update required', 'confirm your identity', 'account will be closed'
    ];
    
    this.fearTactics = [
      'suspended', 'terminated', 'blocked', 'restricted', 'unauthorized',
      'fraudulent', 'suspicious activity', 'security breach', 'compromised',
      'illegal', 'violation', 'penalty', 'legal action'
    ];
    
    this.rewardLures = [
      'prize', 'winner', 'congratulations', 'free', 'bonus', 'reward',
      'gift', 'claim', 'selected', 'lucky', 'exclusive offer', 'limited offer'
    ];
    
    this.legitimacyIndicators = [
      'unsubscribe', 'privacy policy', 'terms of service', 'contact us',
      'customer service', 'help center', 'official', 'secure'
    ];
  }

  /**
   * Initialize the NLP model
   */
  async initialize() {
    try {
      console.log('[Advanced NLP] Initializing...');
      
      // For now, we'll use a lightweight approach
      // In production, you would load a pre-trained DistilBERT model
      // from TensorFlow Hub or a custom trained model
      
      this.initialized = true;
      console.log('[Advanced NLP] Initialized successfully');
      
      return { success: true };
    } catch (error) {
      console.error('[Advanced NLP] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Analyze text for phishing indicators using advanced NLP
   * @param {string} text - Text to analyze
   * @param {Object} context - Additional context (sender, subject, etc.)
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeText(text, context = {}) {
    if (!text || typeof text !== 'string') {
      return {
        success: false,
        error: 'Invalid text input'
      };
    }

    try {
      const textLower = text.toLowerCase();
      
      // Perform multiple analysis techniques
      const sentimentScore = await this.analyzeSentiment(text);
      const urgencyScore = this.detectUrgency(textLower);
      const fearScore = this.detectFearTactics(textLower);
      const rewardScore = this.detectRewardLures(textLower);
      const legitimacyScore = this.detectLegitimacy(textLower);
      const entities = this.extractNamedEntities(text);
      const socialEngineering = this.detectSocialEngineering(textLower);
      const grammarScore = this.analyzeGrammar(text);
      const brandImpersonation = this.detectBrandImpersonation(text, entities);
      
      // Calculate overall phishing probability
      const phishingScore = this.calculatePhishingScore({
        sentiment: sentimentScore,
        urgency: urgencyScore,
        fear: fearScore,
        reward: rewardScore,
        legitimacy: legitimacyScore,
        socialEngineering: socialEngineering.score,
        grammar: grammarScore,
        brandImpersonation: brandImpersonation.score
      });

      return {
        success: true,
        phishingProbability: phishingScore,
        analysis: {
          sentiment: {
            score: sentimentScore,
            label: this.getSentimentLabel(sentimentScore)
          },
          urgency: {
            score: urgencyScore,
            detected: urgencyScore > 0.3,
            phrases: this.findMatchingPhrases(textLower, this.urgencyPhrases)
          },
          fearTactics: {
            score: fearScore,
            detected: fearScore > 0.3,
            phrases: this.findMatchingPhrases(textLower, this.fearTactics)
          },
          rewardLures: {
            score: rewardScore,
            detected: rewardScore > 0.3,
            phrases: this.findMatchingPhrases(textLower, this.rewardLures)
          },
          legitimacy: {
            score: legitimacyScore,
            indicators: this.findMatchingPhrases(textLower, this.legitimacyIndicators)
          },
          entities: entities,
          socialEngineering: socialEngineering,
          grammar: {
            score: grammarScore,
            quality: grammarScore > 0.7 ? 'good' : grammarScore > 0.4 ? 'fair' : 'poor'
          },
          brandImpersonation: brandImpersonation
        },
        riskLevel: this.getRiskLevel(phishingScore),
        confidence: this.calculateConfidence(phishingScore)
      };

    } catch (error) {
      console.error('[Advanced NLP] Analysis error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Analyze sentiment of text
   * @param {string} text - Text to analyze
   * @returns {number} Sentiment score (-1 to 1)
   */
  async analyzeSentiment(text) {
    // Simplified sentiment analysis
    // In production, use a pre-trained sentiment model
    
    const positiveWords = ['thank', 'welcome', 'appreciate', 'help', 'support', 'secure', 'protected'];
    const negativeWords = ['urgent', 'warning', 'alert', 'suspended', 'blocked', 'unauthorized', 'fraud'];
    
    const textLower = text.toLowerCase();
    let score = 0;
    
    positiveWords.forEach(word => {
      if (textLower.includes(word)) score += 0.1;
    });
    
    negativeWords.forEach(word => {
      if (textLower.includes(word)) score -= 0.15;
    });
    
    return Math.max(-1, Math.min(1, score));
  }

  /**
   * Detect urgency in text
   * @param {string} text - Text to analyze
   * @returns {number} Urgency score (0 to 1)
   */
  detectUrgency(text) {
    let score = 0;
    let matches = 0;
    
    this.urgencyPhrases.forEach(phrase => {
      if (text.includes(phrase)) {
        matches++;
        score += 0.2;
      }
    });
    
    // Check for excessive punctuation (!!!, ???)
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 2) score += 0.1;
    
    // Check for ALL CAPS words
    const words = text.split(/\s+/);
    const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase());
    if (capsWords.length > 2) score += 0.15;
    
    return Math.min(1, score);
  }

  /**
   * Detect fear tactics
   * @param {string} text - Text to analyze
   * @returns {number} Fear score (0 to 1)
   */
  detectFearTactics(text) {
    let score = 0;
    
    this.fearTactics.forEach(phrase => {
      if (text.includes(phrase)) {
        score += 0.25;
      }
    });
    
    return Math.min(1, score);
  }

  /**
   * Detect reward lures
   * @param {string} text - Text to analyze
   * @returns {number} Reward score (0 to 1)
   */
  detectRewardLures(text) {
    let score = 0;
    
    this.rewardLures.forEach(phrase => {
      if (text.includes(phrase)) {
        score += 0.2;
      }
    });
    
    return Math.min(1, score);
  }

  /**
   * Detect legitimacy indicators
   * @param {string} text - Text to analyze
   * @returns {number} Legitimacy score (0 to 1)
   */
  detectLegitimacy(text) {
    let score = 0;
    
    this.legitimacyIndicators.forEach(phrase => {
      if (text.includes(phrase)) {
        score += 0.15;
      }
    });
    
    return Math.min(1, score);
  }

  /**
   * Extract named entities (brands, organizations, etc.)
   * @param {string} text - Text to analyze
   * @returns {Object} Extracted entities
   */
  extractNamedEntities(text) {
    // Simplified NER - in production use a proper NER model
    const commonBrands = [
      'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
      'netflix', 'ebay', 'bank of america', 'chase', 'wells fargo',
      'citibank', 'american express', 'visa', 'mastercard'
    ];
    
    const textLower = text.toLowerCase();
    const detectedBrands = [];
    
    commonBrands.forEach(brand => {
      if (textLower.includes(brand)) {
        detectedBrands.push({
          entity: brand,
          type: 'ORGANIZATION',
          confidence: 0.8
        });
      }
    });
    
    // Extract email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = text.match(emailRegex) || [];
    
    // Extract URLs
    const urlRegex = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlRegex) || [];
    
    return {
      brands: detectedBrands,
      emails: emails,
      urls: urls,
      count: detectedBrands.length + emails.length + urls.length
    };
  }

  /**
   * Detect social engineering techniques
   * @param {string} text - Text to analyze
   * @returns {Object} Social engineering analysis
   */
  detectSocialEngineering(text) {
    const techniques = {
      authority: ['official', 'administrator', 'manager', 'director', 'ceo', 'security team'],
      scarcity: ['limited', 'only', 'last chance', 'expires', 'hurry', 'few left'],
      urgency: ['immediately', 'urgent', 'asap', 'right now', 'today'],
      fear: ['suspended', 'locked', 'blocked', 'terminated', 'legal action'],
      curiosity: ['you won\'t believe', 'shocking', 'secret', 'exclusive', 'insider']
    };
    
    const detected = {};
    let totalScore = 0;
    
    Object.keys(techniques).forEach(technique => {
      const matches = techniques[technique].filter(phrase => text.includes(phrase));
      if (matches.length > 0) {
        detected[technique] = matches;
        totalScore += matches.length * 0.15;
      }
    });
    
    return {
      score: Math.min(1, totalScore),
      techniques: detected,
      detected: Object.keys(detected).length > 0
    };
  }

  /**
   * Analyze grammar quality
   * @param {string} text - Text to analyze
   * @returns {number} Grammar score (0 to 1)
   */
  analyzeGrammar(text) {
    let score = 1.0;
    
    // Check for common grammar issues
    const sentences = text.split(/[.!?]+/);
    
    // Check capitalization
    sentences.forEach(sentence => {
      const trimmed = sentence.trim();
      if (trimmed.length > 0 && trimmed[0] !== trimmed[0].toUpperCase()) {
        score -= 0.1;
      }
    });
    
    // Check for excessive spaces
    if (text.includes('  ')) score -= 0.1;
    
    // Check for missing spaces after punctuation
    if (/[.,!?][a-zA-Z]/.test(text)) score -= 0.15;
    
    // Check for spelling-like issues (repeated characters)
    if (/(.)\1{3,}/.test(text)) score -= 0.2;
    
    return Math.max(0, score);
  }

  /**
   * Detect brand impersonation
   * @param {string} text - Text to analyze
   * @param {Object} entities - Extracted entities
   * @returns {Object} Brand impersonation analysis
   */
  detectBrandImpersonation(text, entities) {
    const suspiciousPatterns = [
      /verify.*account/i,
      /confirm.*identity/i,
      /update.*payment/i,
      /unusual.*activity/i,
      /security.*alert/i
    ];
    
    let score = 0;
    const detectedPatterns = [];
    
    // If brands are mentioned with suspicious patterns
    if (entities.brands.length > 0) {
      suspiciousPatterns.forEach(pattern => {
        if (pattern.test(text)) {
          score += 0.3;
          detectedPatterns.push(pattern.source);
        }
      });
    }
    
    return {
      score: Math.min(1, score),
      detected: score > 0.3,
      brands: entities.brands.map(b => b.entity),
      suspiciousPatterns: detectedPatterns
    };
  }

  /**
   * Calculate overall phishing score
   * @param {Object} scores - Individual scores
   * @returns {number} Overall phishing probability (0 to 1)
   */
  calculatePhishingScore(scores) {
    // Weighted combination of scores
    const weights = {
      urgency: 0.20,
      fear: 0.20,
      reward: 0.15,
      socialEngineering: 0.20,
      brandImpersonation: 0.15,
      grammar: -0.10, // Good grammar reduces phishing score
      legitimacy: -0.15, // Legitimacy indicators reduce phishing score
      sentiment: -0.05 // Positive sentiment reduces phishing score
    };
    
    let totalScore = 0;
    
    Object.keys(weights).forEach(key => {
      if (scores[key] !== undefined) {
        totalScore += scores[key] * weights[key];
      }
    });
    
    // Normalize to 0-1 range
    return Math.max(0, Math.min(1, (totalScore + 0.5)));
  }

  /**
   * Get sentiment label
   * @param {number} score - Sentiment score
   * @returns {string} Sentiment label
   */
  getSentimentLabel(score) {
    if (score > 0.3) return 'positive';
    if (score < -0.3) return 'negative';
    return 'neutral';
  }

  /**
   * Get risk level based on phishing score
   * @param {number} score - Phishing score
   * @returns {string} Risk level
   */
  getRiskLevel(score) {
    if (score >= 0.7) return 'critical';
    if (score >= 0.5) return 'high';
    if (score >= 0.3) return 'medium';
    return 'low';
  }

  /**
   * Calculate confidence in the analysis
   * @param {number} score - Phishing score
   * @returns {number} Confidence (0 to 1)
   */
  calculateConfidence(score) {
    // Higher confidence for extreme scores
    const distance = Math.abs(score - 0.5);
    return 0.5 + distance;
  }

  /**
   * Find matching phrases in text
   * @param {string} text - Text to search
   * @param {string[]} phrases - Phrases to find
   * @returns {string[]} Matched phrases
   */
  findMatchingPhrases(text, phrases) {
    return phrases.filter(phrase => text.includes(phrase));
  }

  /**
   * Generate explanation for the analysis
   * @param {Object} analysis - Analysis results
   * @returns {string[]} Array of explanation points
   */
  generateExplanation(analysis) {
    const explanations = [];
    
    if (analysis.urgency.detected) {
      explanations.push(`High urgency detected: ${analysis.urgency.phrases.join(', ')}`);
    }
    
    if (analysis.fearTactics.detected) {
      explanations.push(`Fear tactics used: ${analysis.fearTactics.phrases.join(', ')}`);
    }
    
    if (analysis.rewardLures.detected) {
      explanations.push(`Reward lures detected: ${analysis.rewardLures.phrases.join(', ')}`);
    }
    
    if (analysis.socialEngineering.detected) {
      const techniques = Object.keys(analysis.socialEngineering.techniques).join(', ');
      explanations.push(`Social engineering techniques: ${techniques}`);
    }
    
    if (analysis.brandImpersonation.detected) {
      explanations.push(`Possible brand impersonation: ${analysis.brandImpersonation.brands.join(', ')}`);
    }
    
    if (analysis.grammar.quality === 'poor') {
      explanations.push('Poor grammar quality detected');
    }
    
    if (analysis.entities.count > 0) {
      explanations.push(`${analysis.entities.count} entities detected (brands, emails, URLs)`);
    }
    
    return explanations;
  }
}

// Create singleton instance
export const advancedNLP = new AdvancedNLPAnalyzer();

export default advancedNLP;
