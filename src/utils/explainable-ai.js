/**
 * Explainable AI (XAI) Dashboard
 * Provides transparent explanations for phishing detection decisions
 */

import { advancedNLP } from '../ml/advanced-nlp.js';

/**
 * Explainable AI System
 * Generates human-readable explanations for ML model decisions
 */
export class ExplainableAI {
  constructor() {
    this.explanationTemplates = {
      urlStructure: {
        suspicious: 'The URL structure contains {count} suspicious pattern(s): {patterns}',
        safe: 'The URL structure appears normal with no suspicious patterns detected'
      },
      domain: {
        newDomain: 'This domain was registered recently ({age} days ago), which is common for phishing sites',
        oldDomain: 'This domain has been registered for {age} days, indicating established presence',
        mismatch: 'The domain "{actual}" does not match the expected brand "{expected}"'
      },
      ssl: {
        missing: 'This site does not use HTTPS encryption, making it less secure',
        present: 'This site uses HTTPS encryption',
        invalid: 'This site has an invalid or expired SSL certificate'
      },
      content: {
        urgency: 'The content uses {count} urgency phrase(s) to pressure you: {phrases}',
        fear: 'The content uses {count} fear tactic(s): {phrases}',
        reward: 'The content promises rewards or prizes: {phrases}',
        socialEngineering: 'Social engineering techniques detected: {techniques}'
      },
      logo: {
        impersonation: 'A {brand} logo was detected, but the domain is {domain}',
        lowQuality: 'The logo appears to be a low-quality reproduction',
        multiple: 'Multiple brand logos detected on the same page'
      },
      reputation: {
        safeBrowsing: 'Google Safe Browsing flagged this URL as {threatType}',
        phishTank: 'This URL is listed in the PhishTank phishing database',
        clean: 'No threats found in major threat databases'
      }
    };
  }

  /**
   * Generate comprehensive explanation for analysis result
   * @param {Object} analysis - Complete analysis result
   * @returns {Object} Explanation with visualizations
   */
  generateExplanation(analysis) {
    const explanation = {
      summary: this.generateSummary(analysis),
      riskFactors: this.identifyRiskFactors(analysis),
      safetyIndicators: this.identifySafetyIndicators(analysis),
      detailedAnalysis: this.generateDetailedAnalysis(analysis),
      recommendations: this.generateRecommendations(analysis),
      confidence: this.explainConfidence(analysis),
      visualizations: this.generateVisualizations(analysis)
    };

    return explanation;
  }

  /**
   * Generate summary explanation
   * @param {Object} analysis - Analysis result
   * @returns {string} Summary text
   */
  generateSummary(analysis) {
    const score = analysis.overallScore || analysis.phishingProbability * 100;
    const riskLevel = analysis.riskLevel || this.getRiskLevel(score);

    const summaries = {
      safe: `This URL appears to be SAFE (${Math.round(score)}% safety score). No significant threats were detected.`,
      low: `This URL has a LOW risk level (${Math.round(score)}% safety score). Minor concerns detected, but generally appears safe.`,
      medium: `This URL has a MEDIUM risk level (${Math.round(score)}% safety score). Several suspicious indicators detected. Exercise caution.`,
      high: `This URL has a HIGH risk level (${Math.round(score)}% safety score). Multiple phishing indicators detected. Avoid visiting.`,
      critical: `This URL is CRITICAL RISK (${Math.round(score)}% safety score). Strong evidence of phishing. DO NOT VISIT.`
    };

    return summaries[riskLevel] || summaries.medium;
  }

  /**
   * Identify risk factors
   * @param {Object} analysis - Analysis result
   * @returns {Array} List of risk factors with explanations
   */
  identifyRiskFactors(analysis) {
    const factors = [];

    // URL structure risks
    if (analysis.urlAnalysis && analysis.urlAnalysis.suspicious) {
      const suspicious = analysis.urlAnalysis.suspicious;
      if (suspicious.score > 0.3) {
        factors.push({
          category: 'URL Structure',
          severity: this.getSeverity(suspicious.score),
          description: this.formatTemplate(
            this.explanationTemplates.urlStructure.suspicious,
            {
              count: suspicious.patterns.length,
              patterns: suspicious.patterns.join(', ')
            }
          ),
          score: suspicious.score,
          icon: '🔗'
        });
      }
    }

    // Domain risks
    if (analysis.domainInfo) {
      if (analysis.domainInfo.isNewDomain) {
        factors.push({
          category: 'Domain Age',
          severity: 'medium',
          description: this.formatTemplate(
            this.explanationTemplates.domain.newDomain,
            { age: analysis.domainInfo.age || 'unknown' }
          ),
          score: 0.6,
          icon: '📅'
        });
      }
    }

    // SSL risks
    if (analysis.ssl && !analysis.ssl.hasSSL) {
      factors.push({
        category: 'Security',
        severity: 'high',
        description: this.explanationTemplates.ssl.missing,
        score: 0.7,
        icon: '🔒'
      });
    }

    // Content analysis risks
    if (analysis.contentAnalysis) {
      const content = analysis.contentAnalysis.analysis;
      
      if (content.urgency && content.urgency.detected) {
        factors.push({
          category: 'Content Analysis',
          severity: this.getSeverity(content.urgency.score),
          description: this.formatTemplate(
            this.explanationTemplates.content.urgency,
            {
              count: content.urgency.phrases.length,
              phrases: content.urgency.phrases.slice(0, 3).join(', ')
            }
          ),
          score: content.urgency.score,
          icon: '⚡'
        });
      }

      if (content.fearTactics && content.fearTactics.detected) {
        factors.push({
          category: 'Content Analysis',
          severity: this.getSeverity(content.fearTactics.score),
          description: this.formatTemplate(
            this.explanationTemplates.content.fear,
            {
              count: content.fearTactics.phrases.length,
              phrases: content.fearTactics.phrases.slice(0, 3).join(', ')
            }
          ),
          score: content.fearTactics.score,
          icon: '😨'
        });
      }

      if (content.socialEngineering && content.socialEngineering.detected) {
        const techniques = Object.keys(content.socialEngineering.techniques).join(', ');
        factors.push({
          category: 'Social Engineering',
          severity: this.getSeverity(content.socialEngineering.score),
          description: this.formatTemplate(
            this.explanationTemplates.content.socialEngineering,
            { techniques }
          ),
          score: content.socialEngineering.score,
          icon: '🎭'
        });
      }
    }

    // Logo detection risks
    if (analysis.logoDetection && analysis.logoDetection.domainMismatch) {
      if (analysis.logoDetection.domainMismatch.detected) {
        factors.push({
          category: 'Brand Impersonation',
          severity: 'critical',
          description: this.formatTemplate(
            this.explanationTemplates.logo.impersonation,
            {
              brand: analysis.logoDetection.domainMismatch.suspectedBrand,
              domain: analysis.logoDetection.domainMismatch.actualDomain
            }
          ),
          score: 0.9,
          icon: '🏢'
        });
      }
    }

    // Reputation database risks
    if (analysis.safeBrowsing && !analysis.safeBrowsing.safe) {
      factors.push({
        category: 'Threat Database',
        severity: 'critical',
        description: this.formatTemplate(
          this.explanationTemplates.reputation.safeBrowsing,
          { threatType: analysis.safeBrowsing.highestSeverity }
        ),
        score: 1.0,
        icon: '🛡️'
      });
    }

    if (analysis.phishTank && analysis.phishTank.isPhishing) {
      factors.push({
        category: 'Threat Database',
        severity: 'critical',
        description: this.explanationTemplates.reputation.phishTank,
        score: 1.0,
        icon: '🛡️'
      });
    }

    // Sort by severity
    return factors.sort((a, b) => b.score - a.score);
  }

  /**
   * Identify safety indicators
   * @param {Object} analysis - Analysis result
   * @returns {Array} List of safety indicators
   */
  identifySafetyIndicators(analysis) {
    const indicators = [];

    // SSL present
    if (analysis.ssl && analysis.ssl.hasSSL && analysis.ssl.valid) {
      indicators.push({
        category: 'Security',
        description: this.explanationTemplates.ssl.present,
        icon: '✓'
      });
    }

    // Clean reputation
    if (analysis.safeBrowsing && analysis.safeBrowsing.safe) {
      indicators.push({
        category: 'Reputation',
        description: this.explanationTemplates.reputation.clean,
        icon: '✓'
      });
    }

    // Legitimate content indicators
    if (analysis.contentAnalysis) {
      const content = analysis.contentAnalysis.analysis;
      if (content.legitimacy && content.legitimacy.score > 0.5) {
        indicators.push({
          category: 'Content',
          description: `Legitimate business indicators found: ${content.legitimacy.indicators.join(', ')}`,
          icon: '✓'
        });
      }
    }

    // Established domain
    if (analysis.domainInfo && !analysis.domainInfo.isNewDomain) {
      indicators.push({
        category: 'Domain',
        description: this.formatTemplate(
          this.explanationTemplates.domain.oldDomain,
          { age: analysis.domainInfo.age || 'many' }
        ),
        icon: '✓'
      });
    }

    return indicators;
  }

  /**
   * Generate detailed analysis breakdown
   * @param {Object} analysis - Analysis result
   * @returns {Object} Detailed breakdown
   */
  generateDetailedAnalysis(analysis) {
    return {
      urlAnalysis: this.explainURLAnalysis(analysis.urlAnalysis),
      contentAnalysis: this.explainContentAnalysis(analysis.contentAnalysis),
      reputationAnalysis: this.explainReputationAnalysis(analysis),
      technicalAnalysis: this.explainTechnicalAnalysis(analysis)
    };
  }

  /**
   * Explain URL analysis
   * @param {Object} urlAnalysis - URL analysis result
   * @returns {Object} Explanation
   */
  explainURLAnalysis(urlAnalysis) {
    if (!urlAnalysis) return null;

    return {
      summary: urlAnalysis.suspicious.score > 0.3 
        ? 'URL contains suspicious patterns'
        : 'URL structure appears normal',
      patterns: urlAnalysis.suspicious.patterns,
      score: urlAnalysis.suspicious.score,
      details: urlAnalysis.parsed
    };
  }

  /**
   * Explain content analysis
   * @param {Object} contentAnalysis - Content analysis result
   * @returns {Object} Explanation
   */
  explainContentAnalysis(contentAnalysis) {
    if (!contentAnalysis || !contentAnalysis.analysis) return null;

    const analysis = contentAnalysis.analysis;
    
    return {
      summary: `Phishing probability: ${Math.round(contentAnalysis.phishingProbability * 100)}%`,
      sentiment: `Sentiment: ${analysis.sentiment.label} (${analysis.sentiment.score.toFixed(2)})`,
      urgency: analysis.urgency.detected ? `High urgency detected` : 'No urgency detected',
      fearTactics: analysis.fearTactics.detected ? 'Fear tactics present' : 'No fear tactics',
      socialEngineering: analysis.socialEngineering.detected 
        ? `Social engineering: ${Object.keys(analysis.socialEngineering.techniques).join(', ')}`
        : 'No social engineering detected',
      grammar: `Grammar quality: ${analysis.grammar.quality}`
    };
  }

  /**
   * Explain reputation analysis
   * @param {Object} analysis - Full analysis
   * @returns {Object} Explanation
   */
  explainReputationAnalysis(analysis) {
    const reputation = {
      safeBrowsing: 'Not checked',
      phishTank: 'Not checked',
      overall: 'Unknown'
    };

    if (analysis.safeBrowsing) {
      reputation.safeBrowsing = analysis.safeBrowsing.safe 
        ? 'Clean' 
        : `Threat detected: ${analysis.safeBrowsing.highestSeverity}`;
    }

    if (analysis.phishTank) {
      reputation.phishTank = analysis.phishTank.isPhishing 
        ? 'Listed as phishing' 
        : 'Not in phishing database';
    }

    return reputation;
  }

  /**
   * Explain technical analysis
   * @param {Object} analysis - Full analysis
   * @returns {Object} Explanation
   */
  explainTechnicalAnalysis(analysis) {
    return {
      ssl: analysis.ssl ? (analysis.ssl.hasSSL ? 'HTTPS enabled' : 'No HTTPS') : 'Unknown',
      domain: analysis.domainInfo ? analysis.domainInfo.domain : 'Unknown',
      domainAge: analysis.domainInfo && analysis.domainInfo.age 
        ? `${analysis.domainInfo.age} days` 
        : 'Unknown'
    };
  }

  /**
   * Generate recommendations
   * @param {Object} analysis - Analysis result
   * @returns {Array} List of recommendations
   */
  generateRecommendations(analysis) {
    const recommendations = [];
    const score = analysis.overallScore || (1 - analysis.phishingProbability) * 100;

    if (score < 40) {
      recommendations.push({
        priority: 'critical',
        action: 'Do NOT visit this website',
        reason: 'High risk of phishing detected',
        icon: '🚫'
      });
      recommendations.push({
        priority: 'high',
        action: 'Report this URL',
        reason: 'Help protect others from this threat',
        icon: '📢'
      });
    } else if (score < 60) {
      recommendations.push({
        priority: 'high',
        action: 'Proceed with extreme caution',
        reason: 'Multiple suspicious indicators detected',
        icon: '⚠️'
      });
      recommendations.push({
        priority: 'medium',
        action: 'Do not enter personal information',
        reason: 'Site authenticity cannot be verified',
        icon: '🔐'
      });
    } else if (score < 80) {
      recommendations.push({
        priority: 'medium',
        action: 'Verify the website independently',
        reason: 'Some suspicious indicators present',
        icon: '🔍'
      });
    } else {
      recommendations.push({
        priority: 'low',
        action: 'Site appears safe to visit',
        reason: 'No significant threats detected',
        icon: '✅'
      });
    }

    return recommendations;
  }

  /**
   * Explain confidence level
   * @param {Object} analysis - Analysis result
   * @returns {Object} Confidence explanation
   */
  explainConfidence(analysis) {
    const confidence = analysis.confidence || 50;
    
    let explanation = '';
    if (confidence >= 80) {
      explanation = 'High confidence - Multiple data sources analyzed';
    } else if (confidence >= 60) {
      explanation = 'Moderate confidence - Several data sources analyzed';
    } else {
      explanation = 'Lower confidence - Limited data sources available';
    }

    return {
      score: confidence,
      level: confidence >= 80 ? 'high' : confidence >= 60 ? 'moderate' : 'low',
      explanation: explanation
    };
  }

  /**
   * Generate visualizations data
   * @param {Object} analysis - Analysis result
   * @returns {Object} Visualization data
   */
  generateVisualizations(analysis) {
    return {
      scoreGauge: this.generateScoreGauge(analysis),
      factorBreakdown: this.generateFactorBreakdown(analysis),
      timeline: this.generateTimeline(analysis),
      comparisonChart: this.generateComparisonChart(analysis)
    };
  }

  /**
   * Generate score gauge data
   * @param {Object} analysis - Analysis result
   * @returns {Object} Gauge data
   */
  generateScoreGauge(analysis) {
    const score = analysis.overallScore || (1 - analysis.phishingProbability) * 100;
    
    return {
      value: Math.round(score),
      max: 100,
      ranges: [
        { min: 0, max: 20, color: '#dc3545', label: 'Critical' },
        { min: 20, max: 40, color: '#fd7e14', label: 'High Risk' },
        { min: 40, max: 60, color: '#ffc107', label: 'Medium Risk' },
        { min: 60, max: 80, color: '#17a2b8', label: 'Low Risk' },
        { min: 80, max: 100, color: '#28a745', label: 'Safe' }
      ]
    };
  }

  /**
   * Generate factor breakdown data
   * @param {Object} analysis - Analysis result
   * @returns {Array} Factor data
   */
  generateFactorBreakdown(analysis) {
    const factors = [];

    if (analysis.scores) {
      Object.keys(analysis.scores).forEach(key => {
        if (analysis.scores[key] !== null && analysis.scores[key] !== 0) {
          factors.push({
            name: this.formatFactorName(key),
            score: Math.round(analysis.scores[key] * 100),
            weight: analysis.weights ? analysis.weights[key] : 0
          });
        }
      });
    }

    return factors.sort((a, b) => b.score - a.score);
  }

  /**
   * Generate timeline data
   * @param {Object} analysis - Analysis result
   * @returns {Array} Timeline events
   */
  generateTimeline(analysis) {
    const events = [];
    const timestamp = analysis.timestamp || Date.now();

    events.push({
      time: new Date(timestamp).toLocaleTimeString(),
      event: 'Analysis started',
      type: 'info'
    });

    if (analysis.safeBrowsing) {
      events.push({
        time: new Date(timestamp + 100).toLocaleTimeString(),
        event: 'Google Safe Browsing checked',
        type: analysis.safeBrowsing.safe ? 'success' : 'danger'
      });
    }

    if (analysis.phishTank) {
      events.push({
        time: new Date(timestamp + 200).toLocaleTimeString(),
        event: 'PhishTank database checked',
        type: analysis.phishTank.isPhishing ? 'danger' : 'success'
      });
    }

    events.push({
      time: new Date(timestamp + 500).toLocaleTimeString(),
      event: 'Analysis completed',
      type: 'info'
    });

    return events;
  }

  /**
   * Generate comparison chart data
   * @param {Object} analysis - Analysis result
   * @returns {Object} Comparison data
   */
  generateComparisonChart(analysis) {
    const score = analysis.overallScore || (1 - analysis.phishingProbability) * 100;

    return {
      current: Math.round(score),
      average: 75, // Average safety score
      threshold: 60 // Minimum safe threshold
    };
  }

  /**
   * Format template with variables
   * @param {string} template - Template string
   * @param {Object} vars - Variables to replace
   * @returns {string} Formatted string
   */
  formatTemplate(template, vars) {
    let result = template;
    Object.keys(vars).forEach(key => {
      result = result.replace(`{${key}}`, vars[key]);
    });
    return result;
  }

  /**
   * Get severity level from score
   * @param {number} score - Risk score (0-1)
   * @returns {string} Severity level
   */
  getSeverity(score) {
    if (score >= 0.7) return 'critical';
    if (score >= 0.5) return 'high';
    if (score >= 0.3) return 'medium';
    return 'low';
  }

  /**
   * Get risk level from score
   * @param {number} score - Safety score (0-100)
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
   * Format factor name for display
   * @param {string} name - Factor name
   * @returns {string} Formatted name
   */
  formatFactorName(name) {
    return name
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim();
  }
}

// Create singleton instance
export const explainableAI = new ExplainableAI();

export default explainableAI;
