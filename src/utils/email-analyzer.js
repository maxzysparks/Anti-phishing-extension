/**
 * Email Header & Content Analyzer
 * Analyzes email metadata and content for phishing indicators
 * (Client-side analysis - no Gmail API required)
 */

export class EmailAnalyzer {
  /**
   * Extract email metadata from DOM
   */
  static extractEmailMetadata(emailElement) {
    try {
      // Gmail-specific selectors
      const metadata = {
        from: this.extractSender(emailElement),
        replyTo: this.extractReplyTo(emailElement),
        subject: this.extractSubject(emailElement),
        date: this.extractDate(emailElement),
        headers: this.extractHeaders(emailElement),
        body: this.extractBody(emailElement)
      };
      
      return metadata;
    } catch (error) {
      console.error('[Email] Error extracting metadata:', error);
      return null;
    }
  }

  /**
   * Extract sender information
   */
  static extractSender(emailElement) {
    // Try various Gmail selectors
    const selectors = [
      '[email]',
      '.gD',  // Gmail sender email
      '[data-hovercard-id]',
      '.go'   // Gmail sender name
    ];
    
    for (const selector of selectors) {
      const element = emailElement.querySelector(selector);
      if (element) {
        const email = element.getAttribute('email') || 
                     element.getAttribute('data-hovercard-id') ||
                     element.textContent;
        
        if (email && email.includes('@')) {
          return {
            email: email.trim(),
            name: element.getAttribute('name') || element.textContent.trim()
          };
        }
      }
    }
    
    return null;
  }

  /**
   * Extract reply-to (if different from sender)
   */
  static extractReplyTo(emailElement) {
    // Check if reply-to is shown (usually means it's different from sender)
    const replyToElement = emailElement.querySelector('[aria-label*="Reply"]');
    if (replyToElement) {
      const email = replyToElement.getAttribute('data-email');
      if (email) {
        return email.trim();
      }
    }
    return null;
  }

  /**
   * Extract subject
   */
  static extractSubject(emailElement) {
    const subjectSelectors = ['h2', '[role="heading"]', '.hP'];
    
    for (const selector of subjectSelectors) {
      const element = emailElement.querySelector(selector);
      if (element && element.textContent) {
        return element.textContent.trim();
      }
    }
    
    return '';
  }

  /**
   * Extract date
   */
  static extractDate(emailElement) {
    const dateElement = emailElement.querySelector('[title]');
    if (dateElement) {
      return dateElement.getAttribute('title') || dateElement.textContent;
    }
    return null;
  }

  /**
   * Extract visible headers
   */
  static extractHeaders(emailElement) {
    const headers = {};
    
    // Look for expanded header details
    const headerElements = emailElement.querySelectorAll('[data-message-id]');
    headerElements.forEach(el => {
      const key = el.getAttribute('data-header');
      const value = el.textContent;
      if (key && value) {
        headers[key] = value.trim();
      }
    });
    
    return headers;
  }

  /**
   * Extract email body text
   */
  static extractBody(emailElement) {
    const bodySelectors = ['.a3s', '.ii', '[data-message-id] div'];
    
    for (const selector of bodySelectors) {
      const element = emailElement.querySelector(selector);
      if (element) {
        return element.textContent.trim();
      }
    }
    
    return '';
  }

  /**
   * Analyze email for phishing indicators
   */
  static analyzeEmail(metadata) {
    const findings = [];
    let riskScore = 0;

    if (!metadata) {
      return { findings, riskScore, valid: false };
    }

    // Check 1: Sender-Reply-To Mismatch
    if (metadata.from && metadata.replyTo) {
      const fromDomain = this.extractDomain(metadata.from.email);
      const replyToDomain = this.extractDomain(metadata.replyTo);
      
      if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
        findings.push({
          type: 'sender_mismatch',
          severity: 'high',
          message: `Reply-To domain (${replyToDomain}) differs from sender (${fromDomain})`,
          indicator: 'Possible email spoofing'
        });
        riskScore += 8;
      }
    }

    // Check 2: Sender Domain Analysis
    if (metadata.from) {
      const domainAnalysis = this.analyzeSenderDomain(metadata.from.email);
      if (domainAnalysis.suspicious) {
        findings.push({
          type: 'suspicious_domain',
          severity: domainAnalysis.severity,
          message: domainAnalysis.message,
          indicator: domainAnalysis.indicator
        });
        riskScore += domainAnalysis.score;
      }
    }

    // Check 3: Subject Line Analysis
    if (metadata.subject) {
      const subjectAnalysis = this.analyzeSubject(metadata.subject);
      if (subjectAnalysis.suspicious) {
        findings.push({
          type: 'suspicious_subject',
          severity: subjectAnalysis.severity,
          message: subjectAnalysis.message,
          keywords: subjectAnalysis.keywords
        });
        riskScore += subjectAnalysis.score;
      }
    }

    // Check 4: Email Body Analysis
    if (metadata.body) {
      const bodyAnalysis = this.analyzeBody(metadata.body);
      if (bodyAnalysis.suspicious) {
        findings.push({
          type: 'suspicious_content',
          severity: bodyAnalysis.severity,
          message: bodyAnalysis.message,
          patterns: bodyAnalysis.patterns
        });
        riskScore += bodyAnalysis.score;
      }
    }

    // Check 5: Display Name Spoofing
    if (metadata.from && metadata.from.name) {
      const displayNameAnalysis = this.analyzeDisplayName(
        metadata.from.name,
        metadata.from.email
      );
      
      if (displayNameAnalysis.suspicious) {
        findings.push({
          type: 'display_name_spoof',
          severity: displayNameAnalysis.severity,
          message: displayNameAnalysis.message
        });
        riskScore += displayNameAnalysis.score;
      }
    }

    return {
      findings,
      riskScore,
      valid: true,
      metadata
    };
  }

  /**
   * Extract domain from email
   */
  static extractDomain(email) {
    if (!email) return null;
    const match = email.match(/@(.+)$/);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Analyze sender domain
   */
  static analyzeSenderDomain(email) {
    const domain = this.extractDomain(email);
    if (!domain) return { suspicious: false };

    // Free email providers (higher risk for business emails)
    const freeProviders = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
      'protonmail.com', 'aol.com', 'mail.com'
    ];

    // Suspicious TLDs
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'];
    const tld = domain.split('.').pop();

    // Check for suspicious TLD
    if (suspiciousTLDs.includes(tld)) {
      return {
        suspicious: true,
        severity: 'high',
        message: `Suspicious TLD (.${tld}) commonly used for phishing`,
        indicator: 'Unusual domain extension',
        score: 5
      };
    }

    // Check for recently registered indicators (long random strings)
    if (/[a-z0-9]{15,}/.test(domain)) {
      return {
        suspicious: true,
        severity: 'medium',
        message: 'Domain contains unusually long random string',
        indicator: 'Possible disposable domain',
        score: 3
      };
    }

    // Check for excessive hyphens
    if ((domain.match(/-/g) || []).length > 2) {
      return {
        suspicious: true,
        severity: 'medium',
        message: 'Domain contains excessive hyphens',
        indicator: 'Unusual domain structure',
        score: 2
      };
    }

    return { suspicious: false };
  }

  /**
   * Analyze subject line
   */
  static analyzeSubject(subject) {
    const lowerSubject = subject.toLowerCase();
    let score = 0;
    const keywords = [];

    // Urgent/pressure keywords
    const urgentKeywords = [
      'urgent', 'immediate', 'action required', 'suspended', 'locked',
      'verify', 'confirm', 'update', 'expire', 'limited time', 'act now'
    ];

    urgentKeywords.forEach(keyword => {
      if (lowerSubject.includes(keyword)) {
        keywords.push(keyword);
        score += 2;
      }
    });

    // Financial keywords
    const financialKeywords = [
      'payment', 'invoice', 'refund', 'prize', 'winner', 'claim',
      'wire transfer', 'bank', 'account', 'credit card'
    ];

    financialKeywords.forEach(keyword => {
      if (lowerSubject.includes(keyword)) {
        keywords.push(keyword);
        score += 1;
      }
    });

    // Excessive caps or punctuation
    if (/[A-Z]{5,}/.test(subject)) {
      keywords.push('EXCESSIVE_CAPS');
      score += 2;
    }

    if (/[!?]{3,}/.test(subject)) {
      keywords.push('excessive_punctuation');
      score += 1;
    }

    if (score > 0) {
      return {
        suspicious: true,
        severity: score >= 4 ? 'high' : 'medium',
        message: `Subject contains ${keywords.length} suspicious keywords`,
        keywords: keywords,
        score: score
      };
    }

    return { suspicious: false };
  }

  /**
   * Analyze email body
   */
  static analyzeBody(body) {
    const lowerBody = body.toLowerCase();
    let score = 0;
    const patterns = [];

    // URLs in body
    const urlCount = (body.match(/https?:\/\//gi) || []).length;
    if (urlCount > 5) {
      patterns.push('multiple_links');
      score += 2;
    }

    // Suspicious phrases
    const suspiciousPhrases = [
      'click here', 'verify your account', 'confirm your identity',
      'unusual activity', 'suspended account', 'reactivate',
      'win', 'congratulations', 'selected', 'winner'
    ];

    suspiciousPhrases.forEach(phrase => {
      if (lowerBody.includes(phrase)) {
        patterns.push(phrase);
        score += 1;
      }
    });

    // Sense of urgency
    if (/within \d+ (hour|day)s?/i.test(body)) {
      patterns.push('time_pressure');
      score += 2;
    }

    // Request for personal info
    const personalInfoRequests = [
      'password', 'ssn', 'social security', 'credit card',
      'bank account', 'pin', 'security question'
    ];

    personalInfoRequests.forEach(term => {
      if (lowerBody.includes(term)) {
        patterns.push(`requests_${term.replace(' ', '_')}`);
        score += 3;
      }
    });

    if (score > 0) {
      return {
        suspicious: true,
        severity: score >= 6 ? 'high' : 'medium',
        message: `Email content contains ${patterns.length} phishing indicators`,
        patterns: patterns,
        score: score
      };
    }

    return { suspicious: false };
  }

  /**
   * Analyze display name for spoofing
   */
  static analyzeDisplayName(displayName, email) {
    const lowerName = displayName.toLowerCase();
    const domain = this.extractDomain(email);

    // Check for brand impersonation in display name
    const majorBrands = [
      'paypal', 'amazon', 'microsoft', 'apple', 'google',
      'facebook', 'ebay', 'netflix', 'bank', 'irs'
    ];

    for (const brand of majorBrands) {
      if (lowerName.includes(brand)) {
        // Check if domain matches
        if (!domain || !domain.includes(brand)) {
          return {
            suspicious: true,
            severity: 'high',
            message: `Display name claims to be ${brand} but domain is ${domain}`,
            score: 8
          };
        }
      }
    }

    // Check for email address in display name (unusual)
    if (/@/.test(displayName) && displayName !== email) {
      return {
        suspicious: true,
        severity: 'medium',
        message: 'Display name contains different email address',
        score: 4
      };
    }

    return { suspicious: false };
  }

  /**
   * Generate email analysis report
   */
  static generateReport(analysis) {
    if (!analysis || !analysis.valid) {
      return {
        safe: false,
        message: 'Unable to analyze email'
      };
    }

    const { findings, riskScore } = analysis;

    if (findings.length === 0) {
      return {
        safe: true,
        riskLevel: 'low',
        message: 'No suspicious indicators detected',
        score: 0
      };
    }

    let riskLevel = 'low';
    let message = 'Email appears normal';

    if (riskScore >= 10) {
      riskLevel = 'high';
      message = 'HIGH RISK: Multiple phishing indicators detected';
    } else if (riskScore >= 5) {
      riskLevel = 'medium';
      message = 'CAUTION: Some suspicious characteristics detected';
    } else {
      riskLevel = 'low';
      message = 'Minor concerns detected';
    }

    return {
      safe: riskScore < 5,
      riskLevel,
      message,
      score: riskScore,
      findings: findings,
      details: this.formatFindings(findings)
    };
  }

  /**
   * Format findings for display
   */
  static formatFindings(findings) {
    return findings.map(finding => {
      const icon = finding.severity === 'high' ? '🔴' : 
                   finding.severity === 'medium' ? '🟡' : '🟢';
      return `${icon} ${finding.message}`;
    }).join('\n');
  }
}
