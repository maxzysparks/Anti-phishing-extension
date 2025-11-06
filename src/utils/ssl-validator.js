/**
 * SSL/TLS Certificate Validator
 * Validates HTTPS connections and detects security issues
 */

export class SSLValidator {
  /**
   * Validate URL security
   */
  static validateURL(url) {
    const issues = [];
    
    try {
      const urlObj = new URL(url);
      
      // Check 1: HTTP vs HTTPS
      if (urlObj.protocol === 'http:') {
        issues.push({
          type: 'insecure_protocol',
          severity: 'high',
          message: 'Insecure HTTP connection (not encrypted)',
          recommendation: 'Always use HTTPS for sensitive data'
        });
      }
      
      // Check 2: Localhost exceptions (common in development)
      const isLocalhost = urlObj.hostname === 'localhost' || 
                         urlObj.hostname === '127.0.0.1' ||
                         urlObj.hostname.endsWith('.local');
      
      if (isLocalhost && urlObj.protocol === 'http:') {
        // Downgrade severity for localhost
        const lastIssue = issues[issues.length - 1];
        if (lastIssue && lastIssue.type === 'insecure_protocol') {
          lastIssue.severity = 'low';
          lastIssue.message = 'HTTP on localhost (acceptable for development)';
        }
      }
      
      // Check 3: Mixed content risk (if on HTTPS page)
      if (typeof window !== 'undefined' && window.location.protocol === 'https:') {
        if (urlObj.protocol === 'http:') {
          issues.push({
            type: 'mixed_content',
            severity: 'high',
            message: 'HTTP resource on HTTPS page (blocked by browser)',
            recommendation: 'Use HTTPS version of this resource'
          });
        }
      }
      
      // Check 4: Port-based risks
      const dangerousPorts = [21, 23, 25, 110, 143, 445, 3389];
      if (dangerousPorts.includes(urlObj.port ? parseInt(urlObj.port) : 0)) {
        issues.push({
          type: 'dangerous_port',
          severity: 'high',
          message: `Suspicious port ${urlObj.port} (commonly used for attacks)`,
          recommendation: 'Avoid clicking links with unusual ports'
        });
      }
      
      // Check 5: Weak TLS indicators in URL
      if (urlObj.searchParams.has('ssl') && urlObj.searchParams.get('ssl') === 'false') {
        issues.push({
          type: 'ssl_disabled',
          severity: 'high',
          message: 'SSL explicitly disabled in URL parameters',
          recommendation: 'Do not proceed with this link'
        });
      }
      
      return {
        secure: issues.filter(i => i.severity === 'high').length === 0,
        issues: issues,
        protocol: urlObj.protocol,
        isHTTPS: urlObj.protocol === 'https:',
        isLocalhost: isLocalhost
      };
      
    } catch (error) {
      return {
        secure: false,
        issues: [{
          type: 'validation_error',
          severity: 'medium',
          message: 'Unable to validate URL security',
          error: error.message
        }],
        protocol: null,
        isHTTPS: false
      };
    }
  }

  /**
   * Check for certificate errors (browser-level detection)
   */
  static async checkCertificateErrors(url) {
    try {
      const urlObj = new URL(url);
      
      // Only check HTTPS URLs
      if (urlObj.protocol !== 'https:') {
        return { hasCertError: false, reason: 'Not HTTPS' };
      }
      
      // Use fetch with signal to detect SSL errors
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      
      try {
        const response = await fetch(url, {
          method: 'HEAD',
          mode: 'no-cors',
          signal: controller.signal
        });
        
        clearTimeout(timeout);
        
        // If fetch succeeds, certificate is likely valid
        return {
          hasCertError: false,
          valid: true
        };
        
      } catch (fetchError) {
        clearTimeout(timeout);
        
        // Check if error is SSL-related
        const sslErrors = [
          'ERR_CERT_',
          'ERR_SSL_',
          'certificate',
          'SSL',
          'TLS'
        ];
        
        const errorMessage = fetchError.message || '';
        const isSSLError = sslErrors.some(err => errorMessage.includes(err));
        
        if (isSSLError) {
          return {
            hasCertError: true,
            error: 'SSL/TLS certificate error detected',
            details: errorMessage
          };
        }
        
        // Other network errors
        return {
          hasCertError: false,
          error: 'Network error (not SSL-related)',
          details: errorMessage
        };
      }
      
    } catch (error) {
      return {
        hasCertError: false,
        error: 'Unable to check certificate',
        details: error.message
      };
    }
  }

  /**
   * Get security recommendations based on URL
   */
  static getSecurityRecommendations(url) {
    const validation = this.validateURL(url);
    const recommendations = [];
    
    if (!validation.isHTTPS && !validation.isLocalhost) {
      recommendations.push({
        priority: 'high',
        message: 'Always look for HTTPS (padlock icon) in browser',
        icon: '🔒'
      });
    }
    
    if (validation.issues.some(i => i.type === 'mixed_content')) {
      recommendations.push({
        priority: 'high',
        message: 'Mixed content can expose sensitive data',
        icon: '⚠️'
      });
    }
    
    if (validation.issues.some(i => i.type === 'dangerous_port')) {
      recommendations.push({
        priority: 'high',
        message: 'Unusual ports often indicate malicious links',
        icon: '🚨'
      });
    }
    
    return recommendations;
  }

  /**
   * Format SSL validation results for display
   */
  static formatResults(validation) {
    const highIssues = validation.issues.filter(i => i.severity === 'high');
    const mediumIssues = validation.issues.filter(i => i.severity === 'medium');
    const lowIssues = validation.issues.filter(i => i.severity === 'low');
    
    return {
      ...validation,
      summary: {
        total: validation.issues.length,
        high: highIssues.length,
        medium: mediumIssues.length,
        low: lowIssues.length
      },
      status: validation.secure ? 'secure' : 'insecure',
      icon: validation.secure ? '🔒' : '🔓'
    };
  }
}
