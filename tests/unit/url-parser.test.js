/**
 * Unit Tests for URL Parser
 * Tests all URL analysis and detection methods
 */

import { URLParser, analyzeURL } from '../../src/utils/url-parser.js';

describe('URLParser', () => {
  describe('Basic URL Parsing', () => {
    test('should parse valid HTTPS URL', () => {
      const parser = new URLParser('https://example.com/path');
      expect(parser.hostname).toBe('example.com');
      expect(parser.domain).toBe('example.com');
      expect(parser.protocol).toBe('https:');
    });

    test('should parse URL with subdomain', () => {
      const parser = new URLParser('https://www.example.com');
      expect(parser.hostname).toBe('www.example.com');
      expect(parser.domain).toBe('example.com');
    });

    test('should handle invalid URL', () => {
      const parser = new URLParser('not-a-url');
      expect(parser.parsed).toBeNull();
    });
  });

  describe('IP Address Detection', () => {
    test('should detect IPv4 address', () => {
      const parser = new URLParser('http://192.168.1.1/page');
      expect(parser.isIPAddress()).toBe(true);
    });

    test('should not flag legitimate domain as IP', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.isIPAddress()).toBe(false);
    });
  });

  describe('Suspicious TLD Detection', () => {
    test('should detect suspicious TLD .tk', () => {
      const parser = new URLParser('https://phishing.tk');
      expect(parser.hasSuspiciousTLD()).toBe(true);
    });

    test('should detect suspicious TLD .ml', () => {
      const parser = new URLParser('https://scam.ml');
      expect(parser.hasSuspiciousTLD()).toBe(true);
    });

    test('should not flag .com as suspicious', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.hasSuspiciousTLD()).toBe(false);
    });
  });

  describe('Typosquatting Detection', () => {
    test('should detect gooogle.com typosquatting', () => {
      const parser = new URLParser('https://gooogle.com');
      expect(parser.isTyposquatting()).toBe(true);
    });

    test('should detect paypa1.com typosquatting', () => {
      const parser = new URLParser('https://paypa1.com');
      expect(parser.isTyposquatting()).toBe(true);
    });

    test('should not flag legitimate google.com', () => {
      const parser = new URLParser('https://google.com');
      expect(parser.isTyposquatting()).toBe(false);
    });

    test('should detect character substitution', () => {
      const parser = new URLParser('https://g00gle.com');
      expect(parser.hasCharacterSubstitution('google')).toBe(true);
    });
  });

  describe('Homograph Attack Detection', () => {
    test('should detect Cyrillic characters', () => {
      const parser = new URLParser('https://раypal.com'); // Cyrillic 'а'
      expect(parser.hasHomographAttack()).toBe(true);
    });

    test('should detect mixed scripts', () => {
      const scripts = parser.detectMixedScripts('payраl'); // Latin + Cyrillic
      expect(scripts.size).toBeGreaterThan(1);
    });

    test('should not flag pure Latin domain', () => {
      const parser = new URLParser('https://paypal.com');
      expect(parser.hasHomographAttack()).toBe(false);
    });
  });

  describe('URL Shortener Detection', () => {
    test('should detect bit.ly', () => {
      const parser = new URLParser('https://bit.ly/abc123');
      expect(parser.isURLShortener()).toBe(true);
    });

    test('should detect tinyurl.com', () => {
      const parser = new URLParser('https://tinyurl.com/xyz');
      expect(parser.isURLShortener()).toBe(true);
    });

    test('should not flag regular domain', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.isURLShortener()).toBe(false);
    });
  });

  describe('Legitimate Domain Detection', () => {
    test('should recognize google.com as legitimate', () => {
      const parser = new URLParser('https://google.com');
      expect(parser.isLegitimate()).toBe(true);
    });

    test('should recognize paypal.com as legitimate', () => {
      const parser = new URLParser('https://paypal.com');
      expect(parser.isLegitimate()).toBe(true);
    });

    test('should not flag unknown domain as legitimate', () => {
      const parser = new URLParser('https://unknown-site.com');
      expect(parser.isLegitimate()).toBe(false);
    });
  });

  describe('Encoded Characters Detection', () => {
    test('should detect URL encoding', () => {
      const parser = new URLParser('https://example.com/%2Fpath');
      expect(parser.hasEncodedChars()).toBe(true);
    });

    test('should not flag clean URL', () => {
      const parser = new URLParser('https://example.com/path');
      expect(parser.hasEncodedChars()).toBe(false);
    });
  });

  describe('Insecure Protocol Detection', () => {
    test('should detect HTTP as insecure', () => {
      const parser = new URLParser('http://example.com');
      expect(parser.isInsecure()).toBe(true);
    });

    test('should not flag HTTPS as insecure', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.isInsecure()).toBe(false);
    });
  });

  describe('Dangerous Scheme Detection', () => {
    test('should detect javascript: scheme', () => {
      const parser = new URLParser('javascript:alert(1)');
      expect(parser.hasDangerousScheme()).toBe(true);
    });

    test('should detect data: scheme', () => {
      const parser = new URLParser('data:text/html,<script>alert(1)</script>');
      expect(parser.hasDangerousScheme()).toBe(true);
    });

    test('should not flag https: as dangerous', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.hasDangerousScheme()).toBe(false);
    });
  });

  describe('Username in URL Detection', () => {
    test('should detect username in URL', () => {
      const parser = new URLParser('https://user@example.com');
      expect(parser.hasUsernameInURL()).toBe(true);
    });

    test('should not flag URL without username', () => {
      const parser = new URLParser('https://example.com');
      expect(parser.hasUsernameInURL()).toBe(false);
    });
  });

  describe('Subdomain Impersonation Detection', () => {
    test('should detect paypal in subdomain', () => {
      const parser = new URLParser('https://paypal.evil.com');
      expect(parser.hasSubdomainImpersonation()).toBe(true);
    });

    test('should detect amazon in subdomain', () => {
      const parser = new URLParser('https://amazon.phishing.com');
      expect(parser.hasSubdomainImpersonation()).toBe(true);
    });

    test('should not flag legitimate paypal.com', () => {
      const parser = new URLParser('https://paypal.com');
      expect(parser.hasSubdomainImpersonation()).toBe(false);
    });
  });

  describe('Path Spoofing Detection', () => {
    test('should detect paypal.com in path', () => {
      const parser = new URLParser('https://evil.com/paypal.com/login');
      expect(parser.hasPathSpoofing()).toBe(true);
    });

    test('should not flag legitimate path', () => {
      const parser = new URLParser('https://example.com/about');
      expect(parser.hasPathSpoofing()).toBe(false);
    });
  });

  describe('Threat Level Calculation', () => {
    test('should mark legitimate domain as safe', () => {
      const parser = new URLParser('https://google.com');
      expect(parser.getThreatLevel()).toBe('safe');
    });

    test('should mark IP address as dangerous', () => {
      const parser = new URLParser('http://192.168.1.1');
      const level = parser.getThreatLevel();
      expect(['dangerous', 'suspicious']).toContain(level);
    });

    test('should mark typosquatting as dangerous', () => {
      const parser = new URLParser('https://gooogle.com');
      expect(parser.getThreatLevel()).toBe('dangerous');
    });
  });

  describe('Issue Detection', () => {
    test('should return empty issues for safe URL', () => {
      const parser = new URLParser('https://google.com');
      const issues = parser.getIssues();
      expect(issues.length).toBe(0);
    });

    test('should return multiple issues for dangerous URL', () => {
      const parser = new URLParser('http://192.168.1.1');
      const issues = parser.getIssues();
      expect(issues.length).toBeGreaterThan(0);
    });

    test('should categorize issues by severity', () => {
      const parser = new URLParser('javascript:alert(1)');
      const issues = parser.getIssues();
      const highSeverity = issues.filter(i => i.severity === 'high');
      expect(highSeverity.length).toBeGreaterThan(0);
    });
  });

  describe('analyzeURL Helper Function', () => {
    test('should return complete analysis', () => {
      const analysis = analyzeURL('https://example.com');
      expect(analysis).toHaveProperty('url');
      expect(analysis).toHaveProperty('domain');
      expect(analysis).toHaveProperty('threatLevel');
      expect(analysis).toHaveProperty('issues');
    });

    test('should detect multiple issues', () => {
      const analysis = analyzeURL('http://gooogle.tk');
      expect(analysis.issues.length).toBeGreaterThan(1);
    });
  });

  describe('Edge Cases', () => {
    test('should handle URL with port', () => {
      const parser = new URLParser('https://example.com:8080');
      expect(parser.hostname).toBe('example.com');
    });

    test('should handle URL with query parameters', () => {
      const parser = new URLParser('https://example.com?param=value');
      expect(parser.hostname).toBe('example.com');
    });

    test('should handle URL with fragment', () => {
      const parser = new URLParser('https://example.com#section');
      expect(parser.hostname).toBe('example.com');
    });

    test('should handle very long URL', () => {
      const longPath = 'a'.repeat(1000);
      const parser = new URLParser(`https://example.com/${longPath}`);
      expect(parser.hasLongDomain()).toBe(false);
    });

    test('should handle internationalized domain', () => {
      const parser = new URLParser('https://münchen.de');
      expect(parser.parsed).not.toBeNull();
    });
  });
});
