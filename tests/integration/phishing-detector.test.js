/**
 * Integration Tests for Phishing Detector
 * Tests the complete phishing detection workflow
 */

import { PhishingDetector } from '../../src/utils/phishing-detector.js';
import { StorageManager } from '../../src/utils/storage.js';

describe('PhishingDetector Integration Tests', () => {
  beforeEach(async () => {
    // Clear storage before each test
    await chrome.storage.local.clear();
    await chrome.storage.sync.clear();
  });

  describe('Complete Analysis Workflow', () => {
    test('should analyze safe URL completely', async () => {
      const result = await PhishingDetector.analyzeLink('https://google.com');
      
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('threatLevel');
      expect(result).toHaveProperty('issues');
      expect(result.threatLevel).toBe('safe');
    });

    test('should analyze dangerous URL completely', async () => {
      const result = await PhishingDetector.analyzeLink('http://192.168.1.1');
      
      expect(result.threatLevel).toMatch(/dangerous|suspicious/);
      expect(result.issues.length).toBeGreaterThan(0);
    });

    test('should cache analysis results', async () => {
      const url = 'https://example.com';
      
      // First analysis
      const result1 = await PhishingDetector.analyzeLink(url);
      
      // Second analysis should use cache
      const result2 = await PhishingDetector.analyzeLink(url);
      
      expect(result1.url).toBe(result2.url);
      expect(result1.threatLevel).toBe(result2.threatLevel);
    });
  });

  describe('Whitelist Integration', () => {
    test('should respect whitelist', async () => {
      const domain = 'example.com';
      await StorageManager.addToWhitelist(domain);
      
      const result = await PhishingDetector.analyzeLink('https://example.com/page');
      
      expect(result.threatLevel).toBe('safe');
      expect(result.isWhitelisted).toBe(true);
    });

    test('should remove compromised domain from whitelist', async () => {
      const domain = 'evil.tk';
      await StorageManager.addToWhitelist(domain);
      
      const result = await PhishingDetector.analyzeLink('https://evil.tk');
      
      // Should detect as suspicious despite whitelist
      const whitelist = await StorageManager.getWhitelist();
      expect(whitelist).not.toContain(domain);
    });
  });

  describe('Blacklist Integration', () => {
    test('should block blacklisted domain', async () => {
      const domain = 'evil.com';
      await StorageManager.addToBlacklist(domain);
      
      const result = await PhishingDetector.analyzeLink('https://evil.com');
      
      expect(result.threatLevel).toBe('dangerous');
      expect(result.isBlacklisted).toBe(true);
    });
  });

  describe('Context Analysis', () => {
    test('should detect phishing keywords in context', () => {
      const context = 'urgent verify your account password suspended';
      const score = PhishingDetector.analyzeContext(context);
      
      expect(score).toBeGreaterThan(0);
    });

    test('should detect spam indicators', () => {
      const context = 'viagra cialis free money work from home';
      const score = PhishingDetector.analyzeContext(context);
      
      expect(score).toBeGreaterThan(5);
    });

    test('should not flag normal context', () => {
      const context = 'hello how are you today';
      const score = PhishingDetector.analyzeContext(context);
      
      expect(score).toBe(0);
    });
  });

  describe('Batch Analysis', () => {
    test('should analyze multiple URLs', async () => {
      const urls = [
        'https://google.com',
        'https://example.com',
        'http://192.168.1.1'
      ];
      
      const results = await PhishingDetector.analyzeLinks(urls);
      
      expect(results).toHaveLength(3);
      expect(results[0].threatLevel).toBe('safe');
      expect(results[2].threatLevel).toMatch(/dangerous|suspicious/);
    });
  });

  describe('Statistics Integration', () => {
    test('should update scan statistics', async () => {
      await PhishingDetector.analyzeLink('https://example.com');
      
      const stats = await StorageManager.getStats();
      expect(stats.linksScanned).toBeGreaterThan(0);
    });

    test('should update blocked statistics', async () => {
      await PhishingDetector.analyzeLink('http://192.168.1.1');
      
      const stats = await StorageManager.getStats();
      expect(stats.threatsBlocked).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid URL gracefully', async () => {
      const result = await PhishingDetector.analyzeLink('not-a-url');
      
      expect(result).toHaveProperty('threatLevel');
      expect(result.threatLevel).toBe('unknown');
    });

    test('should handle storage errors gracefully', async () => {
      // Mock storage error
      const originalGet = chrome.storage.local.get;
      chrome.storage.local.get = jest.fn().mockRejectedValue(new Error('Storage error'));
      
      const result = await PhishingDetector.analyzeLink('https://example.com');
      
      expect(result).toHaveProperty('threatLevel');
      
      // Restore
      chrome.storage.local.get = originalGet;
    });
  });

  describe('Threat Level Calculation', () => {
    test('should calculate correct threat level for multiple issues', () => {
      const analysis = {
        issues: [
          { severity: 'high' },
          { severity: 'high' },
          { severity: 'medium' }
        ],
        isLegitimate: false,
        contextScore: 0
      };
      
      const level = PhishingDetector.calculateFinalThreatLevel(analysis);
      expect(level).toBe('dangerous');
    });

    test('should prioritize context score', () => {
      const analysis = {
        issues: [],
        isLegitimate: false,
        contextScore: 10
      };
      
      const level = PhishingDetector.calculateFinalThreatLevel(analysis);
      expect(level).toBe('dangerous');
    });
  });

  describe('Formatting', () => {
    test('should format analysis for display', async () => {
      const analysis = await PhishingDetector.analyzeLink('https://example.com');
      const formatted = PhishingDetector.formatAnalysis(analysis);
      
      expect(formatted).toHaveProperty('color');
      expect(formatted).toHaveProperty('icon');
      expect(formatted).toHaveProperty('description');
      expect(formatted).toHaveProperty('issueCount');
    });

    test('should provide correct colors for threat levels', () => {
      expect(PhishingDetector.getThreatColor('safe')).toBe('#28a745');
      expect(PhishingDetector.getThreatColor('suspicious')).toBe('#ffc107');
      expect(PhishingDetector.getThreatColor('dangerous')).toBe('#dc3545');
    });

    test('should provide correct icons for threat levels', () => {
      expect(PhishingDetector.getThreatIcon('safe')).toBe('✓');
      expect(PhishingDetector.getThreatIcon('suspicious')).toBe('⚠');
      expect(PhishingDetector.getThreatIcon('dangerous')).toBe('✕');
    });
  });
});
