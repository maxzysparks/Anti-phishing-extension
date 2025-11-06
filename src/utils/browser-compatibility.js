/**
 * Browser Compatibility Checker
 * Detects browser capabilities and provides fallbacks
 */

export class BrowserCompatibility {
  static browserInfo = null;

  /**
   * Detect current browser
   */
  static detectBrowser() {
    if (this.browserInfo) {
      return this.browserInfo;
    }

    const userAgent = navigator.userAgent;
    let browserName = 'Unknown';
    let browserVersion = 'Unknown';
    let isChrome = false;
    let isEdge = false;
    let isFirefox = false;
    let isSafari = false;
    let isBrave = false;

    // Detect Brave
    if (navigator.brave && navigator.brave.isBrave) {
      browserName = 'Brave';
      isBrave = true;
      isChrome = true; // Brave is Chromium-based
    }
    // Detect Edge
    else if (userAgent.indexOf('Edg/') > -1) {
      browserName = 'Edge';
      browserVersion = userAgent.match(/Edg\/(\d+)/)?.[1] || 'Unknown';
      isEdge = true;
      isChrome = true; // Edge is Chromium-based
    }
    // Detect Chrome
    else if (userAgent.indexOf('Chrome') > -1 && userAgent.indexOf('Edg') === -1) {
      browserName = 'Chrome';
      browserVersion = userAgent.match(/Chrome\/(\d+)/)?.[1] || 'Unknown';
      isChrome = true;
    }
    // Detect Firefox
    else if (userAgent.indexOf('Firefox') > -1) {
      browserName = 'Firefox';
      browserVersion = userAgent.match(/Firefox\/(\d+)/)?.[1] || 'Unknown';
      isFirefox = true;
    }
    // Detect Safari
    else if (userAgent.indexOf('Safari') > -1 && userAgent.indexOf('Chrome') === -1) {
      browserName = 'Safari';
      browserVersion = userAgent.match(/Version\/(\d+)/)?.[1] || 'Unknown';
      isSafari = true;
    }

    this.browserInfo = {
      name: browserName,
      version: browserVersion,
      isChrome,
      isEdge,
      isFirefox,
      isSafari,
      isBrave,
      userAgent
    };

    return this.browserInfo;
  }

  /**
   * Check if browser supports required features
   */
  static checkCompatibility() {
    const browser = this.detectBrowser();
    const issues = [];
    const warnings = [];

    // Check Manifest V3 support
    if (!chrome.runtime || !chrome.runtime.getManifest) {
      issues.push({
        feature: 'Chrome Extension APIs',
        severity: 'critical',
        message: 'Browser does not support Chrome Extension APIs'
      });
    }

    // Check Storage API
    if (!chrome.storage || !chrome.storage.local) {
      issues.push({
        feature: 'Storage API',
        severity: 'critical',
        message: 'Browser does not support chrome.storage API'
      });
    }

    // Check Notifications API
    if (!chrome.notifications) {
      warnings.push({
        feature: 'Notifications API',
        severity: 'medium',
        message: 'Browser does not support chrome.notifications API'
      });
    }

    // Check Alarms API
    if (!chrome.alarms) {
      warnings.push({
        feature: 'Alarms API',
        severity: 'medium',
        message: 'Browser does not support chrome.alarms API'
      });
    }

    // Check Web Workers
    if (typeof Worker === 'undefined') {
      warnings.push({
        feature: 'Web Workers',
        severity: 'medium',
        message: 'Browser does not support Web Workers'
      });
    }

    // Check Fetch API
    if (typeof fetch === 'undefined') {
      issues.push({
        feature: 'Fetch API',
        severity: 'high',
        message: 'Browser does not support Fetch API'
      });
    }

    // Check Promise support
    if (typeof Promise === 'undefined') {
      issues.push({
        feature: 'Promises',
        severity: 'critical',
        message: 'Browser does not support Promises'
      });
    }

    // Check async/await support
    try {
      eval('(async () => {})');
    } catch (e) {
      issues.push({
        feature: 'Async/Await',
        severity: 'critical',
        message: 'Browser does not support async/await'
      });
    }

    // Check MutationObserver
    if (typeof MutationObserver === 'undefined') {
      issues.push({
        feature: 'MutationObserver',
        severity: 'high',
        message: 'Browser does not support MutationObserver'
      });
    }

    // Check localStorage
    try {
      localStorage.setItem('test', 'test');
      localStorage.removeItem('test');
    } catch (e) {
      warnings.push({
        feature: 'localStorage',
        severity: 'low',
        message: 'localStorage is not available or disabled'
      });
    }

    // Browser-specific checks
    if (browser.isFirefox) {
      // Firefox uses 'browser' namespace
      if (typeof browser === 'undefined') {
        warnings.push({
          feature: 'Firefox WebExtensions API',
          severity: 'medium',
          message: 'Firefox browser API not detected'
        });
      }
    }

    return {
      compatible: issues.length === 0,
      browser,
      issues,
      warnings,
      summary: this.generateSummary(issues, warnings)
    };
  }

  /**
   * Generate compatibility summary
   */
  static generateSummary(issues, warnings) {
    if (issues.length === 0 && warnings.length === 0) {
      return 'Fully compatible';
    }

    if (issues.length > 0) {
      return `Incompatible: ${issues.length} critical issue(s)`;
    }

    return `Compatible with ${warnings.length} warning(s)`;
  }

  /**
   * Get recommended actions
   */
  static getRecommendations() {
    const compat = this.checkCompatibility();
    const recommendations = [];

    if (!compat.compatible) {
      recommendations.push({
        priority: 'high',
        action: 'Update Browser',
        message: 'Please update to the latest version of Chrome, Edge, or Firefox'
      });
    }

    if (compat.browser.isFirefox) {
      recommendations.push({
        priority: 'medium',
        action: 'Firefox Compatibility',
        message: 'Some features may work differently in Firefox. Please report any issues.'
      });
    }

    if (compat.browser.isSafari) {
      recommendations.push({
        priority: 'high',
        action: 'Safari Limitations',
        message: 'Safari has limited extension support. Consider using Chrome or Firefox for best experience.'
      });
    }

    if (compat.warnings.length > 0) {
      recommendations.push({
        priority: 'low',
        action: 'Enable Features',
        message: 'Some optional features are not available. Extension will work with reduced functionality.'
      });
    }

    return recommendations;
  }

  /**
   * Check minimum browser version
   */
  static checkMinimumVersion() {
    const browser = this.detectBrowser();
    const minVersions = {
      Chrome: 88,
      Edge: 88,
      Firefox: 89,
      Brave: 88
    };

    const minVersion = minVersions[browser.name];
    if (!minVersion) {
      return {
        supported: false,
        message: `${browser.name} is not officially supported`
      };
    }

    const currentVersion = parseInt(browser.version);
    if (isNaN(currentVersion)) {
      return {
        supported: true,
        message: 'Could not determine browser version'
      };
    }

    if (currentVersion < minVersion) {
      return {
        supported: false,
        message: `${browser.name} ${currentVersion} is below minimum version ${minVersion}`
      };
    }

    return {
      supported: true,
      message: `${browser.name} ${currentVersion} is supported`
    };
  }

  /**
   * Get polyfills needed
   */
  static getRequiredPolyfills() {
    const polyfills = [];

    if (typeof Promise === 'undefined') {
      polyfills.push('Promise');
    }

    if (typeof fetch === 'undefined') {
      polyfills.push('fetch');
    }

    if (typeof Object.assign === 'undefined') {
      polyfills.push('Object.assign');
    }

    if (typeof Array.prototype.includes === 'undefined') {
      polyfills.push('Array.prototype.includes');
    }

    return polyfills;
  }

  /**
   * Generate compatibility report
   */
  static generateReport() {
    const compat = this.checkCompatibility();
    const versionCheck = this.checkMinimumVersion();
    const polyfills = this.getRequiredPolyfills();
    const recommendations = this.getRecommendations();

    return {
      timestamp: new Date().toISOString(),
      browser: compat.browser,
      compatible: compat.compatible && versionCheck.supported,
      versionCheck,
      issues: compat.issues,
      warnings: compat.warnings,
      polyfills,
      recommendations,
      summary: compat.summary
    };
  }

  /**
   * Log compatibility report to console
   */
  static logReport() {
    const report = this.generateReport();

    console.group('🔍 Browser Compatibility Report');
    console.log('Browser:', `${report.browser.name} ${report.browser.version}`);
    console.log('Compatible:', report.compatible ? '✅ Yes' : '❌ No');
    console.log('Version Check:', report.versionCheck.message);

    if (report.issues.length > 0) {
      console.group('❌ Critical Issues');
      report.issues.forEach(issue => {
        console.error(`${issue.feature}: ${issue.message}`);
      });
      console.groupEnd();
    }

    if (report.warnings.length > 0) {
      console.group('⚠️ Warnings');
      report.warnings.forEach(warning => {
        console.warn(`${warning.feature}: ${warning.message}`);
      });
      console.groupEnd();
    }

    if (report.polyfills.length > 0) {
      console.log('Required Polyfills:', report.polyfills.join(', '));
    }

    if (report.recommendations.length > 0) {
      console.group('💡 Recommendations');
      report.recommendations.forEach(rec => {
        console.log(`[${rec.priority}] ${rec.action}: ${rec.message}`);
      });
      console.groupEnd();
    }

    console.groupEnd();

    return report;
  }
}

// Auto-check on load
if (typeof window !== 'undefined') {
  window.addEventListener('load', () => {
    BrowserCompatibility.logReport();
  });
}
