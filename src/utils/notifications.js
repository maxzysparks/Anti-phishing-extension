/**
 * Notification Manager for Anti-Phishing Extension
 * Handles browser notifications for threat alerts
 */

export class NotificationManager {
  /**
   * Show a threat blocked notification
   */
  static async showThreatBlocked(url, threatLevel, issueCount) {
    const domain = new URL(url).hostname;
    
    let title, message, iconUrl;
    
    switch (threatLevel) {
      case 'dangerous':
        title = '🛡️ DANGEROUS THREAT BLOCKED!';
        message = `Blocked phishing attempt from ${domain}\n${issueCount} security issues detected.`;
        iconUrl = '/icons/icon48.png';
        break;
      
      case 'suspicious':
        title = '⚠️ Suspicious Link Detected';
        message = `Warning: ${domain} shows ${issueCount} suspicious indicators.`;
        iconUrl = '/icons/icon48.png';
        break;
      
      default:
        return; // Don't notify for safe/unknown
    }
    
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: iconUrl,
        title: title,
        message: message,
        priority: threatLevel === 'dangerous' ? 2 : 1,
        requireInteraction: threatLevel === 'dangerous'
      });
    } catch (error) {
      console.error('Failed to show notification:', error);
    }
  }

  /**
   * Show user report submitted notification
   */
  static async showReportSubmitted(reportType) {
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: '/icons/icon48.png',
        title: '✅ Report Submitted',
        message: `Thank you! Your ${reportType} report has been recorded.`,
        priority: 0
      });
    } catch (error) {
      console.error('Failed to show notification:', error);
    }
  }

  /**
   * Show daily/weekly protection summary
   */
  static async showProtectionSummary(stats) {
    const { linksScanned, threatsBlocked } = stats;
    
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: '/icons/icon48.png',
        title: '🛡️ Protection Summary',
        message: `This week: ${linksScanned} links scanned, ${threatsBlocked} threats blocked!`,
        priority: 0
      });
    } catch (error) {
      console.error('Failed to show notification:', error);
    }
  }

  /**
   * Show whitelist verification failure
   */
  static async showWhitelistWarning(domain) {
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: '/icons/icon48.png',
        title: '⚠️ Whitelisted Domain Compromised',
        message: `Warning: ${domain} was removed from whitelist due to security concerns.`,
        priority: 2,
        requireInteraction: true
      });
    } catch (error) {
      console.error('Failed to show notification:', error);
    }
  }
}
