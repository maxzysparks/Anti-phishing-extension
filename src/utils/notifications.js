/**
 * Notification Manager for Anti-Phishing Extension
 * Handles browser notifications for threat alerts
 */

export class NotificationManager {
  // Track recently shown notifications to prevent duplicates
  static recentNotifications = new Map();
  static NOTIFICATION_COOLDOWN = 600000; // 10 minutes in milliseconds (increased from 5)
  static activeNotifications = new Set(); // Track currently displayed notifications

  /**
   * Check if notification was recently shown for this domain
   */
  static wasRecentlyNotified(domain, threatLevel) {
    const key = `${domain}-${threatLevel}`;
    const lastShown = this.recentNotifications.get(key);
    
    if (lastShown) {
      const timeSince = Date.now() - lastShown;
      if (timeSince < this.NOTIFICATION_COOLDOWN) {
        console.log(`[Notifications] Skipping duplicate notification for ${domain} (shown ${Math.floor(timeSince / 1000)}s ago)`);
        return true;
      }
    }
    
    return false;
  }

  /**
   * Mark domain as notified
   */
  static markAsNotified(domain, threatLevel) {
    const key = `${domain}-${threatLevel}`;
    this.recentNotifications.set(key, Date.now());
    
    // Clean up old entries (older than cooldown period)
    for (const [k, timestamp] of this.recentNotifications.entries()) {
      if (Date.now() - timestamp > this.NOTIFICATION_COOLDOWN) {
        this.recentNotifications.delete(k);
      }
    }
  }

  /**
   * Show a threat blocked notification (with enhanced deduplication)
   */
  static async showThreatBlocked(url, threatLevel, issueCount) {
    const domain = new URL(url).hostname;
    
    // ENHANCED DEDUPLICATION: Check if we recently notified about this domain
    if (this.wasRecentlyNotified(domain, threatLevel)) {
      console.log(`[Notifications] Skipping duplicate notification for ${domain}`);
      return; // Skip duplicate notification
    }
    
    // RATE LIMITING: Check if we have too many active notifications
    if (this.activeNotifications.size >= 3) {
      console.log(`[Notifications] Rate limit: Too many active notifications, skipping ${domain}`);
      return; // Don't spam user with too many notifications at once
    }
    
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
      // Create notification with unique ID based on domain
      const notificationId = `threat-${domain}-${Date.now()}`;
      
      await chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: iconUrl,
        title: title,
        message: message,
        priority: threatLevel === 'dangerous' ? 2 : 1,
        requireInteraction: threatLevel === 'dangerous',
        silent: threatLevel === 'suspicious' // Don't make sound for suspicious (only dangerous)
      });
      
      // Track active notification
      this.activeNotifications.add(notificationId);
      
      // Mark as notified to prevent duplicates
      this.markAsNotified(domain, threatLevel);
      
      // Auto-clear notification after delay (except dangerous ones that require interaction)
      if (threatLevel !== 'dangerous') {
        setTimeout(() => {
          chrome.notifications.clear(notificationId);
          this.activeNotifications.delete(notificationId);
        }, 8000); // Clear after 8 seconds
      }
      
      // Listen for notification close to update active set
      chrome.notifications.onClosed.addListener((closedId) => {
        if (closedId === notificationId) {
          this.activeNotifications.delete(closedId);
        }
      });
      
      console.log(`[Notifications] Showed ${threatLevel} notification for ${domain}`);
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
