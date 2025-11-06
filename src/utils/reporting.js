/**
 * User Reporting System
 * Allows users to report false positives/negatives and contribute to threat intelligence
 */

import { StorageManager } from './storage.js';
import { NotificationManager } from './notifications.js';

export class ReportingManager {
  /**
   * Report a false positive (safe link marked as dangerous)
   */
  static async reportFalsePositive(url, domain, reason) {
    try {
      const report = {
        type: 'false_positive',
        url: url,
        domain: domain,
        reason: reason,
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      };
      
      // Store report locally
      await this.storeReport(report);
      
      // Automatically add to whitelist with warning
      await StorageManager.addToWhitelist(domain);
      
      // Show confirmation
      await NotificationManager.showReportSubmitted('false positive');
      
      return { success: true, message: 'Thank you! Domain added to whitelist.' };
    } catch (error) {
      console.error('Error reporting false positive:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Report a false negative (dangerous link marked as safe)
   */
  static async reportFalseNegative(url, domain, reason, evidence) {
    try {
      const report = {
        type: 'false_negative',
        url: url,
        domain: domain,
        reason: reason,
        evidence: evidence, // User can describe what made it suspicious
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      };
      
      // Store report locally
      await this.storeReport(report);
      
      // Automatically add to blacklist
      await StorageManager.addToBlacklist(domain);
      
      // Show confirmation
      await NotificationManager.showReportSubmitted('false negative');
      
      return { success: true, message: 'Thank you! Domain added to blacklist.' };
    } catch (error) {
      console.error('Error reporting false negative:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Report general feedback
   */
  static async reportFeedback(category, message, rating) {
    try {
      const report = {
        type: 'feedback',
        category: category, // 'bug', 'feature_request', 'improvement', 'other'
        message: message,
        rating: rating, // 1-5 stars
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      };
      
      // Store report locally
      await this.storeReport(report);
      
      // Show confirmation
      await NotificationManager.showReportSubmitted('feedback');
      
      return { success: true, message: 'Thank you for your feedback!' };
    } catch (error) {
      console.error('Error reporting feedback:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Store report in local storage
   */
  static async storeReport(report) {
    try {
      const result = await chrome.storage.local.get('userReports');
      const reports = result.userReports || [];
      
      // Add new report
      reports.push(report);
      
      // Keep only last 100 reports to save space
      if (reports.length > 100) {
        reports.splice(0, reports.length - 100);
      }
      
      await chrome.storage.local.set({ userReports: reports });
      
      // Update report stats
      await this.updateReportStats(report.type);
      
      return true;
    } catch (error) {
      console.error('Error storing report:', error);
      return false;
    }
  }

  /**
   * Get all user reports
   */
  static async getAllReports() {
    try {
      const result = await chrome.storage.local.get('userReports');
      return result.userReports || [];
    } catch (error) {
      console.error('Error getting reports:', error);
      return [];
    }
  }

  /**
   * Get report statistics
   */
  static async getReportStats() {
    try {
      const result = await chrome.storage.local.get('reportStats');
      return result.reportStats || {
        falsePositives: 0,
        falseNegatives: 0,
        feedback: 0,
        totalReports: 0
      };
    } catch (error) {
      console.error('Error getting report stats:', error);
      return {
        falsePositives: 0,
        falseNegatives: 0,
        feedback: 0,
        totalReports: 0
      };
    }
  }

  /**
   * Update report statistics
   */
  static async updateReportStats(reportType) {
    try {
      const stats = await this.getReportStats();
      
      stats.totalReports++;
      
      if (reportType === 'false_positive') {
        stats.falsePositives++;
      } else if (reportType === 'false_negative') {
        stats.falseNegatives++;
      } else if (reportType === 'feedback') {
        stats.feedback++;
      }
      
      await chrome.storage.local.set({ reportStats: stats });
      
      return stats;
    } catch (error) {
      console.error('Error updating report stats:', error);
      return null;
    }
  }

  /**
   * Export reports for external analysis
   */
  static async exportReports() {
    try {
      const reports = await this.getAllReports();
      const stats = await this.getReportStats();
      
      const exportData = {
        exportDate: new Date().toISOString(),
        version: '1.0.0',
        stats: stats,
        reports: reports
      };
      
      // Convert to JSON
      const jsonData = JSON.stringify(exportData, null, 2);
      
      // Create blob and download link
      const blob = new Blob([jsonData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `apg-reports-${Date.now()}.json`;
      
      return { success: true, url, filename };
    } catch (error) {
      console.error('Error exporting reports:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Clear all reports (for privacy)
   */
  static async clearReports() {
    try {
      await chrome.storage.local.remove(['userReports', 'reportStats']);
      return { success: true, message: 'All reports cleared successfully.' };
    } catch (error) {
      console.error('Error clearing reports:', error);
      return { success: false, error: error.message };
    }
  }
}
