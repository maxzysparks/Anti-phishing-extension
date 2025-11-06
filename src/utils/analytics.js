/**
 * Analytics Dashboard
 * Track and visualize security metrics
 */

import { StorageManager } from './storage.js';

export class AnalyticsManager {
  /**
   * Get comprehensive analytics data
   */
  static async getAnalytics() {
    try {
      const stats = await StorageManager.getStats();
      const whitelist = await StorageManager.getWhitelist();
      const blacklist = await StorageManager.getBlacklist();
      
      // Get threat breakdown
      const threatBreakdown = await this.getThreatBreakdown();
      
      // Calculate protection rate
      const protectionRate = stats.linksScanned > 0 
        ? ((stats.threatsBlocked / stats.linksScanned) * 100).toFixed(2)
        : 0;
      
      // Get daily/weekly stats
      const dailyStats = await this.getDailyStats();
      const weeklyStats = await this.getWeeklyStats();
      
      return {
        overview: {
          linksScanned: stats.linksScanned || 0,
          threatsBlocked: stats.threatsBlocked || 0,
          protectionRate: protectionRate,
          whitelistCount: whitelist.length,
          blacklistCount: blacklist.length,
          lastScan: stats.lastScan || null
        },
        threatBreakdown: threatBreakdown,
        daily: dailyStats,
        weekly: weeklyStats,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error getting analytics:', error);
      return null;
    }
  }

  /**
   * Get threat breakdown by type
   */
  static async getThreatBreakdown() {
    try {
      const result = await chrome.storage.local.get('threatBreakdown');
      return result.threatBreakdown || {
        dangerous: 0,
        suspicious: 0,
        safe: 0,
        unknown: 0,
        byType: {
          phishing: 0,
          typosquatting: 0,
          homograph: 0,
          spam: 0,
          malicious_scheme: 0,
          ip_address: 0,
          suspicious_tld: 0,
          url_shortener: 0
        }
      };
    } catch (error) {
      console.error('Error getting threat breakdown:', error);
      return null;
    }
  }

  /**
   * Record a threat detection
   */
  static async recordThreat(threatLevel, issueTypes) {
    try {
      const breakdown = await this.getThreatBreakdown();
      
      // Increment threat level counter
      if (threatLevel === 'dangerous') {
        breakdown.dangerous++;
      } else if (threatLevel === 'suspicious') {
        breakdown.suspicious++;
      } else if (threatLevel === 'safe') {
        breakdown.safe++;
      } else {
        breakdown.unknown++;
      }
      
      // Increment by issue type
      issueTypes.forEach(type => {
        if (type.includes('typosquatting')) {
          breakdown.byType.typosquatting++;
        } else if (type.includes('homograph')) {
          breakdown.byType.homograph++;
        } else if (type.includes('spam') || type.includes('suspicious_context')) {
          breakdown.byType.spam++;
        } else if (type.includes('dangerous_scheme')) {
          breakdown.byType.malicious_scheme++;
        } else if (type.includes('ip_address')) {
          breakdown.byType.ip_address++;
        } else if (type.includes('suspicious_tld')) {
          breakdown.byType.suspicious_tld++;
        } else if (type.includes('url_shortener')) {
          breakdown.byType.url_shortener++;
        } else {
          breakdown.byType.phishing++;
        }
      });
      
      await chrome.storage.local.set({ threatBreakdown: breakdown });
      
      // Also record in daily stats
      await this.recordDailyActivity(threatLevel);
      
      return breakdown;
    } catch (error) {
      console.error('Error recording threat:', error);
      return null;
    }
  }

  /**
   * Get daily statistics (last 30 days)
   */
  static async getDailyStats() {
    try {
      const result = await chrome.storage.local.get('dailyStats');
      return result.dailyStats || [];
    } catch (error) {
      console.error('Error getting daily stats:', error);
      return [];
    }
  }

  /**
   * Record daily activity
   */
  static async recordDailyActivity(threatLevel) {
    try {
      const stats = await this.getDailyStats();
      const today = new Date().toDateString();
      
      // Find or create today's entry
      let todayStats = stats.find(s => s.date === today);
      
      if (!todayStats) {
        todayStats = {
          date: today,
          scanned: 0,
          blocked: 0,
          dangerous: 0,
          suspicious: 0
        };
        stats.push(todayStats);
      }
      
      // Update counts
      todayStats.scanned++;
      
      if (threatLevel === 'dangerous') {
        todayStats.blocked++;
        todayStats.dangerous++;
      } else if (threatLevel === 'suspicious') {
        todayStats.suspicious++;
      }
      
      // Keep only last 30 days
      if (stats.length > 30) {
        stats.shift();
      }
      
      await chrome.storage.local.set({ dailyStats: stats });
      
      return stats;
    } catch (error) {
      console.error('Error recording daily activity:', error);
      return null;
    }
  }

  /**
   * Get weekly summary
   */
  static async getWeeklyStats() {
    try {
      const dailyStats = await this.getDailyStats();
      
      // Get last 7 days
      const last7Days = dailyStats.slice(-7);
      
      const weeklyTotal = {
        scanned: 0,
        blocked: 0,
        dangerous: 0,
        suspicious: 0
      };
      
      last7Days.forEach(day => {
        weeklyTotal.scanned += day.scanned || 0;
        weeklyTotal.blocked += day.blocked || 0;
        weeklyTotal.dangerous += day.dangerous || 0;
        weeklyTotal.suspicious += day.suspicious || 0;
      });
      
      return weeklyTotal;
    } catch (error) {
      console.error('Error getting weekly stats:', error);
      return {
        scanned: 0,
        blocked: 0,
        dangerous: 0,
        suspicious: 0
      };
    }
  }

  /**
   * Export analytics data
   */
  static async exportAnalytics() {
    try {
      const analytics = await this.getAnalytics();
      
      const exportData = {
        exportDate: new Date().toISOString(),
        version: '1.0.0',
        analytics: analytics
      };
      
      const jsonData = JSON.stringify(exportData, null, 2);
      const blob = new Blob([jsonData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `apg-analytics-${Date.now()}.json`;
      
      return { success: true, url, filename };
    } catch (error) {
      console.error('Error exporting analytics:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Reset all analytics
   */
  static async resetAnalytics() {
    try {
      await chrome.storage.local.remove(['threatBreakdown', 'dailyStats']);
      await StorageManager.resetStats();
      
      return { success: true, message: 'Analytics reset successfully.' };
    } catch (error) {
      console.error('Error resetting analytics:', error);
      return { success: false, error: error.message };
    }
  }
}
