/**
 * Data Export/Import Manager
 * Backup and restore extension settings, whitelist, blacklist
 */

import { StorageManager } from './storage.js';
import { AnalyticsManager } from './analytics.js';
import { ReportingManager } from './reporting.js';

export class DataExportManager {
  /**
   * Export all extension data
   */
  static async exportAll() {
    try {
      const settings = await StorageManager.getSettings();
      const whitelist = await StorageManager.getWhitelist();
      const blacklist = await StorageManager.getBlacklist();
      const stats = await StorageManager.getStats();
      const analytics = await AnalyticsManager.getAnalytics();
      const reports = await ReportingManager.getAllReports();
      
      const exportData = {
        version: '1.0.0',
        exportDate: new Date().toISOString(),
        data: {
          settings,
          whitelist,
          blacklist,
          stats,
          analytics,
          reports
        }
      };
      
      return { success: true, data: exportData };
    } catch (error) {
      console.error('Error exporting all data:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Export settings only
   */
  static async exportSettings() {
    try {
      const settings = await StorageManager.getSettings();
      const whitelist = await StorageManager.getWhitelist();
      const blacklist = await StorageManager.getBlacklist();
      
      const exportData = {
        version: '1.0.0',
        exportDate: new Date().toISOString(),
        type: 'settings',
        data: {
          settings,
          whitelist,
          blacklist
        }
      };
      
      return { success: true, data: exportData };
    } catch (error) {
      console.error('Error exporting settings:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Import extension data
   */
  static async importData(importData) {
    try {
      // Validate import data
      if (!importData || !importData.version || !importData.data) {
        return { success: false, error: 'Invalid import data format' };
      }
      
      const { data } = importData;
      
      // Import settings
      if (data.settings) {
        await StorageManager.saveSettings(data.settings);
      }
      
      // Import whitelist
      if (data.whitelist && Array.isArray(data.whitelist)) {
        for (const domain of data.whitelist) {
          await StorageManager.addToWhitelist(domain);
        }
      }
      
      // Import blacklist
      if (data.blacklist && Array.isArray(data.blacklist)) {
        for (const domain of data.blacklist) {
          await StorageManager.addToBlacklist(domain);
        }
      }
      
      // Clear cache to force re-analysis with new settings
      await StorageManager.clearCache();
      
      return { 
        success: true, 
        message: 'Data imported successfully',
        imported: {
          settings: !!data.settings,
          whitelist: data.whitelist?.length || 0,
          blacklist: data.blacklist?.length || 0
        }
      };
    } catch (error) {
      console.error('Error importing data:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Download export data as JSON file
   */
  static async downloadExport(exportType = 'all') {
    try {
      let result;
      
      if (exportType === 'settings') {
        result = await this.exportSettings();
      } else if (exportType === 'analytics') {
        result = await AnalyticsManager.exportAnalytics();
        if (result.success) {
          return result;
        }
      } else if (exportType === 'reports') {
        result = await ReportingManager.exportReports();
        if (result.success) {
          return result;
        }
      } else {
        result = await this.exportAll();
      }
      
      if (!result.success) {
        return result;
      }
      
      // Create JSON file
      const jsonData = JSON.stringify(result.data, null, 2);
      const blob = new Blob([jsonData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `apg-export-${exportType}-${Date.now()}.json`;
      
      return { success: true, url, filename };
    } catch (error) {
      console.error('Error downloading export:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Read import file
   */
  static async readImportFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        try {
          const data = JSON.parse(e.target.result);
          resolve({ success: true, data });
        } catch (error) {
          reject({ success: false, error: 'Invalid JSON file' });
        }
      };
      
      reader.onerror = () => {
        reject({ success: false, error: 'Failed to read file' });
      };
      
      reader.readAsText(file);
    });
  }

  /**
   * Backup data to cloud (Chrome Sync Storage)
   */
  static async backupToCloud() {
    try {
      const exportResult = await this.exportSettings();
      
      if (!exportResult.success) {
        return exportResult;
      }
      
      // Store in sync storage (limited to 100KB)
      const backupData = {
        timestamp: Date.now(),
        data: exportResult.data
      };
      
      await chrome.storage.sync.set({ cloudBackup: backupData });
      
      return { success: true, message: 'Backup saved to Chrome Sync' };
    } catch (error) {
      console.error('Error backing up to cloud:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Restore data from cloud
   */
  static async restoreFromCloud() {
    try {
      const result = await chrome.storage.sync.get('cloudBackup');
      
      if (!result.cloudBackup) {
        return { success: false, error: 'No cloud backup found' };
      }
      
      const importResult = await this.importData(result.cloudBackup.data);
      
      if (importResult.success) {
        return {
          success: true,
          message: 'Data restored from cloud backup',
          backupDate: new Date(result.cloudBackup.timestamp).toLocaleString(),
          ...importResult
        };
      }
      
      return importResult;
    } catch (error) {
      console.error('Error restoring from cloud:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Clear all data (factory reset)
   */
  static async factoryReset() {
    try {
      // Clear all storage
      await chrome.storage.local.clear();
      await chrome.storage.sync.clear();
      
      // Reinitialize with default settings
      await StorageManager.saveSettings({});
      
      return { success: true, message: 'Extension reset to factory defaults' };
    } catch (error) {
      console.error('Error performing factory reset:', error);
      return { success: false, error: error.message };
    }
  }
}
