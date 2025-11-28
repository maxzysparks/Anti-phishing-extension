/**
 * Supabase Threat Intelligence Manager
 * Replaces PhishTank with Supabase backend
 */

import { supabase } from '../config/supabase.js';
import { ErrorHandler } from './error-handler.js';

export class SupabaseThreatIntelligence {
  static _cache = new Map();
  static _cacheExpiry = 3600000; // 1 hour cache
  static _lastSync = 0;
  
  /**
   * Initialize and test connection
   */
  static async initialize() {
    try {
      console.log('[Supabase TI] Initializing...');
      
      // Test connection
      const { data, error } = await supabase
        .from('phishing_urls')
        .select('count')
        .limit(1);
      
      if (error) {
        console.error('[Supabase TI] Connection failed:', error);
        return false;
      }
      
      console.log('[Supabase TI] Connected successfully!');
      
      // Load initial data
      await this.syncDatabase();
      
      return true;
    } catch (err) {
      console.error('[Supabase TI] Initialization error:', err);
      return false;
    }
  }
  
  /**
   * Sync database to local cache
   */
  static async syncDatabase() {
    try {
      console.log('[Supabase TI] Syncing database...');
      
      const { data, error } = await supabase
        .from('phishing_urls')
        .select('url, domain, threat_level, verified, confidence_score')
        .eq('verified', true)
        .gte('confidence_score', 0.7);
      
      if (error) {
        console.error('[Supabase TI] Sync error:', error);
        return false;
      }
      
      // Update cache
      this._cache.clear();
      data.forEach(entry => {
        this._cache.set(entry.url, {
          domain: entry.domain,
          threatLevel: entry.threat_level,
          verified: entry.verified,
          confidence: entry.confidence_score,
          timestamp: Date.now()
        });
      });
      
      this._lastSync = Date.now();
      
      console.log(`[Supabase TI] Synced ${data.length} verified threats`);
      
      // Store in chrome.storage for offline access
      await chrome.storage.local.set({
        supabaseCache: {
          data: Array.from(this._cache.entries()),
          lastSync: this._lastSync
        }
      });
      
      return true;
    } catch (err) {
      console.error('[Supabase TI] Sync error:', err);
      return false;
    }
  }
  
  /**
   * Check if URL is in phishing database
   */
  static async checkUrl(url) {
    try {
      // Normalize URL
      const normalizedUrl = url.toLowerCase().replace(/\/$/, '');
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      // Check cache first
      if (this._cache.has(normalizedUrl)) {
        const cached = this._cache.get(normalizedUrl);
        
        // Check if cache is still valid
        if (Date.now() - cached.timestamp < this._cacheExpiry) {
          console.log('[Supabase TI] Cache hit:', normalizedUrl);
          return {
            found: true,
            threatLevel: cached.threatLevel,
            verified: cached.verified,
            confidence: cached.confidence,
            source: 'cache'
          };
        }
      }
      
      // Query database
      const { data, error } = await supabase
        .from('phishing_urls')
        .select('url, domain, threat_level, verified, confidence_score')
        .or(`url.eq.${normalizedUrl},domain.eq.${domain}`)
        .limit(1)
        .single();
      
      if (error && error.code !== 'PGRST116') { // PGRST116 = no rows
        console.error('[Supabase TI] Query error:', error);
        return { found: false, error: error.message };
      }
      
      if (data) {
        // Update cache
        this._cache.set(normalizedUrl, {
          domain: data.domain,
          threatLevel: data.threat_level,
          verified: data.verified,
          confidence: data.confidence_score,
          timestamp: Date.now()
        });
        
        console.log('[Supabase TI] Threat found:', normalizedUrl);
        
        return {
          found: true,
          threatLevel: data.threat_level,
          verified: data.verified,
          confidence: data.confidence_score,
          source: 'supabase'
        };
      }
      
      // Check whitelist
      const whitelisted = await this.checkWhitelist(domain);
      if (whitelisted) {
        return {
          found: true,
          threatLevel: 'safe',
          verified: true,
          confidence: 1.0,
          source: 'whitelist'
        };
      }
      
      // Check blacklist
      const blacklisted = await this.checkBlacklist(domain);
      if (blacklisted) {
        return {
          found: true,
          threatLevel: 'dangerous',
          verified: true,
          confidence: 1.0,
          source: 'blacklist'
        };
      }
      
      return { found: false };
    } catch (err) {
      console.error('[Supabase TI] Check error:', err);
      return { found: false, error: err.message };
    }
  }
  
  /**
   * Report a phishing URL
   */
  static async reportUrl(url, domain, threatLevel, metadata = {}) {
    try {
      const { data, error } = await supabase
        .from('phishing_urls')
        .upsert({
          url: url,
          domain: domain,
          threat_level: threatLevel,
          verified: false,
          source: 'user_report',
          confidence_score: 0.5,
          metadata: metadata
        }, {
          onConflict: 'url'
        });
      
      if (error) {
        console.error('[Supabase TI] Report error:', error);
        return { success: false, error: error.message };
      }
      
      console.log('[Supabase TI] URL reported:', url);
      
      // Invalidate cache
      this._cache.delete(url);
      
      return { success: true };
    } catch (err) {
      console.error('[Supabase TI] Report error:', err);
      return { success: false, error: err.message };
    }
  }
  
  /**
   * Submit user feedback
   */
  static async submitFeedback(feedback) {
    try {
      const { data, error } = await supabase
        .from('user_feedback')
        .insert({
          url: feedback.url,
          domain: feedback.domain,
          detected_threat_level: feedback.detectedThreatLevel,
          feedback_type: feedback.feedbackType,
          user_comment: feedback.comment || null,
          metadata: {
            issues: feedback.issues,
            mlScore: feedback.mlScore,
            confidence: feedback.confidence
          }
        });
      
      if (error) {
        console.error('[Supabase TI] Feedback error:', error);
        return { success: false, error: error.message };
      }
      
      console.log('[Supabase TI] Feedback submitted');
      
      return { success: true };
    } catch (err) {
      console.error('[Supabase TI] Feedback error:', err);
      return { success: false, error: err.message };
    }
  }
  
  /**
   * Check whitelist
   */
  static async checkWhitelist(domain) {
    try {
      const { data, error } = await supabase
        .from('whitelist')
        .select('domain')
        .eq('domain', domain)
        .single();
      
      return !error && data !== null;
    } catch (err) {
      return false;
    }
  }
  
  /**
   * Check blacklist
   */
  static async checkBlacklist(domain) {
    try {
      const { data, error } = await supabase
        .from('blacklist')
        .select('domain')
        .eq('domain', domain)
        .single();
      
      return !error && data !== null;
    } catch (err) {
      return false;
    }
  }
  
  /**
   * Add to whitelist
   */
  static async addToWhitelist(domain, reason = '') {
    try {
      const { data, error } = await supabase
        .from('whitelist')
        .insert({
          domain: domain,
          added_by: 'user',
          reason: reason
        });
      
      if (error) {
        console.error('[Supabase TI] Whitelist error:', error);
        return { success: false, error: error.message };
      }
      
      console.log('[Supabase TI] Added to whitelist:', domain);
      return { success: true };
    } catch (err) {
      console.error('[Supabase TI] Whitelist error:', err);
      return { success: false, error: err.message };
    }
  }
  
  /**
   * Add to blacklist
   */
  static async addToBlacklist(domain, reason = '') {
    try {
      const { data, error } = await supabase
        .from('blacklist')
        .insert({
          domain: domain,
          added_by: 'user',
          reason: reason,
          threat_level: 'dangerous'
        });
      
      if (error) {
        console.error('[Supabase TI] Blacklist error:', error);
        return { success: false, error: error.message };
      }
      
      console.log('[Supabase TI] Added to blacklist:', domain);
      return { success: true };
    } catch (err) {
      console.error('[Supabase TI] Blacklist error:', err);
      return { success: false, error: err.message };
    }
  }
  
  /**
   * Get database statistics
   */
  static async getStats() {
    try {
      const { count, error } = await supabase
        .from('phishing_urls')
        .select('*', { count: 'exact', head: true });
      
      if (error) {
        console.error('[Supabase TI] Stats error:', error);
        return { count: 0, lastSync: this._lastSync };
      }
      
      return {
        count: count || 0,
        lastSync: this._lastSync,
        cacheSize: this._cache.size
      };
    } catch (err) {
      console.error('[Supabase TI] Stats error:', err);
      return { count: 0, lastSync: this._lastSync };
    }
  }
  
  /**
   * Schedule automatic syncs
   */
  static scheduleAutoSync() {
    // Sync every 30 minutes
    setInterval(() => {
      console.log('[Supabase TI] Auto-sync triggered');
      this.syncDatabase();
    }, 1800000); // 30 minutes
    
    console.log('[Supabase TI] Auto-sync scheduled (every 30 minutes)');
  }
}

export default SupabaseThreatIntelligence;
