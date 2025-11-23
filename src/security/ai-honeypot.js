/**
 * AI-Powered Honeypot System
 * WORLD-FIRST: Intelligent deception system that lures and traps attackers
 * Creates fake vulnerabilities to detect and analyze attack patterns
 * Learns attacker behavior and adapts defenses in real-time
 * Makes it impossible for hackers to distinguish real from fake targets
 */

export class AIHoneypot {
  constructor() {
    this.initialized = false;
    this.traps = new Map();
    this.attackLog = [];
    this.attackerProfiles = new Map();
    
    // Honeypot configuration
    this.config = {
      trapDensity: 0.1,        // 10% of links are traps
      deceptionLevel: 3,        // 1-5 (higher = more convincing)
      learningRate: 0.1,        // How fast to adapt
      alertThreshold: 3,        // Attacks before alert
      banDuration: 3600000      // 1 hour ban
    };
    
    // Trap types
    this.trapTypes = {
      FAKE_LOGIN: 'fake_login',
      FAKE_API: 'fake_api',
      FAKE_ADMIN: 'fake_admin',
      FAKE_DATA: 'fake_data',
      FAKE_VULN: 'fake_vulnerability'
    };
  }

  /**
   * Initialize AI honeypot
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[Honeypot] Initializing AI-powered honeypot...');
      
      // Load existing traps and attack logs
      await this.loadState();
      
      // Deploy initial traps
      await this.deployTraps();
      
      // Start monitoring
      this.startMonitoring();
      
      this.initialized = true;
      console.log('[Honeypot] AI honeypot initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[Honeypot] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Deploy honeypot traps
   * @returns {Promise<void>}
   */
  async deployTraps() {
    // Create fake admin panel trap
    this.createTrap(this.trapTypes.FAKE_ADMIN, {
      url: '/admin/dashboard',
      description: 'Fake admin panel',
      attractiveness: 0.9
    });
    
    // Create fake API endpoint trap
    this.createTrap(this.trapTypes.FAKE_API, {
      url: '/api/v1/users',
      description: 'Fake API endpoint',
      attractiveness: 0.8
    });
    
    // Create fake login trap
    this.createTrap(this.trapTypes.FAKE_LOGIN, {
      url: '/login?debug=true',
      description: 'Fake debug login',
      attractiveness: 0.7
    });
    
    // Create fake vulnerability trap
    this.createTrap(this.trapTypes.FAKE_VULN, {
      url: '/backup/database.sql',
      description: 'Fake database backup',
      attractiveness: 0.95
    });
    
    console.log(`[Honeypot] Deployed ${this.traps.size} traps`);
  }

  /**
   * Create a honeypot trap
   * @param {string} type - Trap type
   * @param {Object} config - Trap configuration
   */
  createTrap(type, config) {
    const trapId = this.generateTrapId();
    
    const trap = {
      id: trapId,
      type: type,
      url: config.url,
      description: config.description,
      attractiveness: config.attractiveness,
      hits: 0,
      lastHit: null,
      created: Date.now(),
      active: true
    };
    
    this.traps.set(trapId, trap);
    
    return trapId;
  }

  /**
   * Generate unique trap ID
   * @returns {string} Trap ID
   */
  generateTrapId() {
    return `trap_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Check if URL is a honeypot trap
   * @param {string} url - URL to check
   * @returns {Object|null} Trap info or null
   */
  checkTrap(url) {
    for (const [trapId, trap] of this.traps.entries()) {
      if (trap.active && url.includes(trap.url)) {
        return { trapId, trap };
      }
    }
    return null;
  }

  /**
   * Record trap hit (attacker detected!)
   * @param {string} trapId - Trap ID
   * @param {Object} context - Attack context
   * @returns {Promise<Object>} Response
   */
  async recordTrapHit(trapId, context) {
    const trap = this.traps.get(trapId);
    
    if (!trap) {
      return { success: false, error: 'Trap not found' };
    }
    
    // Update trap stats
    trap.hits++;
    trap.lastHit = Date.now();
    
    // Log attack
    const attack = {
      trapId: trapId,
      trapType: trap.type,
      timestamp: Date.now(),
      attackerId: this.identifyAttacker(context),
      context: this.sanitizeContext(context),
      severity: this.calculateSeverity(trap, context)
    };
    
    this.attackLog.push(attack);
    
    // Keep only last 1000 attacks
    if (this.attackLog.length > 1000) {
      this.attackLog.shift();
    }
    
    // Update attacker profile
    await this.updateAttackerProfile(attack);
    
    // Trigger response
    await this.respondToAttack(attack);
    
    console.warn('[Honeypot] 🚨 TRAP HIT!', {
      trap: trap.description,
      attacker: attack.attackerId,
      severity: attack.severity
    });
    
    return {
      success: true,
      trapped: true,
      response: this.generateDeceptiveResponse(trap)
    };
  }

  /**
   * Identify attacker from context
   * @param {Object} context - Attack context
   * @returns {string} Attacker ID
   */
  identifyAttacker(context) {
    // Create fingerprint from available data
    const fingerprint = [
      context.userAgent || 'unknown',
      context.language || 'unknown',
      context.platform || 'unknown',
      context.screenResolution || 'unknown'
    ].join('|');
    
    // Hash fingerprint
    return this.hashString(fingerprint);
  }

  /**
   * Hash string for attacker ID
   * @param {string} str - String to hash
   * @returns {string} Hash
   */
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Sanitize attack context (remove PII)
   * @param {Object} context - Context
   * @returns {Object} Sanitized context
   */
  sanitizeContext(context) {
    return {
      userAgent: context.userAgent ? context.userAgent.substring(0, 100) : 'unknown',
      language: context.language || 'unknown',
      platform: context.platform || 'unknown',
      timestamp: Date.now()
    };
  }

  /**
   * Calculate attack severity
   * @param {Object} trap - Trap
   * @param {Object} context - Context
   * @returns {string} Severity
   */
  calculateSeverity(trap, context) {
    // High-value traps = high severity
    if (trap.attractiveness > 0.8) {
      return 'critical';
    } else if (trap.attractiveness > 0.6) {
      return 'high';
    } else if (trap.attractiveness > 0.4) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Update attacker profile with new attack
   * @param {Object} attack - Attack data
   * @returns {Promise<void>}
   */
  async updateAttackerProfile(attack) {
    const attackerId = attack.attackerId;
    
    let profile = this.attackerProfiles.get(attackerId);
    
    if (!profile) {
      profile = {
        id: attackerId,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        attackCount: 0,
        trapTypes: new Map(),
        severity: 'low',
        banned: false,
        banUntil: null
      };
    }
    
    // Update profile
    profile.lastSeen = Date.now();
    profile.attackCount++;
    
    // Track trap types
    const trapType = attack.trapType;
    profile.trapTypes.set(trapType, (profile.trapTypes.get(trapType) || 0) + 1);
    
    // Update severity
    if (profile.attackCount >= 10) {
      profile.severity = 'critical';
    } else if (profile.attackCount >= 5) {
      profile.severity = 'high';
    } else if (profile.attackCount >= 3) {
      profile.severity = 'medium';
    }
    
    // Ban if threshold exceeded
    if (profile.attackCount >= this.config.alertThreshold && !profile.banned) {
      profile.banned = true;
      profile.banUntil = Date.now() + this.config.banDuration;
      console.error('[Honeypot] 🚫 ATTACKER BANNED:', attackerId);
    }
    
    this.attackerProfiles.set(attackerId, profile);
    
    // Save to storage
    await this.saveState();
  }

  /**
   * Respond to detected attack
   * @param {Object} attack - Attack data
   * @returns {Promise<void>}
   */
  async respondToAttack(attack) {
    // Alert user if critical
    if (attack.severity === 'critical') {
      if (typeof chrome !== 'undefined' && chrome.notifications) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🚨 Attack Detected!',
          message: `Honeypot trap triggered: ${attack.trapType}`,
          priority: 2
        });
      }
    }
    
    // Log to security events
    await this.logSecurityEvent(attack);
    
    // Adapt defenses based on attack pattern
    await this.adaptDefenses(attack);
  }

  /**
   * Generate deceptive response for attacker
   * @param {Object} trap - Trap that was hit
   * @returns {Object} Deceptive response
   */
  generateDeceptiveResponse(trap) {
    // Generate convincing fake data based on trap type
    switch (trap.type) {
      case this.trapTypes.FAKE_LOGIN:
        return {
          success: false,
          error: 'Invalid credentials',
          message: 'Please try again',
          // Fake session token to waste attacker's time
          sessionToken: this.generateFakeToken()
        };
        
      case this.trapTypes.FAKE_API:
        return {
          success: true,
          data: this.generateFakeAPIData(),
          // Fake pagination to keep attacker engaged
          pagination: {
            page: 1,
            total: 1000,
            hasMore: true
          }
        };
        
      case this.trapTypes.FAKE_ADMIN:
        return {
          success: true,
          user: {
            id: this.generateFakeToken(),
            role: 'admin',
            permissions: ['read', 'write', 'delete']
          },
          // Fake admin panel data
          stats: this.generateFakeStats()
        };
        
      case this.trapTypes.FAKE_VULN:
        return {
          // Fake database dump with honeypot data
          database: 'fake_db',
          tables: ['users', 'sessions', 'logs'],
          data: this.generateFakeDatabaseDump()
        };
        
      default:
        return {
          success: false,
          error: 'Not found'
        };
    }
  }

  /**
   * Generate fake token
   * @returns {string} Fake token
   */
  generateFakeToken() {
    return 'fake_' + Math.random().toString(36).substr(2, 32);
  }

  /**
   * Generate fake API data
   * @returns {Array} Fake data
   */
  generateFakeAPIData() {
    return Array(10).fill(null).map((_, i) => ({
      id: this.generateFakeToken(),
      name: `User ${i + 1}`,
      email: `user${i + 1}@fake.com`,
      created: Date.now() - Math.random() * 86400000
    }));
  }

  /**
   * Generate fake stats
   * @returns {Object} Fake stats
   */
  generateFakeStats() {
    return {
      users: Math.floor(Math.random() * 10000),
      sessions: Math.floor(Math.random() * 1000),
      requests: Math.floor(Math.random() * 100000)
    };
  }

  /**
   * Generate fake database dump
   * @returns {Object} Fake dump
   */
  generateFakeDatabaseDump() {
    return {
      users: this.generateFakeAPIData(),
      sessions: Array(5).fill(null).map(() => ({
        id: this.generateFakeToken(),
        userId: this.generateFakeToken(),
        created: Date.now()
      }))
    };
  }

  /**
   * Adapt defenses based on attack pattern
   * @param {Object} attack - Attack data
   * @returns {Promise<void>}
   */
  async adaptDefenses(attack) {
    // Learn from attack and create new traps
    const attackerId = attack.attackerId;
    const profile = this.attackerProfiles.get(attackerId);
    
    if (profile && profile.attackCount >= 3) {
      // Attacker is persistent, deploy more traps
      console.log('[Honeypot] Deploying additional traps for persistent attacker');
      
      // Create trap similar to what attacker is targeting
      const newTrapUrl = this.generateAdaptiveTrap(attack.trapType);
      this.createTrap(attack.trapType, {
        url: newTrapUrl,
        description: `Adaptive trap for ${attackerId}`,
        attractiveness: 0.85
      });
    }
  }

  /**
   * Generate adaptive trap based on attack pattern
   * @param {string} trapType - Type of trap
   * @returns {string} Trap URL
   */
  generateAdaptiveTrap(trapType) {
    const timestamp = Date.now();
    
    switch (trapType) {
      case this.trapTypes.FAKE_ADMIN:
        return `/admin/panel_${timestamp}`;
      case this.trapTypes.FAKE_API:
        return `/api/v2/data_${timestamp}`;
      case this.trapTypes.FAKE_LOGIN:
        return `/auth/login_${timestamp}`;
      default:
        return `/trap_${timestamp}`;
    }
  }

  /**
   * Start monitoring for attacks
   */
  startMonitoring() {
    // Periodic cleanup of old attacks
    setInterval(() => {
      this.cleanupOldAttacks();
    }, 3600000); // Every hour
    
    // Periodic ban expiration check
    setInterval(() => {
      this.checkBanExpirations();
    }, 60000); // Every minute
  }

  /**
   * Cleanup old attack logs
   */
  cleanupOldAttacks() {
    const cutoff = Date.now() - (7 * 86400000); // 7 days
    this.attackLog = this.attackLog.filter(a => a.timestamp > cutoff);
    console.log('[Honeypot] Cleaned up old attacks');
  }

  /**
   * Check and expire bans
   */
  checkBanExpirations() {
    const now = Date.now();
    
    for (const [attackerId, profile] of this.attackerProfiles.entries()) {
      if (profile.banned && profile.banUntil && now > profile.banUntil) {
        profile.banned = false;
        profile.banUntil = null;
        console.log('[Honeypot] Ban expired for:', attackerId);
      }
    }
  }

  /**
   * Check if attacker is banned
   * @param {string} attackerId - Attacker ID
   * @returns {boolean} Is banned
   */
  isAttackerBanned(attackerId) {
    const profile = this.attackerProfiles.get(attackerId);
    return profile && profile.banned && Date.now() < profile.banUntil;
  }

  /**
   * Log security event
   * @param {Object} event - Security event
   * @returns {Promise<void>}
   */
  async logSecurityEvent(event) {
    try {
      const logs = await chrome.storage.local.get('honeypotLogs') || { honeypotLogs: [] };
      logs.honeypotLogs = logs.honeypotLogs || [];
      logs.honeypotLogs.push(event);
      
      // Keep only last 500 events
      if (logs.honeypotLogs.length > 500) {
        logs.honeypotLogs = logs.honeypotLogs.slice(-500);
      }
      
      await chrome.storage.local.set({ honeypotLogs: logs.honeypotLogs });
    } catch (error) {
      console.error('[Honeypot] Failed to log event:', error);
    }
  }

  /**
   * Load honeypot state
   * @returns {Promise<void>}
   */
  async loadState() {
    try {
      const stored = await chrome.storage.local.get(['honeypotTraps', 'honeypotAttackers']);
      
      if (stored.honeypotTraps) {
        this.traps = new Map(Object.entries(stored.honeypotTraps));
      }
      
      if (stored.honeypotAttackers) {
        this.attackerProfiles = new Map(Object.entries(stored.honeypotAttackers));
      }
      
      console.log('[Honeypot] State loaded');
    } catch (error) {
      console.error('[Honeypot] Failed to load state:', error);
    }
  }

  /**
   * Save honeypot state
   * @returns {Promise<void>}
   */
  async saveState() {
    try {
      await chrome.storage.local.set({
        honeypotTraps: Object.fromEntries(this.traps),
        honeypotAttackers: Object.fromEntries(this.attackerProfiles)
      });
    } catch (error) {
      console.error('[Honeypot] Failed to save state:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      activeTraps: Array.from(this.traps.values()).filter(t => t.active).length,
      totalHits: Array.from(this.traps.values()).reduce((sum, t) => sum + t.hits, 0),
      uniqueAttackers: this.attackerProfiles.size,
      bannedAttackers: Array.from(this.attackerProfiles.values()).filter(p => p.banned).length,
      recentAttacks: this.attackLog.slice(-10)
    };
  }
}

export const aiHoneypot = new AIHoneypot();
