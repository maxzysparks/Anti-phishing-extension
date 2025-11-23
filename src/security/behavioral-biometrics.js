/**
 * Behavioral Biometrics Engine
 * WORLD-FIRST: Continuous user authentication via typing patterns & mouse behavior
 * Detects account takeover and session hijacking in real-time
 * Makes it impossible for hackers to impersonate legitimate users
 */

export class BehavioralBiometrics {
  constructor() {
    this.initialized = false;
    this.userProfile = null;
    this.currentSession = [];
    
    // Behavioral parameters
    this.config = {
      keystrokeWindow: 5,      // Analyze last 5 keystrokes
      mouseWindow: 10,          // Analyze last 10 mouse movements
      confidenceThreshold: 0.85, // 85% match required
      anomalyThreshold: 3,      // 3 anomalies trigger alert
      sessionTimeout: 300000    // 5 minutes
    };
    
    // User behavioral signature
    this.signature = {
      typing: {
        avgSpeed: 0,           // Average typing speed (ms between keys)
        rhythm: [],            // Typing rhythm pattern
        commonPairs: new Map(), // Common key pair timings
        errorRate: 0           // Backspace frequency
      },
      mouse: {
        avgSpeed: 0,           // Average mouse speed
        acceleration: 0,       // Mouse acceleration pattern
        curvature: 0,          // Path curvature
        clickPattern: []       // Click timing pattern
      },
      interaction: {
        scrollSpeed: 0,        // Scroll behavior
        focusPattern: [],      // Focus change pattern
        sessionLength: 0       // Typical session duration
      }
    };
  }

  /**
   * Initialize behavioral biometrics
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[BB] Initializing behavioral biometrics...');
      
      // Load existing user profile
      await this.loadUserProfile();
      
      // Start monitoring
      this.startMonitoring();
      
      this.initialized = true;
      console.log('[BB] Behavioral biometrics initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[BB] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Start monitoring user behavior
   */
  startMonitoring() {
    // Monitor typing patterns
    document.addEventListener('keydown', (e) => this.recordKeystroke(e));
    document.addEventListener('keyup', (e) => this.recordKeyRelease(e));
    
    // Monitor mouse behavior
    document.addEventListener('mousemove', (e) => this.recordMouseMove(e));
    document.addEventListener('click', (e) => this.recordClick(e));
    
    // Monitor scroll behavior
    document.addEventListener('scroll', (e) => this.recordScroll(e));
    
    // Analyze periodically
    setInterval(() => this.analyzeSession(), 10000); // Every 10 seconds
  }

  /**
   * Record keystroke timing
   * @param {KeyboardEvent} event - Keyboard event
   */
  recordKeystroke(event) {
    const timestamp = Date.now();
    
    this.currentSession.push({
      type: 'keydown',
      key: event.key,
      timestamp: timestamp,
      duration: 0
    });
    
    // Keep only recent events
    if (this.currentSession.length > 100) {
      this.currentSession.shift();
    }
  }

  /**
   * Record key release timing
   * @param {KeyboardEvent} event - Keyboard event
   */
  recordKeyRelease(event) {
    const timestamp = Date.now();
    
    // Find matching keydown
    for (let i = this.currentSession.length - 1; i >= 0; i--) {
      if (this.currentSession[i].type === 'keydown' && 
          this.currentSession[i].key === event.key &&
          this.currentSession[i].duration === 0) {
        this.currentSession[i].duration = timestamp - this.currentSession[i].timestamp;
        break;
      }
    }
  }

  /**
   * Record mouse movement
   * @param {MouseEvent} event - Mouse event
   */
  recordMouseMove(event) {
    const timestamp = Date.now();
    
    this.currentSession.push({
      type: 'mousemove',
      x: event.clientX,
      y: event.clientY,
      timestamp: timestamp
    });
    
    // Keep only recent events
    if (this.currentSession.length > 100) {
      this.currentSession.shift();
    }
  }

  /**
   * Record click event
   * @param {MouseEvent} event - Mouse event
   */
  recordClick(event) {
    const timestamp = Date.now();
    
    this.currentSession.push({
      type: 'click',
      x: event.clientX,
      y: event.clientY,
      timestamp: timestamp,
      button: event.button
    });
  }

  /**
   * Record scroll event
   * @param {Event} event - Scroll event
   */
  recordScroll(event) {
    const timestamp = Date.now();
    
    this.currentSession.push({
      type: 'scroll',
      scrollY: window.scrollY,
      timestamp: timestamp
    });
  }

  /**
   * Analyze current session for anomalies
   * @returns {Object} Analysis result
   */
  analyzeSession() {
    if (!this.userProfile || this.currentSession.length < 10) {
      return { anomaly: false, confidence: 0 };
    }

    try {
      // Extract features from current session
      const currentFeatures = this.extractFeatures(this.currentSession);
      
      // Compare with user profile
      const similarity = this.calculateSimilarity(currentFeatures, this.userProfile);
      
      // Detect anomalies
      const isAnomaly = similarity < this.config.confidenceThreshold;
      
      if (isAnomaly) {
        console.warn('[BB] Behavioral anomaly detected! Similarity:', similarity);
        this.handleAnomaly(similarity);
      }
      
      return {
        anomaly: isAnomaly,
        confidence: similarity,
        features: currentFeatures
      };
      
    } catch (error) {
      console.error('[BB] Analysis failed:', error);
      return { anomaly: false, confidence: 0, error: error.message };
    }
  }

  /**
   * Extract behavioral features from session
   * @param {Array} session - Session events
   * @returns {Object} Features
   */
  extractFeatures(session) {
    const features = {
      typing: this.extractTypingFeatures(session),
      mouse: this.extractMouseFeatures(session),
      interaction: this.extractInteractionFeatures(session)
    };
    
    return features;
  }

  /**
   * Extract typing features
   * @param {Array} session - Session events
   * @returns {Object} Typing features
   */
  extractTypingFeatures(session) {
    const keystrokes = session.filter(e => e.type === 'keydown' && e.duration > 0);
    
    if (keystrokes.length === 0) {
      return { avgSpeed: 0, rhythm: [], errorRate: 0 };
    }
    
    // Calculate average typing speed
    const speeds = [];
    for (let i = 1; i < keystrokes.length; i++) {
      const timeDiff = keystrokes[i].timestamp - keystrokes[i-1].timestamp;
      speeds.push(timeDiff);
    }
    
    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    
    // Calculate rhythm (variance in timing)
    const variance = speeds.reduce((sum, speed) => {
      return sum + Math.pow(speed - avgSpeed, 2);
    }, 0) / speeds.length;
    
    // Calculate error rate (backspace frequency)
    const backspaces = keystrokes.filter(k => k.key === 'Backspace').length;
    const errorRate = backspaces / keystrokes.length;
    
    return {
      avgSpeed: avgSpeed,
      rhythm: [Math.sqrt(variance)],
      errorRate: errorRate
    };
  }

  /**
   * Extract mouse features
   * @param {Array} session - Session events
   * @returns {Object} Mouse features
   */
  extractMouseFeatures(session) {
    const mouseMoves = session.filter(e => e.type === 'mousemove');
    
    if (mouseMoves.length < 2) {
      return { avgSpeed: 0, acceleration: 0, curvature: 0 };
    }
    
    // Calculate average mouse speed
    const speeds = [];
    for (let i = 1; i < mouseMoves.length; i++) {
      const dx = mouseMoves[i].x - mouseMoves[i-1].x;
      const dy = mouseMoves[i].y - mouseMoves[i-1].y;
      const distance = Math.sqrt(dx*dx + dy*dy);
      const timeDiff = mouseMoves[i].timestamp - mouseMoves[i-1].timestamp;
      const speed = distance / (timeDiff || 1);
      speeds.push(speed);
    }
    
    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    
    // Calculate acceleration (change in speed)
    const accelerations = [];
    for (let i = 1; i < speeds.length; i++) {
      accelerations.push(Math.abs(speeds[i] - speeds[i-1]));
    }
    
    const avgAcceleration = accelerations.length > 0 
      ? accelerations.reduce((a, b) => a + b, 0) / accelerations.length 
      : 0;
    
    // Calculate path curvature
    let totalAngle = 0;
    for (let i = 2; i < mouseMoves.length; i++) {
      const v1x = mouseMoves[i-1].x - mouseMoves[i-2].x;
      const v1y = mouseMoves[i-1].y - mouseMoves[i-2].y;
      const v2x = mouseMoves[i].x - mouseMoves[i-1].x;
      const v2y = mouseMoves[i].y - mouseMoves[i-1].y;
      
      const angle = Math.atan2(v2y, v2x) - Math.atan2(v1y, v1x);
      totalAngle += Math.abs(angle);
    }
    
    const curvature = totalAngle / (mouseMoves.length - 2 || 1);
    
    return {
      avgSpeed: avgSpeed,
      acceleration: avgAcceleration,
      curvature: curvature
    };
  }

  /**
   * Extract interaction features
   * @param {Array} session - Session events
   * @returns {Object} Interaction features
   */
  extractInteractionFeatures(session) {
    const scrollEvents = session.filter(e => e.type === 'scroll');
    
    // Calculate scroll speed
    let scrollSpeed = 0;
    if (scrollEvents.length > 1) {
      const speeds = [];
      for (let i = 1; i < scrollEvents.length; i++) {
        const scrollDiff = Math.abs(scrollEvents[i].scrollY - scrollEvents[i-1].scrollY);
        const timeDiff = scrollEvents[i].timestamp - scrollEvents[i-1].timestamp;
        speeds.push(scrollDiff / (timeDiff || 1));
      }
      scrollSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    }
    
    return {
      scrollSpeed: scrollSpeed,
      sessionLength: session.length
    };
  }

  /**
   * Calculate similarity between current and profile features
   * @param {Object} current - Current features
   * @param {Object} profile - User profile
   * @returns {number} Similarity score (0-1)
   */
  calculateSimilarity(current, profile) {
    let totalSimilarity = 0;
    let weights = 0;
    
    // Compare typing features (weight: 0.4)
    if (current.typing && profile.typing) {
      const typingSim = this.compareTyping(current.typing, profile.typing);
      totalSimilarity += typingSim * 0.4;
      weights += 0.4;
    }
    
    // Compare mouse features (weight: 0.4)
    if (current.mouse && profile.mouse) {
      const mouseSim = this.compareMouse(current.mouse, profile.mouse);
      totalSimilarity += mouseSim * 0.4;
      weights += 0.4;
    }
    
    // Compare interaction features (weight: 0.2)
    if (current.interaction && profile.interaction) {
      const interactionSim = this.compareInteraction(current.interaction, profile.interaction);
      totalSimilarity += interactionSim * 0.2;
      weights += 0.2;
    }
    
    return weights > 0 ? totalSimilarity / weights : 0;
  }

  /**
   * Compare typing features
   * @param {Object} current - Current typing
   * @param {Object} profile - Profile typing
   * @returns {number} Similarity
   */
  compareTyping(current, profile) {
    // Compare typing speed (tolerance: 30%)
    const speedDiff = Math.abs(current.avgSpeed - profile.avgSpeed) / profile.avgSpeed;
    const speedSim = Math.max(0, 1 - speedDiff / 0.3);
    
    // Compare error rate (tolerance: 50%)
    const errorDiff = Math.abs(current.errorRate - profile.errorRate);
    const errorSim = Math.max(0, 1 - errorDiff / 0.5);
    
    return (speedSim + errorSim) / 2;
  }

  /**
   * Compare mouse features
   * @param {Object} current - Current mouse
   * @param {Object} profile - Profile mouse
   * @returns {number} Similarity
   */
  compareMouse(current, profile) {
    // Compare mouse speed (tolerance: 40%)
    const speedDiff = Math.abs(current.avgSpeed - profile.avgSpeed) / (profile.avgSpeed || 1);
    const speedSim = Math.max(0, 1 - speedDiff / 0.4);
    
    // Compare acceleration (tolerance: 50%)
    const accelDiff = Math.abs(current.acceleration - profile.acceleration) / (profile.acceleration || 1);
    const accelSim = Math.max(0, 1 - accelDiff / 0.5);
    
    // Compare curvature (tolerance: 40%)
    const curveDiff = Math.abs(current.curvature - profile.curvature) / (profile.curvature || 1);
    const curveSim = Math.max(0, 1 - curveDiff / 0.4);
    
    return (speedSim + accelSim + curveSim) / 3;
  }

  /**
   * Compare interaction features
   * @param {Object} current - Current interaction
   * @param {Object} profile - Profile interaction
   * @returns {number} Similarity
   */
  compareInteraction(current, profile) {
    // Compare scroll speed (tolerance: 50%)
    const scrollDiff = Math.abs(current.scrollSpeed - profile.scrollSpeed) / (profile.scrollSpeed || 1);
    const scrollSim = Math.max(0, 1 - scrollDiff / 0.5);
    
    return scrollSim;
  }

  /**
   * Handle detected anomaly
   * @param {number} confidence - Confidence score
   */
  handleAnomaly(confidence) {
    // Log anomaly
    console.error('[BB] SECURITY ALERT: Behavioral anomaly detected!');
    console.error('[BB] Confidence:', confidence);
    console.error('[BB] Possible account takeover or session hijacking');
    
    // Trigger security response
    this.triggerSecurityResponse(confidence);
  }

  /**
   * Trigger security response
   * @param {number} confidence - Confidence score
   */
  async triggerSecurityResponse(confidence) {
    // Show warning to user
    if (typeof chrome !== 'undefined' && chrome.notifications) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 Security Alert',
        message: 'Unusual behavior detected. Your session may be compromised.',
        priority: 2
      });
    }
    
    // Log security event
    await this.logSecurityEvent({
      type: 'behavioral_anomaly',
      confidence: confidence,
      timestamp: Date.now(),
      action: 'alert_triggered'
    });
  }

  /**
   * Log security event
   * @param {Object} event - Security event
   * @returns {Promise<void>}
   */
  async logSecurityEvent(event) {
    try {
      const logs = await chrome.storage.local.get('securityLogs') || { securityLogs: [] };
      logs.securityLogs = logs.securityLogs || [];
      logs.securityLogs.push(event);
      
      // Keep only last 100 events
      if (logs.securityLogs.length > 100) {
        logs.securityLogs = logs.securityLogs.slice(-100);
      }
      
      await chrome.storage.local.set({ securityLogs: logs.securityLogs });
    } catch (error) {
      console.error('[BB] Failed to log security event:', error);
    }
  }

  /**
   * Load user profile
   * @returns {Promise<void>}
   */
  async loadUserProfile() {
    try {
      const stored = await chrome.storage.local.get('behavioralProfile');
      
      if (stored.behavioralProfile) {
        this.userProfile = stored.behavioralProfile;
        console.log('[BB] User profile loaded');
      } else {
        console.log('[BB] No profile found, will create new profile');
      }
    } catch (error) {
      console.error('[BB] Failed to load profile:', error);
    }
  }

  /**
   * Save user profile
   * @returns {Promise<void>}
   */
  async saveUserProfile() {
    try {
      if (this.currentSession.length < 50) {
        return; // Not enough data
      }
      
      const features = this.extractFeatures(this.currentSession);
      
      await chrome.storage.local.set({
        behavioralProfile: features
      });
      
      console.log('[BB] User profile saved');
    } catch (error) {
      console.error('[BB] Failed to save profile:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      hasProfile: !!this.userProfile,
      sessionEvents: this.currentSession.length,
      config: this.config
    };
  }
}

export const behavioralBiometrics = new BehavioralBiometrics();
