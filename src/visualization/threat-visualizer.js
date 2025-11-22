/**
 * Real-Time Threat Visualization
 * Live threat map and network graph visualization
 * Attack pattern visualization
 * Production-ready implementation
 */

/**
 * Threat Visualizer
 * Generates visualization data for threats
 */
export class ThreatVisualizer {
  constructor() {
    this.initialized = false;
    this.threats = [];
    this.updateInterval = 5000; // 5 seconds
    this.maxThreats = 100;
  }

  /**
   * Initialize visualizer
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[Visualizer] Initializing...');
      
      await this.loadThreats();
      this.startAutoUpdate();
      
      this.initialized = true;
      console.log('[Visualizer] Initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[Visualizer] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Generate threat map data
   * @returns {Object} Map visualization data
   */
  generateThreatMap() {
    const mapData = {
      threats: [],
      heatmap: [],
      timeline: [],
      statistics: {
        total: this.threats.length,
        byType: {},
        bySeverity: {},
        byRegion: {}
      }
    };

    // Process threats
    for (const threat of this.threats) {
      // Add to map
      mapData.threats.push({
        id: threat.id,
        type: threat.type,
        severity: threat.severity,
        timestamp: threat.timestamp,
        location: this.anonymizeLocation(threat),
        confidence: threat.confidence || 0.5
      });

      // Update statistics
      mapData.statistics.byType[threat.type] = 
        (mapData.statistics.byType[threat.type] || 0) + 1;
      
      mapData.statistics.bySeverity[threat.severity] = 
        (mapData.statistics.bySeverity[threat.severity] || 0) + 1;
    }

    // Generate heatmap
    mapData.heatmap = this.generateHeatmap();

    // Generate timeline
    mapData.timeline = this.generateTimeline();

    return mapData;
  }

  /**
   * Generate network graph data
   * @param {Object} propagationData - Propagation data from GNN
   * @returns {Object} Graph visualization data
   */
  generateNetworkGraph(propagationData) {
    const graphData = {
      nodes: [],
      edges: [],
      clusters: [],
      metrics: {
        density: 0,
        avgDegree: 0,
        diameter: 0
      }
    };

    if (!propagationData) return graphData;

    // Add source node
    graphData.nodes.push({
      id: propagationData.source,
      type: 'source',
      threat: propagationData.threat,
      risk: 1.0
    });

    // Add affected nodes
    for (const nodeId of propagationData.affectedNodes) {
      const risk = propagationData.riskScores.get(nodeId) || 0.5;
      
      graphData.nodes.push({
        id: nodeId,
        type: 'affected',
        risk: risk,
        timeEstimate: propagationData.timeEstimates.get(nodeId)
      });
    }

    // Add edges (propagation paths)
    for (const path of propagationData.propagationPaths) {
      for (let i = 0; i < path.path.length - 1; i++) {
        graphData.edges.push({
          source: path.path[i],
          target: path.path[i + 1],
          weight: 1.0 / path.length
        });
      }
    }

    // Calculate metrics
    graphData.metrics = this.calculateGraphMetrics(graphData);

    return graphData;
  }

  /**
   * Generate attack pattern visualization
   * @param {Array} threats - Threat data
   * @returns {Object} Pattern visualization data
   */
  generateAttackPatterns(threats = this.threats) {
    const patterns = {
      temporal: this.analyzeTemporalPatterns(threats),
      techniques: this.analyzeTechniques(threats),
      targets: this.analyzeTargets(threats),
      campaigns: this.identifyCampaigns(threats)
    };

    return patterns;
  }

  /**
   * Generate dashboard data
   * @returns {Object} Dashboard data
   */
  generateDashboard() {
    return {
      summary: {
        totalThreats: this.threats.length,
        activeThreats: this.threats.filter(t => 
          Date.now() - t.timestamp < 3600000
        ).length,
        criticalThreats: this.threats.filter(t => 
          t.severity === 'critical'
        ).length,
        blockedThreats: this.threats.filter(t => 
          t.status === 'blocked'
        ).length
      },
      charts: {
        threatsByType: this.generatePieChart('type'),
        threatsBySeverity: this.generatePieChart('severity'),
        threatsOverTime: this.generateLineChart(),
        topTargets: this.generateBarChart('target')
      },
      recentThreats: this.threats.slice(-10).reverse(),
      alerts: this.generateAlerts()
    };
  }

  /**
   * Anonymize location
   * @param {Object} threat - Threat data
   * @returns {Object} Anonymized location
   */
  anonymizeLocation(threat) {
    // Return region only, no specific coordinates
    return {
      region: threat.region || 'unknown',
      country: threat.country || 'unknown'
    };
  }

  /**
   * Generate heatmap
   * @returns {Array} Heatmap data
   */
  generateHeatmap() {
    const heatmap = [];
    const regions = {};

    for (const threat of this.threats) {
      const region = threat.region || 'unknown';
      regions[region] = (regions[region] || 0) + 1;
    }

    for (const [region, count] of Object.entries(regions)) {
      heatmap.push({
        region: region,
        intensity: count / this.threats.length,
        count: count
      });
    }

    return heatmap;
  }

  /**
   * Generate timeline
   * @returns {Array} Timeline data
   */
  generateTimeline() {
    const timeline = [];
    const hourly = {};

    for (const threat of this.threats) {
      const hour = new Date(threat.timestamp).getHours();
      hourly[hour] = (hourly[hour] || 0) + 1;
    }

    for (let hour = 0; hour < 24; hour++) {
      timeline.push({
        hour: hour,
        count: hourly[hour] || 0
      });
    }

    return timeline;
  }

  /**
   * Analyze temporal patterns
   * @param {Array} threats - Threats
   * @returns {Object} Temporal analysis
   */
  analyzeTemporalPatterns(threats) {
    const patterns = {
      hourly: new Array(24).fill(0),
      daily: new Array(7).fill(0),
      peakHours: [],
      peakDays: []
    };

    for (const threat of threats) {
      const date = new Date(threat.timestamp);
      patterns.hourly[date.getHours()]++;
      patterns.daily[date.getDay()]++;
    }

    // Find peaks
    const maxHourly = Math.max(...patterns.hourly);
    const maxDaily = Math.max(...patterns.daily);
    
    patterns.peakHours = patterns.hourly
      .map((count, hour) => ({ hour, count }))
      .filter(p => p.count > maxHourly * 0.8)
      .map(p => p.hour);
    
    patterns.peakDays = patterns.daily
      .map((count, day) => ({ day, count }))
      .filter(p => p.count > maxDaily * 0.8)
      .map(p => p.day);

    return patterns;
  }

  /**
   * Analyze techniques
   * @param {Array} threats - Threats
   * @returns {Object} Technique analysis
   */
  analyzeTechniques(threats) {
    const techniques = {};

    for (const threat of threats) {
      if (threat.techniques) {
        for (const technique of threat.techniques) {
          const name = technique.name || technique;
          techniques[name] = (techniques[name] || 0) + 1;
        }
      }
    }

    return Object.entries(techniques)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Analyze targets
   * @param {Array} threats - Threats
   * @returns {Object} Target analysis
   */
  analyzeTargets(threats) {
    const targets = {};

    for (const threat of threats) {
      const target = threat.target || 'unknown';
      targets[target] = (targets[target] || 0) + 1;
    }

    return Object.entries(targets)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Identify campaigns
   * @param {Array} threats - Threats
   * @returns {Array} Campaigns
   */
  identifyCampaigns(threats) {
    // Simple campaign identification by clustering similar threats
    const campaigns = [];
    const processed = new Set();

    for (let i = 0; i < threats.length; i++) {
      if (processed.has(i)) continue;

      const campaign = {
        id: `campaign_${campaigns.length + 1}`,
        threats: [threats[i]],
        startTime: threats[i].timestamp,
        endTime: threats[i].timestamp
      };

      // Find similar threats
      for (let j = i + 1; j < threats.length; j++) {
        if (processed.has(j)) continue;

        if (this.areSimilarThreats(threats[i], threats[j])) {
          campaign.threats.push(threats[j]);
          campaign.endTime = Math.max(campaign.endTime, threats[j].timestamp);
          processed.add(j);
        }
      }

      if (campaign.threats.length >= 3) {
        campaigns.push(campaign);
      }
      
      processed.add(i);
    }

    return campaigns;
  }

  /**
   * Check if threats are similar
   * @param {Object} t1 - Threat 1
   * @param {Object} t2 - Threat 2
   * @returns {boolean} Are similar
   */
  areSimilarThreats(t1, t2) {
    return t1.type === t2.type && 
           t1.severity === t2.severity &&
           Math.abs(t1.timestamp - t2.timestamp) < 86400000; // Within 24 hours
  }

  /**
   * Calculate graph metrics
   * @param {Object} graphData - Graph data
   * @returns {Object} Metrics
   */
  calculateGraphMetrics(graphData) {
    const metrics = {
      density: 0,
      avgDegree: 0,
      diameter: 0
    };

    if (graphData.nodes.length === 0) return metrics;

    // Calculate density
    const maxEdges = (graphData.nodes.length * (graphData.nodes.length - 1)) / 2;
    metrics.density = maxEdges > 0 ? graphData.edges.length / maxEdges : 0;

    // Calculate average degree
    metrics.avgDegree = (2 * graphData.edges.length) / graphData.nodes.length;

    return metrics;
  }

  /**
   * Generate pie chart data
   * @param {string} field - Field to chart
   * @returns {Array} Chart data
   */
  generatePieChart(field) {
    const data = {};

    for (const threat of this.threats) {
      const value = threat[field] || 'unknown';
      data[value] = (data[value] || 0) + 1;
    }

    return Object.entries(data).map(([label, value]) => ({
      label,
      value,
      percentage: (value / this.threats.length * 100).toFixed(1)
    }));
  }

  /**
   * Generate line chart data
   * @returns {Array} Chart data
   */
  generateLineChart() {
    const data = [];
    const now = Date.now();
    const hourMs = 3600000;

    for (let i = 23; i >= 0; i--) {
      const hourStart = now - (i * hourMs);
      const hourEnd = hourStart + hourMs;
      
      const count = this.threats.filter(t => 
        t.timestamp >= hourStart && t.timestamp < hourEnd
      ).length;

      data.push({
        time: new Date(hourStart).getHours(),
        count: count
      });
    }

    return data;
  }

  /**
   * Generate bar chart data
   * @param {string} field - Field to chart
   * @returns {Array} Chart data
   */
  generateBarChart(field) {
    const data = {};

    for (const threat of this.threats) {
      const value = threat[field] || 'unknown';
      data[value] = (data[value] || 0) + 1;
    }

    return Object.entries(data)
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }

  /**
   * Generate alerts
   * @returns {Array} Alerts
   */
  generateAlerts() {
    const alerts = [];

    // Critical threats
    const critical = this.threats.filter(t => t.severity === 'critical');
    if (critical.length > 0) {
      alerts.push({
        type: 'critical',
        message: `${critical.length} critical threats detected`,
        count: critical.length
      });
    }

    // Recent spike
    const lastHour = this.threats.filter(t => 
      Date.now() - t.timestamp < 3600000
    ).length;
    
    if (lastHour > 10) {
      alerts.push({
        type: 'warning',
        message: `High threat activity: ${lastHour} threats in last hour`,
        count: lastHour
      });
    }

    return alerts;
  }

  /**
   * Add threat
   * @param {Object} threat - Threat data
   */
  addThreat(threat) {
    this.threats.push(threat);
    
    // Keep only recent threats
    if (this.threats.length > this.maxThreats) {
      this.threats.shift();
    }
  }

  /**
   * Start auto-update
   */
  startAutoUpdate() {
    setInterval(async () => {
      await this.loadThreats();
    }, this.updateInterval);
  }

  /**
   * Load threats
   * @returns {Promise<void>}
   */
  async loadThreats() {
    try {
      const stored = await chrome.storage.local.get('visualizerThreats');
      
      if (stored.visualizerThreats) {
        this.threats = stored.visualizerThreats;
      }
    } catch (error) {
      console.error('[Visualizer] Load failed:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      threats: this.threats.length,
      updateInterval: this.updateInterval
    };
  }
}

