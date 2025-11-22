/**
 * DBSCAN Clustering for Campaign Detection
 * Density-based spatial clustering of applications with noise
 * Identifies phishing campaigns and attack patterns
 * Production-ready implementation
 */

/**
 * DBSCAN Clustering Algorithm
 * Groups similar threats into campaigns
 */
export class DBSCANClustering {
  constructor() {
    this.initialized = false;
    this.clusters = [];
    this.noise = [];
    
    // DBSCAN parameters
    this.config = {
      epsilon: 0.3, // Maximum distance between points
      minPoints: 3, // Minimum points to form cluster
      distanceMetric: 'euclidean' // euclidean, cosine, manhattan
    };
  }

  /**
   * Initialize clustering
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[DBSCAN] Initializing...');
      
      await this.loadClusters();
      
      this.initialized = true;
      console.log('[DBSCAN] Initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[DBSCAN] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Cluster threats into campaigns
   * @param {Array} threats - Threat data
   * @param {Object} options - Clustering options
   * @returns {Object} Clustering result
   */
  cluster(threats, options = {}) {
    try {
      const { epsilon = this.config.epsilon, minPoints = this.config.minPoints } = options;

      // Reset clusters
      this.clusters = [];
      this.noise = [];

      // Extract features
      const features = threats.map(t => this.extractFeatures(t));

      // Track visited and cluster assignments
      const visited = new Set();
      const clusterAssignments = new Array(threats.length).fill(-1);
      let clusterId = 0;

      // DBSCAN algorithm
      for (let i = 0; i < threats.length; i++) {
        if (visited.has(i)) continue;

        visited.add(i);

        // Find neighbors
        const neighbors = this.findNeighbors(i, features, epsilon);

        if (neighbors.length < minPoints) {
          // Mark as noise
          this.noise.push(threats[i]);
        } else {
          // Create new cluster
          this.expandCluster(i, neighbors, clusterId, features, epsilon, minPoints, visited, clusterAssignments, threats);
          clusterId++;
        }
      }

      // Build cluster objects
      for (let i = 0; i < clusterId; i++) {
        const clusterThreats = threats.filter((_, idx) => clusterAssignments[idx] === i);
        
        this.clusters.push({
          id: `cluster_${i}`,
          threats: clusterThreats,
          size: clusterThreats.length,
          centroid: this.calculateCentroid(clusterThreats),
          characteristics: this.analyzeCluster(clusterThreats),
          timespan: this.calculateTimespan(clusterThreats)
        });
      }

      return {
        success: true,
        clusters: this.clusters,
        noise: this.noise,
        statistics: {
          totalClusters: this.clusters.length,
          totalNoise: this.noise.length,
          avgClusterSize: this.clusters.reduce((sum, c) => sum + c.size, 0) / this.clusters.length || 0
        }
      };

    } catch (error) {
      console.error('[DBSCAN] Clustering failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Expand cluster
   * @param {number} pointIdx - Point index
   * @param {Array} neighbors - Neighbor indices
   * @param {number} clusterId - Cluster ID
   * @param {Array} features - Feature vectors
   * @param {number} epsilon - Epsilon parameter
   * @param {number} minPoints - Min points parameter
   * @param {Set} visited - Visited set
   * @param {Array} clusterAssignments - Cluster assignments
   * @param {Array} threats - Threat data
   */
  expandCluster(pointIdx, neighbors, clusterId, features, epsilon, minPoints, visited, clusterAssignments, threats) {
    clusterAssignments[pointIdx] = clusterId;

    let i = 0;
    while (i < neighbors.length) {
      const neighborIdx = neighbors[i];

      if (!visited.has(neighborIdx)) {
        visited.add(neighborIdx);

        const neighborNeighbors = this.findNeighbors(neighborIdx, features, epsilon);

        if (neighborNeighbors.length >= minPoints) {
          neighbors.push(...neighborNeighbors.filter(n => !neighbors.includes(n)));
        }
      }

      if (clusterAssignments[neighborIdx] === -1) {
        clusterAssignments[neighborIdx] = clusterId;
      }

      i++;
    }
  }

  /**
   * Find neighbors within epsilon
   * @param {number} pointIdx - Point index
   * @param {Array} features - Feature vectors
   * @param {number} epsilon - Epsilon parameter
   * @returns {Array} Neighbor indices
   */
  findNeighbors(pointIdx, features, epsilon) {
    const neighbors = [];
    const point = features[pointIdx];

    for (let i = 0; i < features.length; i++) {
      if (i === pointIdx) continue;

      const distance = this.calculateDistance(point, features[i]);

      if (distance <= epsilon) {
        neighbors.push(i);
      }
    }

    return neighbors;
  }

  /**
   * Extract features from threat
   * @param {Object} threat - Threat data
   * @returns {Array} Feature vector
   */
  extractFeatures(threat) {
    const features = [];

    // Temporal features (normalized)
    const timestamp = threat.timestamp || Date.now();
    const date = new Date(timestamp);
    features.push(date.getHours() / 24);
    features.push(date.getDay() / 7);

    // Type encoding
    const typeMap = { phishing: 0, malware: 0.33, spam: 0.66, other: 1 };
    features.push(typeMap[threat.type] || 1);

    // Severity encoding
    const severityMap = { low: 0.25, medium: 0.5, high: 0.75, critical: 1 };
    features.push(severityMap[threat.severity] || 0.5);

    // Confidence
    features.push(threat.confidence || 0.5);

    // URL features
    if (threat.url) {
      try {
        const url = new URL(threat.url);
        features.push(url.hostname.length / 100); // Normalized length
        features.push(url.pathname.length / 100);
        features.push(url.search ? 1 : 0);
      } catch {
        features.push(0, 0, 0);
      }
    } else {
      features.push(0, 0, 0);
    }

    // Technique similarity (simplified)
    features.push(threat.techniques?.length || 0 / 10);

    return features;
  }

  /**
   * Calculate distance between points
   * @param {Array} point1 - First point
   * @param {Array} point2 - Second point
   * @returns {number} Distance
   */
  calculateDistance(point1, point2) {
    if (this.config.distanceMetric === 'euclidean') {
      return this.euclideanDistance(point1, point2);
    } else if (this.config.distanceMetric === 'cosine') {
      return this.cosineDistance(point1, point2);
    } else if (this.config.distanceMetric === 'manhattan') {
      return this.manhattanDistance(point1, point2);
    }
    return this.euclideanDistance(point1, point2);
  }

  /**
   * Euclidean distance
   * @param {Array} p1 - Point 1
   * @param {Array} p2 - Point 2
   * @returns {number} Distance
   */
  euclideanDistance(p1, p2) {
    let sum = 0;
    for (let i = 0; i < p1.length; i++) {
      sum += Math.pow(p1[i] - p2[i], 2);
    }
    return Math.sqrt(sum);
  }

  /**
   * Cosine distance
   * @param {Array} p1 - Point 1
   * @param {Array} p2 - Point 2
   * @returns {number} Distance
   */
  cosineDistance(p1, p2) {
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < p1.length; i++) {
      dotProduct += p1[i] * p2[i];
      norm1 += p1[i] * p1[i];
      norm2 += p2[i] * p2[i];
    }

    const similarity = dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    return 1 - similarity;
  }

  /**
   * Manhattan distance
   * @param {Array} p1 - Point 1
   * @param {Array} p2 - Point 2
   * @returns {number} Distance
   */
  manhattanDistance(p1, p2) {
    let sum = 0;
    for (let i = 0; i < p1.length; i++) {
      sum += Math.abs(p1[i] - p2[i]);
    }
    return sum;
  }

  /**
   * Calculate cluster centroid
   * @param {Array} threats - Cluster threats
   * @returns {Object} Centroid
   */
  calculateCentroid(threats) {
    const features = threats.map(t => this.extractFeatures(t));
    const centroid = new Array(features[0].length).fill(0);

    for (const feature of features) {
      for (let i = 0; i < feature.length; i++) {
        centroid[i] += feature[i];
      }
    }

    for (let i = 0; i < centroid.length; i++) {
      centroid[i] /= features.length;
    }

    return centroid;
  }

  /**
   * Analyze cluster characteristics
   * @param {Array} threats - Cluster threats
   * @returns {Object} Characteristics
   */
  analyzeCluster(threats) {
    const characteristics = {
      dominantType: this.findDominant(threats, 'type'),
      dominantSeverity: this.findDominant(threats, 'severity'),
      avgConfidence: threats.reduce((sum, t) => sum + (t.confidence || 0.5), 0) / threats.length,
      techniques: this.aggregateTechniques(threats),
      targets: this.aggregateTargets(threats)
    };

    return characteristics;
  }

  /**
   * Find dominant value
   * @param {Array} threats - Threats
   * @param {string} field - Field name
   * @returns {string} Dominant value
   */
  findDominant(threats, field) {
    const counts = {};
    
    for (const threat of threats) {
      const value = threat[field] || 'unknown';
      counts[value] = (counts[value] || 0) + 1;
    }

    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';
  }

  /**
   * Aggregate techniques
   * @param {Array} threats - Threats
   * @returns {Array} Techniques
   */
  aggregateTechniques(threats) {
    const techniques = {};

    for (const threat of threats) {
      if (threat.techniques) {
        for (const tech of threat.techniques) {
          const name = tech.name || tech;
          techniques[name] = (techniques[name] || 0) + 1;
        }
      }
    }

    return Object.entries(techniques)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Aggregate targets
   * @param {Array} threats - Threats
   * @returns {Array} Targets
   */
  aggregateTargets(threats) {
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
   * Calculate timespan
   * @param {Array} threats - Threats
   * @returns {Object} Timespan
   */
  calculateTimespan(threats) {
    const timestamps = threats.map(t => t.timestamp || Date.now());
    const min = Math.min(...timestamps);
    const max = Math.max(...timestamps);

    return {
      start: min,
      end: max,
      duration: max - min,
      durationHours: (max - min) / 3600000
    };
  }

  /**
   * Get campaign insights
   * @returns {Object} Insights
   */
  getCampaignInsights() {
    return {
      totalCampaigns: this.clusters.length,
      activeCampaigns: this.clusters.filter(c => 
        Date.now() - c.timespan.end < 86400000
      ).length,
      largeCampaigns: this.clusters.filter(c => c.size >= 10).length,
      avgCampaignSize: this.clusters.reduce((sum, c) => sum + c.size, 0) / this.clusters.length || 0,
      noiseRate: this.noise.length / (this.noise.length + this.clusters.reduce((sum, c) => sum + c.size, 0)) || 0
    };
  }

  /**
   * Load clusters
   * @returns {Promise<void>}
   */
  async loadClusters() {
    try {
      const stored = await chrome.storage.local.get('dbscanClusters');
      
      if (stored.dbscanClusters) {
        this.clusters = stored.dbscanClusters;
      }
    } catch (error) {
      console.error('[DBSCAN] Load failed:', error);
    }
  }

  /**
   * Save clusters
   * @returns {Promise<void>}
   */
  async saveClusters() {
    try {
      await chrome.storage.local.set({
        dbscanClusters: this.clusters,
        dbscanNoise: this.noise
      });
    } catch (error) {
      console.error('[DBSCAN] Save failed:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      clusters: this.clusters.length,
      noise: this.noise.length,
      config: this.config
    };
  }
}

export const dbscanClustering = new DBSCANClustering();
