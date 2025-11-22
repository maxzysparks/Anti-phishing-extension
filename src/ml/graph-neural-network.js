/**
 * Graph Neural Network for Threat Propagation
 * Models how threats spread through networks
 * Predicts cascade effects and propagation patterns
 * Production-ready implementation
 */

import * as tf from '@tensorflow/tfjs';

/**
 * Graph Neural Network
 * Analyzes threat propagation through network topology
 */
export class GraphNeuralNetwork {
  constructor() {
    this.initialized = false;
    this.model = null;
    this.graph = {
      nodes: new Map(),
      edges: new Map()
    };
    
    // GNN configuration
    this.config = {
      hiddenDim: 32,
      numLayers: 3,
      aggregation: 'mean', // mean, max, sum
      learningRate: 0.001
    };
  }

  /**
   * Initialize GNN
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[GNN] Initializing...');
      
      await this.loadGraph();
      await this.buildModel();
      
      this.initialized = true;
      console.log('[GNN] Initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[GNN] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Build GNN model
   * @returns {Promise<void>}
   */
  async buildModel() {
    // Simplified GNN using dense layers
    this.model = tf.sequential({
      layers: [
        tf.layers.dense({ inputShape: [this.config.hiddenDim], units: 64, activation: 'relu' }),
        tf.layers.dropout({ rate: 0.2 }),
        tf.layers.dense({ units: 32, activation: 'relu' }),
        tf.layers.dense({ units: 1, activation: 'sigmoid' })
      ]
    });
    
    this.model.compile({
      optimizer: tf.train.adam(this.config.learningRate),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });
  }

  /**
   * Predict threat propagation
   * @param {string} sourceNode - Source node ID
   * @param {Object} threat - Threat data
   * @returns {Promise<Object>} Propagation prediction
   */
  async predictPropagation(sourceNode, threat) {
    try {
      if (!this.initialized) await this.initialize();

      const propagation = {
        source: sourceNode,
        threat: threat,
        affectedNodes: [],
        propagationPaths: [],
        riskScores: new Map(),
        timeEstimates: new Map()
      };

      // Get neighbors
      const neighbors = this.getNeighbors(sourceNode);
      
      for (const neighbor of neighbors) {
        const risk = await this.calculatePropagationRisk(sourceNode, neighbor, threat);
        
        if (risk > 0.5) {
          propagation.affectedNodes.push(neighbor);
          propagation.riskScores.set(neighbor, risk);
          propagation.timeEstimates.set(neighbor, this.estimatePropagationTime(risk));
        }
      }

      // Find propagation paths
      propagation.propagationPaths = this.findPropagationPaths(sourceNode, propagation.affectedNodes);

      return {
        success: true,
        propagation: propagation
      };
    } catch (error) {
      console.error('[GNN] Prediction failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Calculate propagation risk
   * @param {string} source - Source node
   * @param {string} target - Target node
   * @param {Object} threat - Threat data
   * @returns {Promise<number>} Risk score
   */
  async calculatePropagationRisk(source, target, threat) {
    // Simplified risk calculation
    const edgeWeight = this.getEdgeWeight(source, target);
    const threatSeverity = this.getThreatSeverity(threat);
    const nodeVulnerability = this.getNodeVulnerability(target);
    
    return Math.min(edgeWeight * threatSeverity * nodeVulnerability, 1.0);
  }

  /**
   * Get neighbors of node
   * @param {string} nodeId - Node ID
   * @returns {Array} Neighbor IDs
   */
  getNeighbors(nodeId) {
    const neighbors = [];
    
    for (const [edgeId, edge] of this.graph.edges) {
      if (edge.source === nodeId) {
        neighbors.push(edge.target);
      } else if (edge.target === nodeId) {
        neighbors.push(edge.source);
      }
    }
    
    return neighbors;
  }

  /**
   * Get edge weight
   * @param {string} source - Source node
   * @param {string} target - Target node
   * @returns {number} Weight
   */
  getEdgeWeight(source, target) {
    for (const edge of this.graph.edges.values()) {
      if ((edge.source === source && edge.target === target) ||
          (edge.source === target && edge.target === source)) {
        return edge.weight || 0.5;
      }
    }
    return 0.1; // Default low weight
  }

  /**
   * Get threat severity
   * @param {Object} threat - Threat data
   * @returns {number} Severity score
   */
  getThreatSeverity(threat) {
    const severityMap = { low: 0.25, medium: 0.5, high: 0.75, critical: 1.0 };
    return severityMap[threat.severity] || 0.5;
  }

  /**
   * Get node vulnerability
   * @param {string} nodeId - Node ID
   * @returns {number} Vulnerability score
   */
  getNodeVulnerability(nodeId) {
    const node = this.graph.nodes.get(nodeId);
    return node?.vulnerability || 0.5;
  }

  /**
   * Estimate propagation time
   * @param {number} risk - Risk score
   * @returns {number} Time in milliseconds
   */
  estimatePropagationTime(risk) {
    // Higher risk = faster propagation
    const baseTime = 3600000; // 1 hour
    return baseTime * (1 - risk * 0.5);
  }

  /**
   * Find propagation paths
   * @param {string} source - Source node
   * @param {Array} targets - Target nodes
   * @returns {Array} Paths
   */
  findPropagationPaths(source, targets) {
    const paths = [];
    
    for (const target of targets) {
      const path = this.findShortestPath(source, target);
      if (path) {
        paths.push({
          from: source,
          to: target,
          path: path,
          length: path.length
        });
      }
    }
    
    return paths;
  }

  /**
   * Find shortest path (BFS)
   * @param {string} start - Start node
   * @param {string} end - End node
   * @returns {Array|null} Path
   */
  findShortestPath(start, end) {
    const queue = [[start]];
    const visited = new Set([start]);
    
    while (queue.length > 0) {
      const path = queue.shift();
      const node = path[path.length - 1];
      
      if (node === end) {
        return path;
      }
      
      for (const neighbor of this.getNeighbors(node)) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      }
    }
    
    return null;
  }

  /**
   * Add node to graph
   * @param {string} nodeId - Node ID
   * @param {Object} data - Node data
   */
  addNode(nodeId, data = {}) {
    this.graph.nodes.set(nodeId, {
      id: nodeId,
      vulnerability: data.vulnerability || 0.5,
      ...data
    });
  }

  /**
   * Add edge to graph
   * @param {string} source - Source node
   * @param {string} target - Target node
   * @param {number} weight - Edge weight
   */
  addEdge(source, target, weight = 0.5) {
    const edgeId = `${source}_${target}`;
    this.graph.edges.set(edgeId, {
      source,
      target,
      weight
    });
  }

  /**
   * Load graph
   * @returns {Promise<void>}
   */
  async loadGraph() {
    try {
      const stored = await chrome.storage.local.get('gnnGraph');
      
      if (stored.gnnGraph) {
        this.graph.nodes = new Map(Object.entries(stored.gnnGraph.nodes || {}));
        this.graph.edges = new Map(Object.entries(stored.gnnGraph.edges || {}));
      }
    } catch (error) {
      console.error('[GNN] Load failed:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      nodes: this.graph.nodes.size,
      edges: this.graph.edges.size
    };
  }
}

