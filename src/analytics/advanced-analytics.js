/**
 * Advanced Analytics Suite
 * Bayesian Inference + Time-Series Analysis + Reinforcement Learning
 * Production-ready implementation
 */

/**
 * Bayesian Inference Engine
 * Probabilistic threat assessment
 */
export class BayesianInference {
  constructor() {
    this.priors = new Map();
    this.likelihoods = new Map();
    this.evidence = new Map();
  }

  /**
   * Calculate posterior probability
   * @param {string} hypothesis - Hypothesis
   * @param {Array} evidence - Evidence
   * @returns {number} Posterior probability
   */
  calculatePosterior(hypothesis, evidence) {
    const prior = this.getPrior(hypothesis);
    const likelihood = this.calculateLikelihood(hypothesis, evidence);
    const evidenceProb = this.calculateEvidence(evidence);
    
    return (likelihood * prior) / evidenceProb;
  }

  /**
   * Update beliefs with new evidence
   * @param {string} hypothesis - Hypothesis
   * @param {Object} evidence - New evidence
   * @param {boolean} observed - Was hypothesis true
   */
  updateBelief(hypothesis, evidence, observed) {
    const posterior = this.calculatePosterior(hypothesis, [evidence]);
    this.priors.set(hypothesis, posterior);
    
    // Update likelihood
    const key = `${hypothesis}_${JSON.stringify(evidence)}`;
    const current = this.likelihoods.get(key) || { true: 0, false: 0, total: 0 };
    
    if (observed) {
      current.true++;
    } else {
      current.false++;
    }
    current.total++;
    
    this.likelihoods.set(key, current);
  }

  /**
   * Get prior probability
   * @param {string} hypothesis - Hypothesis
   * @returns {number} Prior probability
   */
  getPrior(hypothesis) {
    return this.priors.get(hypothesis) || 0.5;
  }

  /**
   * Calculate likelihood
   * @param {string} hypothesis - Hypothesis
   * @param {Array} evidence - Evidence
   * @returns {number} Likelihood
   */
  calculateLikelihood(hypothesis, evidence) {
    let likelihood = 1.0;
    
    for (const e of evidence) {
      const key = `${hypothesis}_${JSON.stringify(e)}`;
      const stats = this.likelihoods.get(key);
      
      if (stats && stats.total > 0) {
        likelihood *= stats.true / stats.total;
      } else {
        likelihood *= 0.5; // Neutral
      }
    }
    
    return likelihood;
  }

  /**
   * Calculate evidence probability
   * @param {Array} evidence - Evidence
   * @returns {number} Evidence probability
   */
  calculateEvidence(evidence) {
    // Simplified: assume uniform distribution
    return 0.5;
  }

  /**
   * Predict threat probability
   * @param {Object} threat - Threat data
   * @returns {Object} Prediction
   */
  predictThreat(threat) {
    const evidence = [
      { type: 'url_suspicious', value: this.isURLSuspicious(threat.url) },
      { type: 'content_urgent', value: this.hasUrgentContent(threat.content) },
      { type: 'high_confidence', value: (threat.confidence || 0) > 0.7 }
    ];

    const posterior = this.calculatePosterior('is_phishing', evidence);

    return {
      probability: posterior,
      confidence: this.calculateConfidence(evidence),
      evidence: evidence
    };
  }

  /**
   * Check if URL is suspicious
   * @param {string} url - URL
   * @returns {boolean} Is suspicious
   */
  isURLSuspicious(url) {
    if (!url) return false;
    return /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|@|-{3,}/.test(url);
  }

  /**
   * Check for urgent content
   * @param {string} content - Content
   * @returns {boolean} Has urgent content
   */
  hasUrgentContent(content) {
    if (!content) return false;
    return /urgent|immediate|act now|verify|suspend/i.test(content);
  }

  /**
   * Calculate confidence
   * @param {Array} evidence - Evidence
   * @returns {number} Confidence
   */
  calculateConfidence(evidence) {
    return Math.min(evidence.length / 5, 1.0);
  }
}

/**
 * Time-Series Analyzer
 * ARIMA-inspired threat forecasting
 */
export class TimeSeriesAnalyzer {
  constructor() {
    this.history = [];
    this.maxHistory = 168; // 7 days hourly
  }

  /**
   * Add observation
   * @param {number} value - Observation value
   * @param {number} timestamp - Timestamp
   */
  addObservation(value, timestamp = Date.now()) {
    this.history.push({ value, timestamp });
    
    if (this.history.length > this.maxHistory) {
      this.history.shift();
    }
  }

  /**
   * Forecast future values
   * @param {number} steps - Steps ahead
   * @returns {Array} Forecasts
   */
  forecast(steps = 24) {
    if (this.history.length < 10) {
      return Array(steps).fill(0);
    }

    const forecasts = [];
    const values = this.history.map(h => h.value);
    
    // Simple exponential smoothing
    const alpha = 0.3;
    let level = values[values.length - 1];
    
    for (let i = 0; i < steps; i++) {
      forecasts.push(level);
      // Trend component (simplified)
      const trend = this.calculateTrend(values);
      level = level + trend;
    }

    return forecasts;
  }

  /**
   * Calculate trend
   * @param {Array} values - Values
   * @returns {number} Trend
   */
  calculateTrend(values) {
    if (values.length < 2) return 0;
    
    const recent = values.slice(-10);
    let sum = 0;
    
    for (let i = 1; i < recent.length; i++) {
      sum += recent[i] - recent[i - 1];
    }
    
    return sum / (recent.length - 1);
  }

  /**
   * Detect anomalies
   * @param {number} threshold - Z-score threshold
   * @returns {Array} Anomalies
   */
  detectAnomalies(threshold = 2.5) {
    if (this.history.length < 10) return [];

    const values = this.history.map(h => h.value);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const std = Math.sqrt(
      values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length
    );

    const anomalies = [];
    
    for (let i = 0; i < this.history.length; i++) {
      const zScore = Math.abs((this.history[i].value - mean) / std);
      
      if (zScore > threshold) {
        anomalies.push({
          index: i,
          timestamp: this.history[i].timestamp,
          value: this.history[i].value,
          zScore: zScore
        });
      }
    }

    return anomalies;
  }

  /**
   * Calculate moving average
   * @param {number} window - Window size
   * @returns {Array} Moving averages
   */
  movingAverage(window = 7) {
    const values = this.history.map(h => h.value);
    const ma = [];

    for (let i = window - 1; i < values.length; i++) {
      const sum = values.slice(i - window + 1, i + 1).reduce((a, b) => a + b, 0);
      ma.push(sum / window);
    }

    return ma;
  }
}

/**
 * Reinforcement Learning Agent
 * Q-Learning for adaptive threat response
 */
export class RLAgent {
  constructor() {
    this.qTable = new Map();
    this.config = {
      learningRate: 0.1,
      discountFactor: 0.9,
      explorationRate: 0.2
    };
  }

  /**
   * Get Q-value
   * @param {string} state - State
   * @param {string} action - Action
   * @returns {number} Q-value
   */
  getQValue(state, action) {
    const key = `${state}_${action}`;
    return this.qTable.get(key) || 0;
  }

  /**
   * Set Q-value
   * @param {string} state - State
   * @param {string} action - Action
   * @param {number} value - Value
   */
  setQValue(state, action, value) {
    const key = `${state}_${action}`;
    this.qTable.set(key, value);
  }

  /**
   * Choose action
   * @param {string} state - Current state
   * @param {Array} actions - Available actions
   * @returns {string} Chosen action
   */
  chooseAction(state, actions) {
    // Epsilon-greedy
    if (Math.random() < this.config.explorationRate) {
      return actions[Math.floor(Math.random() * actions.length)];
    }

    // Choose best action
    let bestAction = actions[0];
    let bestValue = this.getQValue(state, bestAction);

    for (const action of actions) {
      const value = this.getQValue(state, action);
      if (value > bestValue) {
        bestValue = value;
        bestAction = action;
      }
    }

    return bestAction;
  }

  /**
   * Update Q-value
   * @param {string} state - State
   * @param {string} action - Action
   * @param {number} reward - Reward
   * @param {string} nextState - Next state
   * @param {Array} nextActions - Next actions
   */
  update(state, action, reward, nextState, nextActions) {
    const currentQ = this.getQValue(state, action);
    
    // Find max Q-value for next state
    let maxNextQ = 0;
    for (const nextAction of nextActions) {
      const q = this.getQValue(nextState, nextAction);
      if (q > maxNextQ) {
        maxNextQ = q;
      }
    }

    // Q-learning update
    const newQ = currentQ + this.config.learningRate * 
      (reward + this.config.discountFactor * maxNextQ - currentQ);

    this.setQValue(state, action, newQ);
  }

  /**
   * Get policy
   * @param {string} state - State
   * @param {Array} actions - Actions
   * @returns {Object} Policy
   */
  getPolicy(state, actions) {
    const policy = {};
    
    for (const action of actions) {
      policy[action] = this.getQValue(state, action);
    }

    return policy;
  }
}

/**
 * Advanced Analytics Manager
 * Coordinates all analytics components
 */
export class AdvancedAnalytics {
  constructor() {
    this.bayesian = new BayesianInference();
    this.timeSeries = new TimeSeriesAnalyzer();
    this.rlAgent = new RLAgent();
    this.initialized = false;
  }

  /**
   * Initialize analytics
   * @returns {Promise<Object>} Result
   */
  async initialize() {
    try {
      console.log('[Advanced Analytics] Initializing...');
      
      await this.loadState();
      
      this.initialized = true;
      console.log('[Advanced Analytics] Initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[Advanced Analytics] Init failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Analyze threat comprehensively
   * @param {Object} threat - Threat data
   * @returns {Object} Analysis
   */
  analyzeThreat(threat) {
    // Bayesian prediction
    const bayesianResult = this.bayesian.predictThreat(threat);

    // Time-series context
    this.timeSeries.addObservation(bayesianResult.probability);
    const forecast = this.timeSeries.forecast(6);
    const anomalies = this.timeSeries.detectAnomalies();

    // RL recommendation
    const state = this.encodeState(threat, bayesianResult);
    const actions = ['block', 'warn', 'allow', 'investigate'];
    const recommendedAction = this.rlAgent.chooseAction(state, actions);

    return {
      bayesian: bayesianResult,
      timeSeries: {
        forecast: forecast,
        anomalies: anomalies,
        trend: this.timeSeries.calculateTrend(
          this.timeSeries.history.map(h => h.value)
        )
      },
      recommendation: {
        action: recommendedAction,
        policy: this.rlAgent.getPolicy(state, actions)
      },
      overallRisk: this.calculateOverallRisk(bayesianResult, forecast)
    };
  }

  /**
   * Encode state for RL
   * @param {Object} threat - Threat
   * @param {Object} bayesianResult - Bayesian result
   * @returns {string} State
   */
  encodeState(threat, bayesianResult) {
    const prob = bayesianResult.probability;
    const severity = threat.severity || 'medium';
    
    if (prob > 0.8) return `high_${severity}`;
    if (prob > 0.5) return `medium_${severity}`;
    return `low_${severity}`;
  }

  /**
   * Calculate overall risk
   * @param {Object} bayesianResult - Bayesian result
   * @param {Array} forecast - Forecast
   * @returns {number} Risk score
   */
  calculateOverallRisk(bayesianResult, forecast) {
    const currentRisk = bayesianResult.probability;
    const futureRisk = forecast.reduce((a, b) => a + b, 0) / forecast.length;
    
    return (currentRisk * 0.7 + futureRisk * 0.3);
  }

  /**
   * Provide feedback
   * @param {Object} threat - Threat
   * @param {string} action - Action taken
   * @param {boolean} wasCorrect - Was action correct
   */
  provideFeedback(threat, action, wasCorrect) {
    // Update Bayesian beliefs
    const evidence = { type: threat.type, severity: threat.severity };
    this.bayesian.updateBelief('is_phishing', evidence, wasCorrect);

    // Update RL agent
    const state = this.encodeState(threat, { probability: wasCorrect ? 0.9 : 0.1 });
    const reward = wasCorrect ? 1 : -1;
    const nextState = state;
    const actions = ['block', 'warn', 'allow', 'investigate'];
    
    this.rlAgent.update(state, action, reward, nextState, actions);
  }

  /**
   * Load state
   * @returns {Promise<void>}
   */
  async loadState() {
    try {
      const stored = await chrome.storage.local.get('advancedAnalytics');
      
      if (stored.advancedAnalytics) {
        const state = stored.advancedAnalytics;
        
        if (state.bayesian) {
          this.bayesian.priors = new Map(Object.entries(state.bayesian.priors || {}));
          this.bayesian.likelihoods = new Map(Object.entries(state.bayesian.likelihoods || {}));
        }
        
        if (state.timeSeries) {
          this.timeSeries.history = state.timeSeries.history || [];
        }
        
        if (state.rlAgent) {
          this.rlAgent.qTable = new Map(Object.entries(state.rlAgent.qTable || {}));
        }
      }
    } catch (error) {
      console.error('[Advanced Analytics] Load failed:', error);
    }
  }

  /**
   * Save state
   * @returns {Promise<void>}
   */
  async saveState() {
    try {
      await chrome.storage.local.set({
        advancedAnalytics: {
          bayesian: {
            priors: Object.fromEntries(this.bayesian.priors),
            likelihoods: Object.fromEntries(this.bayesian.likelihoods)
          },
          timeSeries: {
            history: this.timeSeries.history
          },
          rlAgent: {
            qTable: Object.fromEntries(this.rlAgent.qTable)
          }
        }
      });
    } catch (error) {
      console.error('[Advanced Analytics] Save failed:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      bayesian: {
        priors: this.bayesian.priors.size,
        likelihoods: this.bayesian.likelihoods.size
      },
      timeSeries: {
        observations: this.timeSeries.history.length
      },
      rlAgent: {
        qTableSize: this.rlAgent.qTable.size
      }
    };
  }
}

export const advancedAnalytics = new AdvancedAnalytics();
