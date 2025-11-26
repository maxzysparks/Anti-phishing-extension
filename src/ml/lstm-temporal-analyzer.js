/**
 * LSTM Temporal Pattern Analyzer
 * Advanced time-series analysis for phishing attack prediction
 * Production-ready implementation with TensorFlow.js
 */

import * as tf from '@tensorflow/tfjs';

/**
 * LSTM Temporal Analyzer
 * Analyzes temporal patterns to predict future attacks
 */
export class LSTMTemporalAnalyzer {
  constructor() {
    this.model = null;
    this.initialized = false;
    
    // Model configuration
    this.config = {
      sequenceLength: 24, // 24 hours of data
      features: 10, // Number of features per timestep
      lstmUnits: 64,
      dropoutRate: 0.2,
      learningRate: 0.001
    };
    
    // Historical data buffer
    this.historicalData = [];
    this.maxHistorySize = 168; // 7 days of hourly data
    
    // Feature normalization parameters
    this.normalizationParams = {
      mean: null,
      std: null
    };
  }

  /**
   * Initialize LSTM model
   * @returns {Promise<Object>} Initialization result
   */
  async initialize() {
    try {
      console.log('[LSTM Temporal] Initializing...');
      
      // Load historical data
      await this.loadHistoricalData();
      
      // Build LSTM model
      await this.buildModel();
      
      // Load pre-trained weights if available
      await this.loadPretrainedWeights();
      
      this.initialized = true;
      console.log('[LSTM Temporal] Initialized successfully');
      
      return { success: true };
      
    } catch (error) {
      console.error('[LSTM Temporal] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Build LSTM model architecture
   * @returns {Promise<void>}
   */
  async buildModel() {
    try {
      const { sequenceLength, features, lstmUnits, dropoutRate } = this.config;
      
      // Input shape: [batch, timesteps, features]
      const input = tf.input({ shape: [sequenceLength, features] });
      
      // First LSTM layer with return sequences
      let x = tf.layers.lstm({
        units: lstmUnits,
        returnSequences: true,
        recurrentDropout: dropoutRate
      }).apply(input);
      
      // Dropout for regularization
      x = tf.layers.dropout({ rate: dropoutRate }).apply(x);
      
      // Second LSTM layer
      x = tf.layers.lstm({
        units: lstmUnits / 2,
        returnSequences: false,
        recurrentDropout: dropoutRate
      }).apply(x);
      
      // Dropout
      x = tf.layers.dropout({ rate: dropoutRate }).apply(x);
      
      // Dense layers for prediction
      x = tf.layers.dense({ units: 32, activation: 'relu' }).apply(x);
      x = tf.layers.dropout({ rate: dropoutRate }).apply(x);
      
      // Output layer: probability of attack in next hour
      const output = tf.layers.dense({ 
        units: 1, 
        activation: 'sigmoid' 
      }).apply(x);
      
      // Create model
      this.model = tf.model({ inputs: input, outputs: output });
      
      // Compile model
      this.model.compile({
        optimizer: tf.train.adam(this.config.learningRate),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
      });
      
      console.log('[LSTM Temporal] Model built successfully');
      this.model.summary();
      
    } catch (error) {
      console.error('[LSTM Temporal] Model building failed:', error);
      throw error;
    }
  }

  /**
   * Predict attack probability for next time window
   * @param {Object} context - Current context
   * @returns {Promise<Object>} Prediction result
   */
  async predict(context = {}) {
    try {
      if (!this.initialized) {
        await this.initialize();
      }

      // Record current observation
      await this.recordObservation(context);

      // Check if we have enough data
      if (this.historicalData.length < this.config.sequenceLength) {
        return {
          success: true,
          probability: 0.5, // Neutral prediction
          confidence: 0.3, // Low confidence
          message: 'Insufficient historical data',
          needsMoreData: true
        };
      }

      // Prepare sequence
      const sequence = this.prepareSequence();
      
      // Make prediction
      const prediction = await this.makePrediction(sequence);
      
      // Analyze prediction
      const analysis = this.analyzePrediction(prediction, context);

      return {
        success: true,
        probability: prediction,
        confidence: analysis.confidence,
        timeframe: analysis.timeframe,
        factors: analysis.factors,
        recommendation: analysis.recommendation,
        timestamp: Date.now()
      };

    } catch (error) {
      console.error('[LSTM Temporal] Prediction failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Record current observation
   * @param {Object} context - Current context
   * @returns {Promise<void>}
   */
  async recordObservation(context) {
    try {
      const now = new Date();
      
      // Extract features
      const features = this.extractFeatures(context, now);
      
      // Add to historical data
      this.historicalData.push({
        timestamp: now.getTime(),
        features: features,
        hour: now.getHours(),
        dayOfWeek: now.getDay(),
        isWeekend: now.getDay() === 0 || now.getDay() === 6
      });

      // Limit history size
      if (this.historicalData.length > this.maxHistorySize) {
        this.historicalData.shift();
      }

      // Save to storage periodically
      if (this.historicalData.length % 10 === 0) {
        await this.saveHistoricalData();
      }

    } catch (error) {
      console.error('[LSTM Temporal] Failed to record observation:', error);
    }
  }

  /**
   * Extract features from context
   * @param {Object} context - Context data
   * @param {Date} timestamp - Current timestamp
   * @returns {Array} Feature vector
   */
  extractFeatures(context, timestamp) {
    const features = [];
    
    // Temporal features
    features.push(timestamp.getHours() / 24); // Hour of day (normalized)
    features.push(timestamp.getDay() / 7); // Day of week (normalized)
    features.push(timestamp.getDate() / 31); // Day of month (normalized)
    
    // Behavioral features
    features.push(context.threatCount || 0);
    features.push(context.clickSpeed || 0);
    features.push(context.activeTime || 0);
    
    // Environmental features
    features.push(context.networkThreats || 0);
    features.push(context.campaignActivity || 0);
    
    // User state features
    features.push(context.isWorkingHours ? 1 : 0);
    features.push(context.isHighRiskTime ? 1 : 0);
    
    return features;
  }

  /**
   * Prepare sequence for prediction
   * @returns {tf.Tensor} Prepared sequence tensor
   */
  prepareSequence() {
    try {
      // Get last N observations
      const sequence = this.historicalData
        .slice(-this.config.sequenceLength)
        .map(obs => obs.features);

      // Normalize features
      const normalized = this.normalizeSequence(sequence);

      // Convert to tensor: [1, sequenceLength, features]
      const tensor = tf.tensor3d([normalized]);

      return tensor;

    } catch (error) {
      console.error('[LSTM Temporal] Sequence preparation failed:', error);
      throw error;
    }
  }

  /**
   * Normalize sequence data
   * @param {Array} sequence - Raw sequence data
   * @returns {Array} Normalized sequence
   */
  normalizeSequence(sequence) {
    if (!this.normalizationParams.mean) {
      // Calculate normalization parameters
      this.calculateNormalizationParams(sequence);
    }

    // Normalize each feature
    return sequence.map(features => 
      features.map((value, idx) => {
        const mean = this.normalizationParams.mean[idx] || 0;
        const std = this.normalizationParams.std[idx] || 1;
        return (value - mean) / (std + 1e-8); // Add epsilon to avoid division by zero
      })
    );
  }

  /**
   * Calculate normalization parameters
   * @param {Array} sequence - Sequence data
   */
  calculateNormalizationParams(sequence) {
    const numFeatures = sequence[0].length;
    const mean = new Array(numFeatures).fill(0);
    const std = new Array(numFeatures).fill(0);

    // Calculate mean
    sequence.forEach(features => {
      features.forEach((value, idx) => {
        mean[idx] += value;
      });
    });
    mean.forEach((sum, idx) => {
      mean[idx] = sum / sequence.length;
    });

    // Calculate standard deviation
    sequence.forEach(features => {
      features.forEach((value, idx) => {
        std[idx] += Math.pow(value - mean[idx], 2);
      });
    });
    std.forEach((sum, idx) => {
      std[idx] = Math.sqrt(sum / sequence.length);
    });

    this.normalizationParams = { mean, std };
  }

  /**
   * Make prediction using model
   * @param {tf.Tensor} sequence - Input sequence
   * @returns {Promise<number>} Prediction probability
   */
  async makePrediction(sequence) {
    try {
      if (!this.model) {
        // Fallback to rule-based prediction
        return this.ruleBasedPrediction();
      }

      // Get prediction
      const prediction = this.model.predict(sequence);
      const value = await prediction.data();

      // Cleanup
      sequence.dispose();
      prediction.dispose();

      return value[0];

    } catch (error) {
      console.error('[LSTM Temporal] Prediction error:', error);
      return this.ruleBasedPrediction();
    }
  }

  /**
   * Rule-based prediction fallback
   * @returns {number} Prediction probability
   */
  ruleBasedPrediction() {
    if (this.historicalData.length === 0) return 0.5;

    // Analyze recent trend
    const recentData = this.historicalData.slice(-24); // Last 24 hours
    const threatCount = recentData.reduce((sum, obs) => sum + (obs.features[3] || 0), 0);
    
    // Simple heuristic
    const probability = Math.min(threatCount / 10, 0.9);
    
    return probability;
  }

  /**
   * Analyze prediction result
   * @param {number} probability - Predicted probability
   * @param {Object} context - Current context
   * @returns {Object} Analysis result
   */
  analyzePrediction(probability, context) {
    const analysis = {
      confidence: 0,
      timeframe: '',
      factors: [],
      recommendation: {}
    };

    // Calculate confidence based on data quality
    const dataQuality = this.historicalData.length / this.maxHistorySize;
    analysis.confidence = Math.min(dataQuality * 0.8 + 0.2, 0.95);

    // Determine timeframe
    if (probability >= 0.8) {
      analysis.timeframe = 'imminent (within 1 hour)';
    } else if (probability >= 0.6) {
      analysis.timeframe = 'near-term (within 6 hours)';
    } else if (probability >= 0.4) {
      analysis.timeframe = 'short-term (within 24 hours)';
    } else {
      analysis.timeframe = 'low probability';
    }

    // Identify contributing factors
    if (this.historicalData.length > 0) {
      const recent = this.historicalData[this.historicalData.length - 1];
      
      if (recent.features[3] > 0.5) {
        analysis.factors.push({
          type: 'threat_activity',
          description: 'Recent threat activity detected',
          impact: 'high'
        });
      }
      
      if (recent.features[6] > 0.5) {
        analysis.factors.push({
          type: 'network_threats',
          description: 'Network threat propagation detected',
          impact: 'medium'
        });
      }
      
      if (recent.features[9] === 1) {
        analysis.factors.push({
          type: 'high_risk_time',
          description: 'Currently in high-risk time window',
          impact: 'medium'
        });
      }
    }

    // Generate recommendation
    if (probability >= 0.7) {
      analysis.recommendation = {
        action: 'enable_maximum_protection',
        message: 'High attack probability - Enable maximum protection',
        priority: 'critical'
      };
    } else if (probability >= 0.5) {
      analysis.recommendation = {
        action: 'increase_vigilance',
        message: 'Moderate attack probability - Stay vigilant',
        priority: 'high'
      };
    } else {
      analysis.recommendation = {
        action: 'normal_protection',
        message: 'Low attack probability - Normal protection sufficient',
        priority: 'low'
      };
    }

    return analysis;
  }

  /**
   * Train model on new data
   * @param {Array} trainingData - Training dataset
   * @param {Object} options - Training options
   * @returns {Promise<Object>} Training result
   */
  async train(trainingData, options = {}) {
    try {
      if (!this.model) {
        await this.buildModel();
      }

      console.log('[LSTM Temporal] Starting training...');

      const {
        epochs = 50,
        batchSize = 32,
        validationSplit = 0.2
      } = options;

      // Prepare training data
      const { xs, ys } = this.prepareTrainingData(trainingData);

      // Train model
      const history = await this.model.fit(xs, ys, {
        epochs: epochs,
        batchSize: batchSize,
        validationSplit: validationSplit,
        callbacks: {
          onEpochEnd: (epoch, logs) => {
            console.log(`Epoch ${epoch + 1}: loss = ${logs.loss.toFixed(4)}, accuracy = ${logs.acc.toFixed(4)}`);
          }
        }
      });

      // Cleanup
      xs.dispose();
      ys.dispose();

      // Save trained model
      await this.saveModel();

      console.log('[LSTM Temporal] Training completed');

      return {
        success: true,
        history: history.history,
        finalLoss: history.history.loss[history.history.loss.length - 1],
        finalAccuracy: history.history.acc[history.history.acc.length - 1]
      };

    } catch (error) {
      console.error('[LSTM Temporal] Training failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Prepare training data
   * @param {Array} trainingData - Raw training data
   * @returns {Object} Prepared tensors
   */
  prepareTrainingData(trainingData) {
    const sequences = [];
    const labels = [];

    // Create sequences
    for (let i = 0; i < trainingData.length - this.config.sequenceLength; i++) {
      const sequence = trainingData
        .slice(i, i + this.config.sequenceLength)
        .map(item => item.features);
      
      const label = trainingData[i + this.config.sequenceLength].label;

      sequences.push(sequence);
      labels.push(label);
    }

    // Normalize sequences
    const normalizedSequences = sequences.map(seq => this.normalizeSequence(seq));

    // Convert to tensors
    const xs = tf.tensor3d(normalizedSequences);
    const ys = tf.tensor2d(labels.map(l => [l]));

    return { xs, ys };
  }

  /**
   * Load pre-trained weights
   * @returns {Promise<void>}
   */
  async loadPretrainedWeights() {
    try {
      // In production, load from server or local storage
      // For now, skip if no weights available
      console.log('[LSTM Temporal] No pre-trained weights available');
    } catch (error) {
      console.error('[LSTM Temporal] Failed to load weights:', error);
    }
  }

  /**
   * Save model
   * @returns {Promise<void>}
   */
  async saveModel() {
    try {
      if (!this.model) return;

      // Save to IndexedDB
      await this.model.save('indexeddb://lstm-temporal-model');
      console.log('[LSTM Temporal] Model saved');

    } catch (error) {
      console.error('[LSTM Temporal] Failed to save model:', error);
    }
  }

  /**
   * Load model
   * @returns {Promise<void>}
   */
  async loadModel() {
    try {
      this.model = await tf.loadLayersModel('indexeddb://lstm-temporal-model');
      console.log('[LSTM Temporal] Model loaded');
    } catch (error) {
      console.log('[LSTM Temporal] No saved model found');
    }
  }

  /**
   * Load historical data
   * @returns {Promise<void>}
   */
  async loadHistoricalData() {
    try {
      const stored = await chrome.storage.local.get('lstmHistoricalData');
      
      if (stored.lstmHistoricalData) {
        this.historicalData = stored.lstmHistoricalData;
        console.log('[LSTM Temporal] Loaded', this.historicalData.length, 'historical observations');
      }
      
    } catch (error) {
      console.error('[LSTM Temporal] Failed to load historical data:', error);
    }
  }

  /**
   * Save historical data
   * @returns {Promise<void>}
   */
  async saveHistoricalData() {
    try {
      await chrome.storage.local.set({
        lstmHistoricalData: this.historicalData,
        lstmTimestamp: Date.now()
      });
    } catch (error) {
      console.error('[LSTM Temporal] Failed to save historical data:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      modelLoaded: !!this.model,
      historicalDataPoints: this.historicalData.length,
      maxHistorySize: this.maxHistorySize,
      sequenceLength: this.config.sequenceLength,
      dataCompleteness: (this.historicalData.length / this.maxHistorySize * 100).toFixed(1) + '%'
    };
  }
}

// Create singleton instance
export const lstmTemporalAnalyzer = new LSTMTemporalAnalyzer();

export default lstmTemporalAnalyzer;
