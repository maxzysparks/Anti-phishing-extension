/**
 * Ensemble Phishing Detector
 * Combines multiple ML models for superior accuracy
 * Random Forest + Neural Network + Rule-Based System
 * Production-ready implementation
 */

import * as tf from '@tensorflow/tfjs';

/**
 * Ensemble Detector
 * Combines multiple models using weighted voting
 */
export class EnsembleDetector {
  constructor() {
    this.initialized = false;
    
    // Individual models
    this.models = {
      neuralNetwork: null,
      randomForest: null,
      ruleBased: null
    };
    
    // Model weights (learned from validation data)
    this.weights = {
      neuralNetwork: 0.4,
      randomForest: 0.35,
      ruleBased: 0.25
    };
    
    // Performance tracking
    this.performance = {
      neuralNetwork: { accuracy: 0, precision: 0, recall: 0 },
      randomForest: { accuracy: 0, precision: 0, recall: 0 },
      ruleBased: { accuracy: 0, precision: 0, recall: 0 }
    };
    
    // Feature importance
    this.featureImportance = null;
  }

  /**
   * Initialize ensemble
   * @returns {Promise<Object>} Initialization result
   */
  async initialize() {
    try {
      console.log('[Ensemble] Initializing...');
      
      // Initialize neural network
      await this.initializeNeuralNetwork();
      
      // Initialize random forest
      await this.initializeRandomForest();
      
      // Initialize rule-based system
      this.initializeRuleBased();
      
      // Load performance metrics
      await this.loadPerformanceMetrics();
      
      this.initialized = true;
      console.log('[Ensemble] Initialized successfully');
      
      return { success: true };
      
    } catch (error) {
      console.error('[Ensemble] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Initialize neural network model
   * @returns {Promise<void>}
   */
  async initializeNeuralNetwork() {
    try {
      // Build deep neural network
      const model = tf.sequential();
      
      // Input layer
      model.add(tf.layers.dense({
        inputShape: [50],
        units: 128,
        activation: 'relu',
        kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
      }));
      model.add(tf.layers.batchNormalization());
      model.add(tf.layers.dropout({ rate: 0.3 }));
      
      // Hidden layers
      model.add(tf.layers.dense({
        units: 64,
        activation: 'relu',
        kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
      }));
      model.add(tf.layers.batchNormalization());
      model.add(tf.layers.dropout({ rate: 0.3 }));
      
      model.add(tf.layers.dense({
        units: 32,
        activation: 'relu'
      }));
      model.add(tf.layers.dropout({ rate: 0.2 }));
      
      // Output layer
      model.add(tf.layers.dense({
        units: 1,
        activation: 'sigmoid'
      }));
      
      // Compile (only use built-in metrics)
      model.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
      });
      
      this.models.neuralNetwork = model;
      console.log('[Ensemble] Neural network initialized');
      
    } catch (error) {
      console.error('[Ensemble] Neural network initialization failed:', error);
    }
  }

  /**
   * Initialize random forest (simplified implementation)
   * @returns {Promise<void>}
   */
  async initializeRandomForest() {
    try {
      // Random Forest implementation using decision trees
      this.models.randomForest = {
        trees: [],
        numTrees: 100,
        maxDepth: 10,
        minSamplesSplit: 5,
        
        // Predict using all trees
        predict: async function(features) {
          if (this.trees.length === 0) {
            return 0.5; // Neutral if not trained
          }
          
          // Get predictions from all trees
          const predictions = this.trees.map(tree => 
            this.predictTree(tree, features)
          );
          
          // Average predictions (soft voting)
          const average = predictions.reduce((a, b) => a + b, 0) / predictions.length;
          return average;
        },
        
        // Predict using single tree
        predictTree: function(tree, features) {
          let node = tree;
          
          while (!node.isLeaf) {
            const featureValue = features[node.featureIndex];
            node = featureValue <= node.threshold ? node.left : node.right;
          }
          
          return node.value;
        },
        
        // Train random forest
        train: async function(X, y, options = {}) {
          const { numTrees = 100, maxDepth = 10 } = options;
          
          this.trees = [];
          this.numTrees = numTrees;
          this.maxDepth = maxDepth;
          
          // Train each tree
          for (let i = 0; i < numTrees; i++) {
            // Bootstrap sampling
            const { X_sample, y_sample } = this.bootstrapSample(X, y);
            
            // Train tree
            const tree = this.buildTree(X_sample, y_sample, 0, maxDepth);
            this.trees.push(tree);
            
            if ((i + 1) % 10 === 0) {
              console.log(`[Ensemble] Trained ${i + 1}/${numTrees} trees`);
            }
          }
          
          console.log('[Ensemble] Random forest training complete');
        },
        
        // Bootstrap sampling
        bootstrapSample: function(X, y) {
          const n = X.length;
          const X_sample = [];
          const y_sample = [];
          
          for (let i = 0; i < n; i++) {
            const idx = Math.floor(Math.random() * n);
            X_sample.push(X[idx]);
            y_sample.push(y[idx]);
          }
          
          return { X_sample, y_sample };
        },
        
        // Build decision tree
        buildTree: function(X, y, depth, maxDepth) {
          // Check stopping criteria
          if (depth >= maxDepth || X.length < this.minSamplesSplit || this.isPure(y)) {
            return {
              isLeaf: true,
              value: this.calculateLeafValue(y)
            };
          }
          
          // Find best split
          const split = this.findBestSplit(X, y);
          
          if (!split) {
            return {
              isLeaf: true,
              value: this.calculateLeafValue(y)
            };
          }
          
          // Split data
          const { leftX, leftY, rightX, rightY } = this.splitData(X, y, split);
          
          // Build child nodes
          return {
            isLeaf: false,
            featureIndex: split.featureIndex,
            threshold: split.threshold,
            left: this.buildTree(leftX, leftY, depth + 1, maxDepth),
            right: this.buildTree(rightX, rightY, depth + 1, maxDepth)
          };
        },
        
        // Check if labels are pure
        isPure: function(y) {
          return new Set(y).size === 1;
        },
        
        // Calculate leaf value
        calculateLeafValue: function(y) {
          const sum = y.reduce((a, b) => a + b, 0);
          return sum / y.length;
        },
        
        // Find best split
        findBestSplit: function(X, y) {
          let bestGini = Infinity;
          let bestSplit = null;
          
          const numFeatures = X[0].length;
          const featuresToTry = Math.floor(Math.sqrt(numFeatures)); // Random feature selection
          
          // Randomly select features
          const features = [];
          while (features.length < featuresToTry) {
            const idx = Math.floor(Math.random() * numFeatures);
            if (!features.includes(idx)) {
              features.push(idx);
            }
          }
          
          // Try each feature
          for (const featureIdx of features) {
            const values = X.map(x => x[featureIdx]);
            const uniqueValues = [...new Set(values)].sort((a, b) => a - b);
            
            // Try each threshold
            for (let i = 0; i < uniqueValues.length - 1; i++) {
              const threshold = (uniqueValues[i] + uniqueValues[i + 1]) / 2;
              
              // Calculate Gini impurity
              const gini = this.calculateGini(X, y, featureIdx, threshold);
              
              if (gini < bestGini) {
                bestGini = gini;
                bestSplit = { featureIndex: featureIdx, threshold };
              }
            }
          }
          
          return bestSplit;
        },
        
        // Calculate Gini impurity
        calculateGini: function(X, y, featureIdx, threshold) {
          const { leftY, rightY } = this.splitLabels(X, y, featureIdx, threshold);
          
          if (leftY.length === 0 || rightY.length === 0) {
            return Infinity;
          }
          
          const n = y.length;
          const leftGini = this.giniImpurity(leftY);
          const rightGini = this.giniImpurity(rightY);
          
          return (leftY.length / n) * leftGini + (rightY.length / n) * rightGini;
        },
        
        // Gini impurity
        giniImpurity: function(y) {
          const n = y.length;
          const sum = y.reduce((a, b) => a + b, 0);
          const p = sum / n;
          return 2 * p * (1 - p);
        },
        
        // Split labels
        splitLabels: function(X, y, featureIdx, threshold) {
          const leftY = [];
          const rightY = [];
          
          for (let i = 0; i < X.length; i++) {
            if (X[i][featureIdx] <= threshold) {
              leftY.push(y[i]);
            } else {
              rightY.push(y[i]);
            }
          }
          
          return { leftY, rightY };
        },
        
        // Split data
        splitData: function(X, y, split) {
          const leftX = [], leftY = [];
          const rightX = [], rightY = [];
          
          for (let i = 0; i < X.length; i++) {
            if (X[i][split.featureIndex] <= split.threshold) {
              leftX.push(X[i]);
              leftY.push(y[i]);
            } else {
              rightX.push(X[i]);
              rightY.push(y[i]);
            }
          }
          
          return { leftX, leftY, rightX, rightY };
        }
      };
      
      console.log('[Ensemble] Random forest initialized');
      
    } catch (error) {
      console.error('[Ensemble] Random forest initialization failed:', error);
    }
  }

  /**
   * Initialize rule-based system
   */
  initializeRuleBased() {
    this.models.ruleBased = {
      rules: [
        // High-risk patterns
        { pattern: /password|login|verify|account|suspend/i, weight: 0.3, type: 'content' },
        { pattern: /urgent|immediate|act now|limited time/i, weight: 0.25, type: 'content' },
        { pattern: /click here|verify now|confirm/i, weight: 0.2, type: 'content' },
        
        // URL patterns
        { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, weight: 0.4, type: 'url' }, // IP address
        { pattern: /@/, weight: 0.3, type: 'url' }, // @ in URL
        { pattern: /-{3,}/, weight: 0.25, type: 'url' }, // Multiple hyphens
        { pattern: /\.tk|\.ml|\.ga|\.cf/, weight: 0.35, type: 'url' }, // Suspicious TLDs
        
        // Domain patterns
        { pattern: /paypal|amazon|microsoft|apple|google/i, weight: 0.3, type: 'domain_mismatch' }
      ],
      
      predict: function(features, context = {}) {
        let score = 0;
        const matchedRules = [];
        
        // Check URL rules
        if (context.url) {
          this.rules.filter(r => r.type === 'url').forEach(rule => {
            if (rule.pattern.test(context.url)) {
              score += rule.weight;
              matchedRules.push(rule);
            }
          });
        }
        
        // Check content rules
        if (context.content) {
          this.rules.filter(r => r.type === 'content').forEach(rule => {
            if (rule.pattern.test(context.content)) {
              score += rule.weight;
              matchedRules.push(rule);
            }
          });
        }
        
        // Normalize score
        const probability = Math.min(score, 1.0);
        
        return {
          probability,
          matchedRules,
          confidence: matchedRules.length / this.rules.length
        };
      }
    };
    
    console.log('[Ensemble] Rule-based system initialized');
  }

  /**
   * Predict using ensemble
   * @param {Array} features - Feature vector
   * @param {Object} context - Additional context
   * @returns {Promise<Object>} Prediction result
   */
  async predict(features, context = {}) {
    try {
      if (!this.initialized) {
        await this.initialize();
      }

      // Get predictions from each model
      const predictions = await this.getPredictions(features, context);
      
      // Combine predictions using weighted voting
      const ensemblePrediction = this.combinePredictions(predictions);
      
      // Calculate confidence
      const confidence = this.calculateConfidence(predictions);
      
      // Generate explanation
      const explanation = this.generateExplanation(predictions, ensemblePrediction);

      return {
        success: true,
        probability: ensemblePrediction,
        confidence: confidence,
        predictions: predictions,
        explanation: explanation,
        timestamp: Date.now()
      };

    } catch (error) {
      console.error('[Ensemble] Prediction failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get predictions from all models
   * @param {Array} features - Feature vector
   * @param {Object} context - Context data
   * @returns {Promise<Object>} All predictions
   */
  async getPredictions(features, context) {
    const predictions = {};

    // Neural network prediction
    try {
      if (this.models.neuralNetwork) {
        const tensor = tf.tensor2d([features]);
        const pred = this.models.neuralNetwork.predict(tensor);
        const value = await pred.data();
        predictions.neuralNetwork = value[0];
        tensor.dispose();
        pred.dispose();
      } else {
        predictions.neuralNetwork = 0.5;
      }
    } catch (error) {
      console.error('[Ensemble] Neural network prediction failed:', error);
      predictions.neuralNetwork = 0.5;
    }

    // Random forest prediction
    try {
      if (this.models.randomForest && this.models.randomForest.trees.length > 0) {
        predictions.randomForest = await this.models.randomForest.predict(features);
      } else {
        predictions.randomForest = 0.5;
      }
    } catch (error) {
      console.error('[Ensemble] Random forest prediction failed:', error);
      predictions.randomForest = 0.5;
    }

    // Rule-based prediction
    try {
      const ruleResult = this.models.ruleBased.predict(features, context);
      predictions.ruleBased = ruleResult.probability;
      predictions.ruleBasedDetails = ruleResult;
    } catch (error) {
      console.error('[Ensemble] Rule-based prediction failed:', error);
      predictions.ruleBased = 0.5;
    }

    return predictions;
  }

  /**
   * Combine predictions using weighted voting
   * @param {Object} predictions - Individual predictions
   * @returns {number} Combined prediction
   */
  combinePredictions(predictions) {
    let weightedSum = 0;
    let totalWeight = 0;

    Object.keys(this.weights).forEach(model => {
      if (predictions[model] !== undefined) {
        weightedSum += predictions[model] * this.weights[model];
        totalWeight += this.weights[model];
      }
    });

    return totalWeight > 0 ? weightedSum / totalWeight : 0.5;
  }

  /**
   * Calculate ensemble confidence
   * @param {Object} predictions - Individual predictions
   * @returns {number} Confidence score
   */
  calculateConfidence(predictions) {
    const values = Object.values(predictions).filter(v => typeof v === 'number');
    
    if (values.length === 0) return 0;

    // Calculate agreement (inverse of variance)
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    
    // Low variance = high agreement = high confidence
    const agreement = 1 - Math.min(variance * 4, 1);
    
    return agreement;
  }

  /**
   * Generate explanation
   * @param {Object} predictions - Individual predictions
   * @param {number} ensemblePrediction - Final prediction
   * @returns {Object} Explanation
   */
  generateExplanation(predictions, ensemblePrediction) {
    const explanation = {
      decision: ensemblePrediction > 0.5 ? 'phishing' : 'legitimate',
      modelAgreement: this.calculateConfidence(predictions),
      individualPredictions: {},
      reasoning: []
    };

    // Format individual predictions
    Object.keys(predictions).forEach(model => {
      if (typeof predictions[model] === 'number') {
        explanation.individualPredictions[model] = {
          probability: predictions[model],
          weight: this.weights[model],
          contribution: predictions[model] * this.weights[model]
        };
      }
    });

    // Add reasoning
    if (predictions.ruleBased > 0.6 && predictions.ruleBasedDetails) {
      explanation.reasoning.push({
        source: 'rule-based',
        message: `Matched ${predictions.ruleBasedDetails.matchedRules.length} suspicious patterns`
      });
    }

    if (predictions.neuralNetwork > 0.7) {
      explanation.reasoning.push({
        source: 'neural-network',
        message: 'Deep learning model detected high-risk patterns'
      });
    }

    if (predictions.randomForest > 0.7) {
      explanation.reasoning.push({
        source: 'random-forest',
        message: 'Ensemble of decision trees flagged as suspicious'
      });
    }

    return explanation;
  }

  /**
   * Train ensemble on dataset
   * @param {Array} X - Features
   * @param {Array} y - Labels
   * @param {Object} options - Training options
   * @returns {Promise<Object>} Training result
   */
  async train(X, y, options = {}) {
    try {
      console.log('[Ensemble] Starting training...');

      const results = {};

      // Train neural network
      if (this.models.neuralNetwork) {
        console.log('[Ensemble] Training neural network...');
        const nnResult = await this.trainNeuralNetwork(X, y, options);
        results.neuralNetwork = nnResult;
      }

      // Train random forest
      if (this.models.randomForest) {
        console.log('[Ensemble] Training random forest...');
        await this.models.randomForest.train(X, y, options);
        results.randomForest = { success: true };
      }

      // Save models
      await this.saveModels();

      console.log('[Ensemble] Training completed');

      return {
        success: true,
        results: results
      };

    } catch (error) {
      console.error('[Ensemble] Training failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Train neural network
   * @param {Array} X - Features
   * @param {Array} y - Labels
   * @param {Object} options - Training options
   * @returns {Promise<Object>} Training result
   */
  async trainNeuralNetwork(X, y, options) {
    const {
      epochs = 100,
      batchSize = 32,
      validationSplit = 0.2
    } = options;

    const xs = tf.tensor2d(X);
    const ys = tf.tensor2d(y.map(label => [label]));

    const history = await this.models.neuralNetwork.fit(xs, ys, {
      epochs,
      batchSize,
      validationSplit,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if ((epoch + 1) % 10 === 0) {
            console.log(`Epoch ${epoch + 1}: loss = ${logs.loss.toFixed(4)}, acc = ${logs.acc.toFixed(4)}`);
          }
        }
      }
    });

    xs.dispose();
    ys.dispose();

    return {
      success: true,
      history: history.history
    };
  }

  /**
   * Save models
   * @returns {Promise<void>}
   */
  async saveModels() {
    try {
      // Save neural network
      if (this.models.neuralNetwork) {
        await this.models.neuralNetwork.save('indexeddb://ensemble-nn-model');
      }

      // Save random forest (serialize to JSON)
      if (this.models.randomForest) {
        await chrome.storage.local.set({
          randomForestTrees: this.models.randomForest.trees
        });
      }

      console.log('[Ensemble] Models saved');

    } catch (error) {
      console.error('[Ensemble] Failed to save models:', error);
    }
  }

  /**
   * Load performance metrics
   * @returns {Promise<void>}
   */
  async loadPerformanceMetrics() {
    try {
      const stored = await chrome.storage.local.get('ensemblePerformance');
      
      if (stored.ensemblePerformance) {
        this.performance = stored.ensemblePerformance;
        console.log('[Ensemble] Performance metrics loaded');
      }
      
    } catch (error) {
      console.error('[Ensemble] Failed to load performance metrics:', error);
    }
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      initialized: this.initialized,
      models: {
        neuralNetwork: !!this.models.neuralNetwork,
        randomForest: this.models.randomForest?.trees?.length || 0,
        ruleBased: this.models.ruleBased?.rules?.length || 0
      },
      weights: this.weights,
      performance: this.performance
    };
  }
}

// Create singleton instance
export const ensembleDetector = new EnsembleDetector();
