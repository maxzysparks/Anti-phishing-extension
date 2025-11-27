/**
 * TensorFlow.js Model Manager
 * Handles ML model loading, inference, and management
 */

import * as tf from '@tensorflow/tfjs';

// CRITICAL FIX #14: Suppress TensorFlow warnings
// Suppress console warnings from TensorFlow (orthogonal initializer warnings)
const originalWarn = console.warn;
console.warn = function(...args) {
  const message = args.join(' ');
  // Filter out TensorFlow orthogonal initializer warnings
  if (message.includes('Orthogonal initializer') || 
      message.includes('Slowness may result')) {
    return; // Suppress these warnings
  }
  originalWarn.apply(console, args);
};

export class TensorFlowManager {
  constructor() {
    this.model = null;
    this.isInitialized = false;
    this.isLoading = false;
    this.fallbackMode = false;
    this.initializationAttempts = 0;
    this.maxInitAttempts = 3;
  }

  /**
   * Initialize TensorFlow.js backend with comprehensive error recovery
   * CRITICAL FIX #1: Enhanced fallback mechanisms
   */
  async initialize() {
    if (this.isInitialized) {
      return { success: true, message: 'Already initialized', fallbackMode: this.fallbackMode };
    }

    if (this.isLoading) {
      return { success: false, message: 'Already loading' };
    }

    this.initializationAttempts++;
    
    if (this.initializationAttempts > this.maxInitAttempts) {
      console.warn('[TF] Max initialization attempts reached, entering fallback mode');
      this.fallbackMode = true;
      this.isInitialized = true;
      return { 
        success: true, 
        message: 'Using fallback mode (heuristic-only detection)',
        fallbackMode: true 
      };
    }

    try {
      this.isLoading = true;
      console.log(`[TF] Initializing TensorFlow.js (attempt ${this.initializationAttempts}/${this.maxInitAttempts})...`);

      // Try WebGL backend first (best performance)
      try {
        await tf.setBackend('webgl');
        await tf.ready();
        console.log('[TF] Backend: WebGL (optimal performance)');
        this.isInitialized = true;
        this.isLoading = false;
        this.fallbackMode = false;
        return { success: true, message: 'Initialized with WebGL backend', backend: 'webgl' };
      } catch (webglError) {
        console.warn('[TF] WebGL backend failed, trying CPU...', webglError.message);
        
        // Fallback to CPU backend
        try {
          await tf.setBackend('cpu');
          await tf.ready();
          console.log('[TF] Backend: CPU (reduced performance)');
          this.isInitialized = true;
          this.isLoading = false;
          this.fallbackMode = false;
          return { success: true, message: 'Initialized with CPU backend', backend: 'cpu' };
        } catch (cpuError) {
          console.warn('[TF] CPU backend failed, trying WASM...', cpuError.message);
          
          // Final fallback to WASM
          try {
            await tf.setBackend('wasm');
            await tf.ready();
            console.log('[TF] Backend: WASM (basic support)');
            this.isInitialized = true;
            this.isLoading = false;
            this.fallbackMode = false;
            return { success: true, message: 'Initialized with WASM backend', backend: 'wasm' };
          } catch (wasmError) {
            throw new Error('All TensorFlow backends failed');
          }
        }
      }
    } catch (error) {
      console.error('[TF] All initialization attempts failed:', error);
      this.isLoading = false;
      
      // Enter fallback mode - use heuristic detection only
      console.warn('[TF] Entering fallback mode - ML features disabled');
      this.fallbackMode = true;
      this.isInitialized = true; // Mark as initialized to prevent retry loops
      
      return { 
        success: true, 
        message: 'Using fallback mode (heuristic-only detection)', 
        error: error.message,
        fallbackMode: true 
      };
    }
  }

  /**
   * Create a simple neural network for phishing detection
   */
  async createPhishingModel() {
    try {
      console.log('[TF] Creating phishing detection model...');

      // Simple feedforward neural network
      const model = tf.sequential({
        layers: [
          // Input layer: 20 features
          tf.layers.dense({
            inputShape: [20],
            units: 64,
            activation: 'relu',
            kernelInitializer: 'heNormal'
          }),
          tf.layers.dropout({ rate: 0.3 }),
          
          // Hidden layer
          tf.layers.dense({
            units: 32,
            activation: 'relu',
            kernelInitializer: 'heNormal'
          }),
          tf.layers.dropout({ rate: 0.2 }),
          
          // Hidden layer
          tf.layers.dense({
            units: 16,
            activation: 'relu',
            kernelInitializer: 'heNormal'
          }),
          
          // Output layer: 3 classes (safe, suspicious, dangerous)
          tf.layers.dense({
            units: 3,
            activation: 'softmax'
          })
        ]
      });

      // Compile model
      model.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'categoricalCrossentropy',
        metrics: ['accuracy']
      });

      this.model = model;
      console.log('[TF] Model created successfully');
      
      return { success: true, model: model };
    } catch (error) {
      console.error('[TF] Model creation error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Extract numerical features from URL analysis for ML model
   */
  extractMLFeatures(urlAnalysis) {
    try {
      const features = urlAnalysis.features || {};
      
      // Normalize features to 0-1 range for neural network
      return [
        // URL structure (normalized)
        Math.min(features.urlLength / 200, 1),
        Math.min(features.domainLength / 50, 1),
        Math.min(features.pathLength / 100, 1),
        Math.min(features.paramCount / 10, 1),
        
        // Character analysis (normalized)
        Math.min(features.digitCount / 20, 1),
        Math.min(features.specialCharCount / 30, 1),
        Math.min(features.uppercaseCount / 20, 1),
        
        // Domain features (binary)
        Math.min(features.subdomainCount / 5, 1),
        features.hasDash ? 1 : 0,
        features.hasUnderscore ? 1 : 0,
        
        // Critical flags (binary)
        features.hasIP ? 1 : 0,
        features.hasPort ? 1 : 0,
        features.hasAtSymbol ? 1 : 0,
        features.isHTTPS ? 1 : 0,
        
        // TLD analysis
        features.isCommonTLD ? 1 : 0,
        
        // Entropy (normalized)
        Math.min(features.entropy / 6, 1),
        
        // Suspicious keywords (normalized)
        Math.min(features.suspiciousKeywords / 5, 1),
        
        // Additional computed features
        urlAnalysis.baseScore ? Math.min(urlAnalysis.baseScore / 30, 1) : 0,
        urlAnalysis.patternScore ? Math.min(urlAnalysis.patternScore / 20, 1) : 0,
        urlAnalysis.contextScore ? Math.min(urlAnalysis.contextScore / 10, 1) : 0
      ];
    } catch (error) {
      console.error('[TF] Feature extraction error:', error);
      return new Array(20).fill(0); // Return zero vector on error
    }
  }

  /**
   * Predict phishing probability using the model
   * CRITICAL FIX #1: Enhanced error handling with fallback
   */
  async predict(urlAnalysis) {
    // Check if in fallback mode
    if (this.fallbackMode) {
      console.log('[TF] Using fallback heuristic prediction (ML disabled)');
      return this.heuristicPredict(urlAnalysis);
    }

    if (!this.isInitialized) {
      const initResult = await this.initialize();
      if (initResult.fallbackMode) {
        return this.heuristicPredict(urlAnalysis);
      }
    }

    if (!this.model) {
      const modelResult = await this.createPhishingModel();
      if (!modelResult.success) {
        console.warn('[TF] Model creation failed, using heuristic fallback');
        return this.heuristicPredict(urlAnalysis);
      }
    }

    try {
      // Extract features
      const features = this.extractMLFeatures(urlAnalysis);
      
      // Create tensor with error handling
      let inputTensor;
      try {
        inputTensor = tf.tensor2d([features], [1, 20]);
      } catch (tensorError) {
        console.error('[TF] Tensor creation failed:', tensorError);
        return this.heuristicPredict(urlAnalysis);
      }
      
      // Make prediction with timeout
      const predictionPromise = this.model.predict(inputTensor);
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Prediction timeout')), 5000)
      );
      
      const prediction = await Promise.race([predictionPromise, timeoutPromise]);
      const probabilities = await prediction.data();
      
      // Clean up tensors
      inputTensor.dispose();
      prediction.dispose();

      // Probabilities: [safe, suspicious, dangerous]
      const result = {
        safe: probabilities[0],
        suspicious: probabilities[1],
        dangerous: probabilities[2],
        prediction: this.getPredictionClass(probabilities),
        confidence: Math.max(...probabilities),
        mlEnabled: true
      };

      console.log('[TF] ML Prediction:', result);
      return result;
    } catch (error) {
      console.error('[TF] Prediction error, falling back to heuristics:', error);
      
      // Don't fail completely - use heuristic fallback
      return this.heuristicPredict(urlAnalysis);
    }
  }

  /**
   * Heuristic-based prediction fallback (no ML required)
   * CRITICAL FIX #1: Ensures extension works even if ML fails
   */
  heuristicPredict(urlAnalysis) {
    try {
      // Calculate threat probability based on heuristic analysis
      const issueCount = urlAnalysis.issues?.length || 0;
      const highSeverity = urlAnalysis.issues?.filter(i => i.severity === 'high').length || 0;
      const mediumSeverity = urlAnalysis.issues?.filter(i => i.severity === 'medium').length || 0;
      
      // Score calculation
      const score = (highSeverity * 3) + (mediumSeverity * 2) + issueCount;
      
      let safe, suspicious, dangerous;
      
      if (score >= 7 || highSeverity >= 3) {
        // High threat
        dangerous = 0.8;
        suspicious = 0.15;
        safe = 0.05;
      } else if (score >= 4 || highSeverity >= 2) {
        // Medium threat
        dangerous = 0.3;
        suspicious = 0.6;
        safe = 0.1;
      } else if (score >= 2 || highSeverity >= 1) {
        // Low threat
        dangerous = 0.1;
        suspicious = 0.5;
        safe = 0.4;
      } else {
        // Minimal threat
        dangerous = 0.05;
        suspicious = 0.15;
        safe = 0.8;
      }
      
      const probabilities = [safe, suspicious, dangerous];
      
      return {
        safe,
        suspicious,
        dangerous,
        prediction: this.getPredictionClass(probabilities),
        confidence: Math.max(...probabilities),
        mlEnabled: false,
        fallbackMode: true,
        heuristicScore: score
      };
    } catch (error) {
      console.error('[TF] Even heuristic prediction failed:', error);
      // Ultimate fallback - neutral prediction
      return {
        safe: 0.33,
        suspicious: 0.34,
        dangerous: 0.33,
        prediction: 'unknown',
        confidence: 0.33,
        mlEnabled: false,
        fallbackMode: true,
        error: error.message
      };
    }
  }

  /**
   * Get prediction class from probabilities
   */
  getPredictionClass(probabilities) {
    const maxProb = Math.max(...probabilities);
    const maxIndex = probabilities.indexOf(maxProb);
    
    const classes = ['safe', 'suspicious', 'dangerous'];
    return classes[maxIndex];
  }

  /**
   * Train model with user feedback
   */
  async trainWithFeedback(feedbackData) {
    if (!this.model) {
      await this.createPhishingModel();
    }

    try {
      console.log('[TF] Training with feedback data...');

      // Prepare training data
      const features = [];
      const labels = [];

      for (const feedback of feedbackData) {
        if (feedback.features) {
          features.push(this.extractMLFeatures(feedback));
          
          // Convert threat level to one-hot encoding
          const label = this.threatLevelToOneHot(feedback.actualThreat);
          labels.push(label);
        }
      }

      if (features.length === 0) {
        return { success: false, message: 'No valid training data' };
      }

      // Create tensors
      const xs = tf.tensor2d(features);
      const ys = tf.tensor2d(labels);

      // Train model
      const history = await this.model.fit(xs, ys, {
        epochs: 10,
        batchSize: 32,
        validationSplit: 0.2,
        shuffle: true,
        callbacks: {
          onEpochEnd: (epoch, logs) => {
            console.log(`[TF] Epoch ${epoch + 1}: loss = ${logs.loss.toFixed(4)}, accuracy = ${logs.acc.toFixed(4)}`);
          }
        }
      });

      // Clean up tensors
      xs.dispose();
      ys.dispose();

      console.log('[TF] Training completed');
      
      return {
        success: true,
        history: {
          loss: history.history.loss,
          accuracy: history.history.acc
        }
      };
    } catch (error) {
      console.error('[TF] Training error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Convert threat level to one-hot encoding
   */
  threatLevelToOneHot(threatLevel) {
    // [safe, suspicious, dangerous]
    switch (threatLevel) {
      case 'SAFE':
        return [1, 0, 0];
      case 'SUSPICIOUS':
        return [0, 1, 0];
      case 'DANGEROUS':
        return [0, 0, 1];
      default:
        return [0.33, 0.33, 0.34]; // Unknown
    }
  }

  /**
   * Save model to IndexedDB
   */
  async saveModel() {
    if (!this.model) {
      return { success: false, message: 'No model to save' };
    }

    try {
      console.log('[TF] Saving model...');
      await this.model.save('indexeddb://phishing-detection-model');
      console.log('[TF] Model saved successfully');
      return { success: true };
    } catch (error) {
      console.error('[TF] Save error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Load model from IndexedDB
   */
  async loadModel() {
    try {
      console.log('[TF] Loading model...');
      this.model = await tf.loadLayersModel('indexeddb://phishing-detection-model');
      console.log('[TF] Model loaded successfully');
      return { success: true };
    } catch (error) {
      console.log('[TF] No saved model found, creating new model');
      return await this.createPhishingModel();
    }
  }

  /**
   * Get model summary
   */
  getModelSummary() {
    if (!this.model) {
      return { error: 'No model loaded' };
    }

    return {
      layers: this.model.layers.length,
      trainable: this.model.trainable,
      backend: tf.getBackend(),
      memory: tf.memory()
    };
  }

  /**
   * Dispose model and free memory
   */
  dispose() {
    if (this.model) {
      this.model.dispose();
      this.model = null;
    }
    this.isInitialized = false;
  }
}

// Singleton instance
export const tfManager = new TensorFlowManager();
