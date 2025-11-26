/**
 * ML Model Trainer
 * Trains the TensorFlow.js model with collected data
 */

import { tfManager } from './tensorflow-manager.js';
import { TrainingDataCollector } from './training-data-collector.js';

export class ModelTrainer {
  /**
   * Train the phishing detection model
   */
  static async trainModel(options = {}) {
    const {
      epochs = 50,
      batchSize = 32,
      validationSplit = 0.2,
      learningRate = 0.001
    } = options;
    
    console.log('[Trainer] Starting model training...');
    console.log(`[Trainer] Config: epochs=${epochs}, batchSize=${batchSize}, lr=${learningRate}`);
    
    try {
      // Step 1: Initialize TensorFlow
      await tfManager.initialize();
      
      // Step 2: Load or initialize training data
      let dataResult = await TrainingDataCollector.loadTrainingData();
      if (!dataResult.success) {
        console.log('[Trainer] No training data found, initializing...');
        const initResult = await TrainingDataCollector.initializeTrainingData();
        if (!initResult.success) {
          throw new Error('Failed to initialize training data');
        }
        dataResult = await TrainingDataCollector.loadTrainingData();
      }
      
      const trainingData = dataResult.data;
      console.log(`[Trainer] Loaded ${trainingData.length} training samples`);
      
      // Step 3: Prepare data for training
      const { features, labels } = this.prepareTrainingData(trainingData);
      console.log(`[Trainer] Prepared ${features.length} feature vectors`);
      
      // Step 4: Create or load model
      let modelResult = await tfManager.loadModel();
      if (!modelResult.success) {
        console.log('[Trainer] Creating new model...');
        modelResult = await tfManager.createPhishingModel();
        if (!modelResult.success) {
          throw new Error('Failed to create model');
        }
      }
      
      // Step 5: Train the model
      console.log('[Trainer] Training model...');
      const history = await this.performTraining(
        features,
        labels,
        { epochs, batchSize, validationSplit, learningRate }
      );
      
      // Step 6: Save trained model
      console.log('[Trainer] Saving trained model...');
      await tfManager.saveModel();
      
      // Step 7: Evaluate model
      const evaluation = this.evaluateTraining(history);
      
      console.log('[Trainer] ✓ Training completed successfully');
      console.log(`[Trainer] Final accuracy: ${(evaluation.finalAccuracy * 100).toFixed(2)}%`);
      
      return {
        success: true,
        history: history,
        evaluation: evaluation,
        modelSummary: tfManager.getModelSummary()
      };
      
    } catch (error) {
      console.error('[Trainer] Training failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  /**
   * Prepare training data for TensorFlow
   */
  static prepareTrainingData(trainingData) {
    const features = [];
    const labels = [];
    
    trainingData.forEach(sample => {
      // Extract 20 numerical features
      const featureVector = tfManager.extractMLFeatures({
        features: sample.features,
        baseScore: 0,
        patternScore: 0,
        contextScore: 0
      });
      
      features.push(featureVector);
      labels.push(sample.labelEncoded);
    });
    
    return { features, labels };
  }
  
  /**
   * Perform the actual training
   */
  static async performTraining(features, labels, options) {
    const { epochs, batchSize, validationSplit, learningRate } = options;
    
    // Create tensors
    const xs = tf.tensor2d(features);
    const ys = tf.tensor2d(labels);
    
    // Configure optimizer
    tfManager.model.compile({
      optimizer: tf.train.adam(learningRate),
      loss: 'categoricalCrossentropy',
      metrics: ['accuracy']
    });
    
    // Training history
    const history = {
      loss: [],
      accuracy: [],
      valLoss: [],
      valAccuracy: []
    };
    
    // Train with callbacks
    await tfManager.model.fit(xs, ys, {
      epochs: epochs,
      batchSize: batchSize,
      validationSplit: validationSplit,
      shuffle: true,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          history.loss.push(logs.loss);
          history.accuracy.push(logs.acc);
          if (logs.val_loss) history.valLoss.push(logs.val_loss);
          if (logs.val_acc) history.valAccuracy.push(logs.val_acc);
          
          // Log progress every 10 epochs
          if ((epoch + 1) % 10 === 0) {
            console.log(`[Trainer] Epoch ${epoch + 1}/${epochs}:`);
            console.log(`  Loss: ${logs.loss.toFixed(4)}, Acc: ${(logs.acc * 100).toFixed(2)}%`);
            if (logs.val_loss) {
              console.log(`  Val Loss: ${logs.val_loss.toFixed(4)}, Val Acc: ${(logs.val_acc * 100).toFixed(2)}%`);
            }
          }
        }
      }
    });
    
    // Clean up tensors
    xs.dispose();
    ys.dispose();
    
    return history;
  }
  
  /**
   * Evaluate training results
   */
  static evaluateTraining(history) {
    const finalLoss = history.loss[history.loss.length - 1];
    const finalAccuracy = history.accuracy[history.accuracy.length - 1];
    const finalValLoss = history.valLoss.length > 0 ? 
      history.valLoss[history.valLoss.length - 1] : null;
    const finalValAccuracy = history.valAccuracy.length > 0 ? 
      history.valAccuracy[history.valAccuracy.length - 1] : null;
    
    // Check for overfitting
    const isOverfitting = finalValAccuracy && 
      (finalAccuracy - finalValAccuracy) > 0.15;
    
    // Check if model converged
    const recentLosses = history.loss.slice(-5);
    const lossVariance = this.calculateVariance(recentLosses);
    const hasConverged = lossVariance < 0.001;
    
    return {
      finalLoss,
      finalAccuracy,
      finalValLoss,
      finalValAccuracy,
      isOverfitting,
      hasConverged,
      totalEpochs: history.loss.length
    };
  }
  
  /**
   * Calculate variance of an array
   */
  static calculateVariance(arr) {
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const squaredDiffs = arr.map(x => Math.pow(x - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / arr.length;
  }
  
  /**
   * Test model on test data
   */
  static async testModel(testData) {
    console.log('[Trainer] Testing model...');
    
    const { features, labels } = this.prepareTrainingData(testData);
    
    const xs = tf.tensor2d(features);
    const ys = tf.tensor2d(labels);
    
    const evaluation = tfManager.model.evaluate(xs, ys);
    const loss = await evaluation[0].data();
    const accuracy = await evaluation[1].data();
    
    xs.dispose();
    ys.dispose();
    evaluation[0].dispose();
    evaluation[1].dispose();
    
    console.log(`[Trainer] Test Loss: ${loss[0].toFixed(4)}`);
    console.log(`[Trainer] Test Accuracy: ${(accuracy[0] * 100).toFixed(2)}%`);
    
    return {
      testLoss: loss[0],
      testAccuracy: accuracy[0]
    };
  }
  
  /**
   * Get training recommendations
   */
  static getTrainingRecommendations(evaluation) {
    const recommendations = [];
    
    if (evaluation.isOverfitting) {
      recommendations.push('Model is overfitting. Consider:');
      recommendations.push('  - Adding more training data');
      recommendations.push('  - Increasing dropout rate');
      recommendations.push('  - Reducing model complexity');
    }
    
    if (!evaluation.hasConverged) {
      recommendations.push('Model has not converged. Consider:');
      recommendations.push('  - Training for more epochs');
      recommendations.push('  - Adjusting learning rate');
    }
    
    if (evaluation.finalAccuracy < 0.7) {
      recommendations.push('Low accuracy detected. Consider:');
      recommendations.push('  - Collecting more diverse training data');
      recommendations.push('  - Feature engineering improvements');
      recommendations.push('  - Trying different model architecture');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('✓ Model training looks good!');
      recommendations.push('✓ Ready for production use');
    }
    
    return recommendations;
  }
  
  /**
   * Save training metadata
   */
  static async saveTrainingMetadata(result) {
    try {
      await chrome.storage.local.set({
        modelMetadata: {
          trained: true,
          timestamp: Date.now(),
          accuracy: result.evaluation.finalAccuracy,
          valAccuracy: result.evaluation.finalValAccuracy,
          epochs: result.evaluation.totalEpochs,
          isOverfitting: result.evaluation.isOverfitting,
          hasConverged: result.evaluation.hasConverged
        }
      });
      console.log('[Trainer] Training metadata saved');
      return { success: true };
    } catch (error) {
      console.error('[Trainer] Error saving metadata:', error);
      return { success: false, error: error.message };
    }
  }
  
  /**
   * Get training status
   */
  static async getTrainingStatus() {
    try {
      const result = await chrome.storage.local.get('modelMetadata');
      if (result.modelMetadata) {
        return {
          trained: true,
          ...result.modelMetadata,
          timestamp: new Date(result.modelMetadata.timestamp).toLocaleString()
        };
      }
      return { trained: false };
    } catch (error) {
      return { trained: false, error: error.message };
    }
  }
}
