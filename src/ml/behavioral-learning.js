/**
 * Behavioral Learning System
 * Learns from user feedback and adapts detection over time
 */

import { tfManager } from './tensorflow-manager.js';
import { StorageManager } from '../utils/storage.js';

export class BehavioralLearning {
  constructor() {
    this.feedbackQueue = [];
    this.trainingScheduled = false;
    this.minFeedbackForTraining = 20;
    this.lastTrainingTime = 0;
    this.trainingInterval = 3600000; // 1 hour
  }

  /**
   * Record user feedback on a URL classification
   */
  async recordFeedback(url, predictedThreat, userAction, actualThreat = null) {
    try {
      const feedback = {
        url: url,
        predictedThreat: predictedThreat,
        userAction: userAction, // 'whitelist', 'blacklist', 'report', 'ignore'
        actualThreat: actualThreat || this.inferThreatFromAction(userAction),
        timestamp: Date.now(),
        features: null // Will be populated later
      };

      // Store feedback
      const stored = await chrome.storage.local.get('behavioralFeedback');
      const feedbackList = stored.behavioralFeedback || [];
      
      feedbackList.push(feedback);
      
      // Keep last 1000 feedback items
      if (feedbackList.length > 1000) {
        feedbackList.shift();
      }
      
      await chrome.storage.local.set({ behavioralFeedback: feedbackList });
      
      console.log('[Behavioral] Feedback recorded:', feedback);

      // Add to training queue
      this.feedbackQueue.push(feedback);

      // Schedule training if enough feedback accumulated
      if (this.feedbackQueue.length >= this.minFeedbackForTraining) {
        this.scheduleTraining();
      }

      return { success: true };
    } catch (error) {
      console.error('[Behavioral] Error recording feedback:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Infer actual threat level from user action
   */
  inferThreatFromAction(action) {
    switch (action) {
      case 'whitelist':
        return 'SAFE';
      case 'blacklist':
      case 'report':
        return 'DANGEROUS';
      case 'ignore':
        return 'SUSPICIOUS';
      default:
        return 'UNKNOWN';
    }
  }

  /**
   * Schedule model training
   */
  scheduleTraining() {
    if (this.trainingScheduled) {
      return;
    }

    const timeSinceLastTraining = Date.now() - this.lastTrainingTime;
    if (timeSinceLastTraining < this.trainingInterval) {
      console.log('[Behavioral] Training scheduled too soon, waiting...');
      return;
    }

    this.trainingScheduled = true;
    console.log('[Behavioral] Training scheduled with', this.feedbackQueue.length, 'samples');

    // Train after a short delay to batch multiple feedbacks
    setTimeout(() => {
      this.trainModel();
    }, 5000);
  }

  /**
   * Train the model with accumulated feedback
   */
  async trainModel() {
    try {
      console.log('[Behavioral] Starting model training...');

      // Get all feedback
      const stored = await chrome.storage.local.get('behavioralFeedback');
      const feedbackList = stored.behavioralFeedback || [];

      if (feedbackList.length < this.minFeedbackForTraining) {
        console.log('[Behavioral] Not enough feedback for training');
        this.trainingScheduled = false;
        return;
      }

      // Filter valid feedback (with actual threat labels)
      const validFeedback = feedbackList.filter(f => 
        f.actualThreat && f.actualThreat !== 'UNKNOWN'
      );

      if (validFeedback.length < 10) {
        console.log('[Behavioral] Not enough valid feedback for training');
        this.trainingScheduled = false;
        return;
      }

      // Train TensorFlow model
      const result = await tfManager.trainWithFeedback(validFeedback);

      if (result.success) {
        console.log('[Behavioral] Training completed successfully');
        
        // Save the trained model
        await tfManager.saveModel();
        
        // Update training time
        this.lastTrainingTime = Date.now();
        
        // Clear training queue
        this.feedbackQueue = [];
        
        // Update statistics
        await this.updateLearningStats(validFeedback.length);
      } else {
        console.error('[Behavioral] Training failed:', result.error);
      }

      this.trainingScheduled = false;
    } catch (error) {
      console.error('[Behavioral] Training error:', error);
      this.trainingScheduled = false;
    }
  }

  /**
   * Update learning statistics
   */
  async updateLearningStats(samplesUsed) {
    try {
      const stored = await chrome.storage.local.get('learningStats');
      const stats = stored.learningStats || {
        totalTrainingSessions: 0,
        totalSamplesUsed: 0,
        lastTrainingDate: null,
        modelVersion: 1
      };

      stats.totalTrainingSessions++;
      stats.totalSamplesUsed += samplesUsed;
      stats.lastTrainingDate = new Date().toISOString();
      stats.modelVersion++;

      await chrome.storage.local.set({ learningStats: stats });
      
      console.log('[Behavioral] Learning stats updated:', stats);
    } catch (error) {
      console.error('[Behavioral] Error updating stats:', error);
    }
  }

  /**
   * Get learning statistics
   */
  async getLearningStats() {
    try {
      const stored = await chrome.storage.local.get(['learningStats', 'behavioralFeedback']);
      const stats = stored.learningStats || {
        totalTrainingSessions: 0,
        totalSamplesUsed: 0,
        lastTrainingDate: null,
        modelVersion: 1
      };

      const feedbackList = stored.behavioralFeedback || [];
      
      // Calculate feedback distribution
      const distribution = {
        safe: feedbackList.filter(f => f.actualThreat === 'SAFE').length,
        suspicious: feedbackList.filter(f => f.actualThreat === 'SUSPICIOUS').length,
        dangerous: feedbackList.filter(f => f.actualThreat === 'DANGEROUS').length,
        unknown: feedbackList.filter(f => !f.actualThreat || f.actualThreat === 'UNKNOWN').length
      };

      return {
        ...stats,
        totalFeedback: feedbackList.length,
        feedbackDistribution: distribution,
        queuedForTraining: this.feedbackQueue.length,
        trainingScheduled: this.trainingScheduled
      };
    } catch (error) {
      console.error('[Behavioral] Error getting stats:', error);
      return null;
    }
  }

  /**
   * Analyze user behavior patterns
   */
  async analyzeUserBehavior() {
    try {
      const stored = await chrome.storage.local.get('behavioralFeedback');
      const feedbackList = stored.behavioralFeedback || [];

      if (feedbackList.length === 0) {
        return {
          hasData: false,
          message: 'No behavioral data available'
        };
      }

      // Analyze action patterns
      const actions = {
        whitelist: feedbackList.filter(f => f.userAction === 'whitelist').length,
        blacklist: feedbackList.filter(f => f.userAction === 'blacklist').length,
        report: feedbackList.filter(f => f.userAction === 'report').length,
        ignore: feedbackList.filter(f => f.userAction === 'ignore').length
      };

      // Calculate accuracy (when prediction matches user action)
      const accurateCount = feedbackList.filter(f => {
        const predicted = f.predictedThreat;
        const actual = f.actualThreat;
        
        if (predicted === 'DANGEROUS' && actual === 'DANGEROUS') return true;
        if (predicted === 'SAFE' && actual === 'SAFE') return true;
        if (predicted === 'SUSPICIOUS' && actual === 'SUSPICIOUS') return true;
        
        return false;
      }).length;

      const accuracy = feedbackList.length > 0 
        ? (accurateCount / feedbackList.length * 100).toFixed(1)
        : 0;

      // Analyze time patterns
      const recentFeedback = feedbackList.filter(f => 
        Date.now() - f.timestamp < 7 * 24 * 60 * 60 * 1000 // Last 7 days
      );

      return {
        hasData: true,
        totalActions: feedbackList.length,
        actionDistribution: actions,
        accuracy: parseFloat(accuracy),
        recentActivity: recentFeedback.length,
        mostCommonAction: Object.keys(actions).reduce((a, b) => 
          actions[a] > actions[b] ? a : b
        ),
        userTrust: this.calculateUserTrust(actions, accuracy)
      };
    } catch (error) {
      console.error('[Behavioral] Error analyzing behavior:', error);
      return null;
    }
  }

  /**
   * Calculate user trust level based on behavior
   */
  calculateUserTrust(actions, accuracy) {
    // High trust: User frequently whitelists and model is accurate
    // Low trust: User frequently blacklists or reports
    
    const totalActions = Object.values(actions).reduce((a, b) => a + b, 0);
    if (totalActions === 0) return 'unknown';

    const whitelistRatio = actions.whitelist / totalActions;
    const blacklistRatio = (actions.blacklist + actions.report) / totalActions;

    if (accuracy > 80 && whitelistRatio > 0.5) {
      return 'high';
    } else if (accuracy > 60 && blacklistRatio < 0.3) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Get personalized recommendations based on user behavior
   */
  async getPersonalizedRecommendations() {
    const behavior = await this.analyzeUserBehavior();
    
    if (!behavior || !behavior.hasData) {
      return {
        recommendations: [
          'Start using the extension to build your behavioral profile',
          'Provide feedback on detected threats to improve accuracy'
        ]
      };
    }

    const recommendations = [];

    // Based on accuracy
    if (behavior.accuracy < 60) {
      recommendations.push('Model accuracy is low. Continue providing feedback to improve detection.');
    } else if (behavior.accuracy > 80) {
      recommendations.push('Great! Model is performing well based on your feedback.');
    }

    // Based on user trust
    if (behavior.userTrust === 'low') {
      recommendations.push('Consider reviewing your whitelist/blacklist settings.');
      recommendations.push('The model may need more training data from your feedback.');
    }

    // Based on recent activity
    if (behavior.recentActivity < 5) {
      recommendations.push('More recent activity will help keep the model up-to-date.');
    }

    // Based on action distribution
    if (behavior.actionDistribution.ignore > behavior.totalActions * 0.5) {
      recommendations.push('You frequently ignore warnings. Consider adjusting sensitivity settings.');
    }

    return {
      recommendations: recommendations,
      userProfile: {
        trustLevel: behavior.userTrust,
        accuracy: behavior.accuracy,
        activityLevel: behavior.recentActivity > 10 ? 'high' : 
                       behavior.recentActivity > 5 ? 'medium' : 'low'
      }
    };
  }

  /**
   * Export behavioral data for analysis
   */
  async exportBehavioralData() {
    try {
      const stored = await chrome.storage.local.get(['behavioralFeedback', 'learningStats']);
      
      return {
        feedback: stored.behavioralFeedback || [],
        stats: stored.learningStats || {},
        exportDate: new Date().toISOString()
      };
    } catch (error) {
      console.error('[Behavioral] Error exporting data:', error);
      return null;
    }
  }

  /**
   * Clear all behavioral data
   */
  async clearBehavioralData() {
    try {
      await chrome.storage.local.remove(['behavioralFeedback', 'learningStats']);
      this.feedbackQueue = [];
      this.lastTrainingTime = 0;
      
      console.log('[Behavioral] All behavioral data cleared');
      return { success: true };
    } catch (error) {
      console.error('[Behavioral] Error clearing data:', error);
      return { success: false, error: error.message };
    }
  }
}

// Singleton instance
export const behavioralLearning = new BehavioralLearning();
