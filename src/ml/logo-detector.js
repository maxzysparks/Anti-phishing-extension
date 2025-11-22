/**
 * Computer Vision for Logo and Brand Detection
 * Uses TensorFlow.js with MobileNet for visual similarity and logo recognition
 */

import * as tf from '@tensorflow/tfjs';

/**
 * Logo Detector using Computer Vision
 */
export class LogoDetector {
  constructor() {
    this.model = null;
    this.initialized = false;
    this.modelType = 'mobilenet'; // or 'efficientnet'
    
    // Known brand logos database (in production, this would be much larger)
    this.knownLogos = {
      'paypal': {
        colors: ['#003087', '#009cde', '#012169'],
        features: ['blue', 'white', 'paypal text']
      },
      'amazon': {
        colors: ['#ff9900', '#146eb4', '#000000'],
        features: ['orange arrow', 'smile', 'amazon text']
      },
      'microsoft': {
        colors: ['#f25022', '#7fba00', '#00a4ef', '#ffb900'],
        features: ['four squares', 'windows logo']
      },
      'apple': {
        colors: ['#000000', '#ffffff', '#a6a6a6'],
        features: ['apple shape', 'bite mark']
      },
      'google': {
        colors: ['#4285f4', '#ea4335', '#fbbc05', '#34a853'],
        features: ['multicolor', 'google text']
      }
    };
  }

  /**
   * Initialize the logo detection model
   */
  async initialize() {
    try {
      console.log('[Logo Detector] Initializing...');
      
      // Load MobileNet model for feature extraction
      // In production, you would load a custom-trained logo detection model
      try {
        this.model = await tf.loadLayersModel('https://storage.googleapis.com/tfjs-models/tfjs/mobilenet_v1_0.25_224/model.json');
        console.log('[Logo Detector] MobileNet model loaded');
      } catch (error) {
        console.warn('[Logo Detector] Could not load MobileNet, using fallback detection');
        this.model = null;
      }
      
      this.initialized = true;
      console.log('[Logo Detector] Initialized successfully');
      
      return { success: true };
    } catch (error) {
      console.error('[Logo Detector] Initialization failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Analyze image for logo detection
   * @param {string|HTMLImageElement} imageSource - Image URL or element
   * @returns {Promise<Object>} Detection results
   */
  async detectLogo(imageSource) {
    try {
      // Load image
      const img = await this.loadImage(imageSource);
      
      // Extract features
      const features = await this.extractFeatures(img);
      
      // Detect logos
      const detectedLogos = await this.matchLogos(features);
      
      // Analyze for impersonation
      const impersonation = this.analyzeImpersonation(detectedLogos, features);
      
      return {
        success: true,
        detectedLogos: detectedLogos,
        impersonation: impersonation,
        confidence: this.calculateConfidence(detectedLogos),
        features: features
      };
      
    } catch (error) {
      console.error('[Logo Detector] Detection error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Load image from URL or element
   * @param {string|HTMLImageElement} source - Image source
   * @returns {Promise<HTMLImageElement>} Loaded image
   */
  async loadImage(source) {
    if (source instanceof HTMLImageElement) {
      return source;
    }
    
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('Failed to load image'));
      
      img.src = source;
    });
  }

  /**
   * Extract visual features from image
   * @param {HTMLImageElement} img - Image element
   * @returns {Promise<Object>} Extracted features
   */
  async extractFeatures(img) {
    const features = {
      colors: [],
      dominantColors: [],
      brightness: 0,
      contrast: 0,
      hasText: false,
      textRegions: [],
      shapes: []
    };

    try {
      // Create canvas for image processing
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      
      // Extract color information
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const colorAnalysis = this.analyzeColors(imageData);
      
      features.colors = colorAnalysis.colors;
      features.dominantColors = colorAnalysis.dominant;
      features.brightness = colorAnalysis.brightness;
      features.contrast = colorAnalysis.contrast;
      
      // Detect text regions (simplified OCR)
      features.textRegions = this.detectTextRegions(imageData);
      features.hasText = features.textRegions.length > 0;
      
      // Detect basic shapes
      features.shapes = this.detectShapes(imageData);
      
      // If model is loaded, extract deep features
      if (this.model) {
        const tensor = tf.browser.fromPixels(img)
          .resizeBilinear([224, 224])
          .expandDims(0)
          .toFloat()
          .div(255.0);
        
        const predictions = await this.model.predict(tensor);
        features.deepFeatures = await predictions.data();
        
        tensor.dispose();
        predictions.dispose();
      }
      
    } catch (error) {
      console.error('[Logo Detector] Feature extraction error:', error);
    }
    
    return features;
  }

  /**
   * Analyze colors in image
   * @param {ImageData} imageData - Image data
   * @returns {Object} Color analysis
   */
  analyzeColors(imageData) {
    const data = imageData.data;
    const colorMap = new Map();
    let totalBrightness = 0;
    let minBrightness = 255;
    let maxBrightness = 0;
    
    // Sample pixels (every 10th pixel for performance)
    for (let i = 0; i < data.length; i += 40) {
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      
      // Calculate brightness
      const brightness = (r + g + b) / 3;
      totalBrightness += brightness;
      minBrightness = Math.min(minBrightness, brightness);
      maxBrightness = Math.max(maxBrightness, brightness);
      
      // Store color
      const colorKey = `${Math.floor(r/32)},${Math.floor(g/32)},${Math.floor(b/32)}`;
      colorMap.set(colorKey, (colorMap.get(colorKey) || 0) + 1);
    }
    
    // Get dominant colors
    const sortedColors = Array.from(colorMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([key]) => {
        const [r, g, b] = key.split(',').map(v => parseInt(v) * 32);
        return this.rgbToHex(r, g, b);
      });
    
    const avgBrightness = totalBrightness / (data.length / 4);
    const contrast = maxBrightness - minBrightness;
    
    return {
      colors: Array.from(colorMap.keys()).map(key => {
        const [r, g, b] = key.split(',').map(v => parseInt(v) * 32);
        return this.rgbToHex(r, g, b);
      }),
      dominant: sortedColors,
      brightness: avgBrightness / 255,
      contrast: contrast / 255
    };
  }

  /**
   * Convert RGB to hex color
   * @param {number} r - Red value
   * @param {number} g - Green value
   * @param {number} b - Blue value
   * @returns {string} Hex color
   */
  rgbToHex(r, g, b) {
    return '#' + [r, g, b].map(x => {
      const hex = x.toString(16);
      return hex.length === 1 ? '0' + hex : hex;
    }).join('');
  }

  /**
   * Detect text regions in image (simplified)
   * @param {ImageData} imageData - Image data
   * @returns {Array} Text regions
   */
  detectTextRegions(imageData) {
    // Simplified text detection
    // In production, use Tesseract.js or similar OCR library
    const regions = [];
    
    // Look for high contrast regions that might contain text
    const data = imageData.data;
    const width = imageData.width;
    const height = imageData.height;
    
    // Sample grid
    const gridSize = 20;
    for (let y = 0; y < height; y += gridSize) {
      for (let x = 0; x < width; x += gridSize) {
        const idx = (y * width + x) * 4;
        const brightness = (data[idx] + data[idx + 1] + data[idx + 2]) / 3;
        
        // Check surrounding pixels for contrast
        let contrastSum = 0;
        let samples = 0;
        
        for (let dy = -5; dy <= 5; dy += 5) {
          for (let dx = -5; dx <= 5; dx += 5) {
            const nx = x + dx;
            const ny = y + dy;
            if (nx >= 0 && nx < width && ny >= 0 && ny < height) {
              const nidx = (ny * width + nx) * 4;
              const nbrightness = (data[nidx] + data[nidx + 1] + data[nidx + 2]) / 3;
              contrastSum += Math.abs(brightness - nbrightness);
              samples++;
            }
          }
        }
        
        const avgContrast = contrastSum / samples;
        if (avgContrast > 50) {
          regions.push({ x, y, width: gridSize, height: gridSize, contrast: avgContrast });
        }
      }
    }
    
    return regions;
  }

  /**
   * Detect basic shapes in image
   * @param {ImageData} imageData - Image data
   * @returns {Array} Detected shapes
   */
  detectShapes(imageData) {
    // Simplified shape detection
    // In production, use more sophisticated edge detection and shape recognition
    const shapes = [];
    
    // Look for rectangular regions (common in logos)
    const textRegions = this.detectTextRegions(imageData);
    
    if (textRegions.length > 0) {
      shapes.push({ type: 'rectangle', count: textRegions.length });
    }
    
    return shapes;
  }

  /**
   * Match extracted features against known logos
   * @param {Object} features - Extracted features
   * @returns {Promise<Array>} Matched logos
   */
  async matchLogos(features) {
    const matches = [];
    
    for (const [brand, logoData] of Object.entries(this.knownLogos)) {
      const similarity = this.calculateSimilarity(features, logoData);
      
      if (similarity > 0.5) {
        matches.push({
          brand: brand,
          similarity: similarity,
          confidence: similarity,
          matchedFeatures: this.getMatchedFeatures(features, logoData)
        });
      }
    }
    
    // Sort by similarity
    matches.sort((a, b) => b.similarity - a.similarity);
    
    return matches;
  }

  /**
   * Calculate similarity between features and known logo
   * @param {Object} features - Extracted features
   * @param {Object} logoData - Known logo data
   * @returns {number} Similarity score (0 to 1)
   */
  calculateSimilarity(features, logoData) {
    let score = 0;
    let factors = 0;
    
    // Color similarity
    if (features.dominantColors && logoData.colors) {
      const colorMatch = this.compareColors(features.dominantColors, logoData.colors);
      score += colorMatch * 0.6;
      factors += 0.6;
    }
    
    // Feature similarity (if deep features available)
    if (features.deepFeatures && logoData.deepFeatures) {
      const featureMatch = this.compareFeatures(features.deepFeatures, logoData.deepFeatures);
      score += featureMatch * 0.4;
      factors += 0.4;
    }
    
    return factors > 0 ? score / factors : 0;
  }

  /**
   * Compare color palettes
   * @param {Array} colors1 - First color palette
   * @param {Array} colors2 - Second color palette
   * @returns {number} Similarity score (0 to 1)
   */
  compareColors(colors1, colors2) {
    let matches = 0;
    
    for (const color1 of colors1) {
      for (const color2 of colors2) {
        if (this.colorDistance(color1, color2) < 50) {
          matches++;
          break;
        }
      }
    }
    
    return matches / Math.max(colors1.length, colors2.length);
  }

  /**
   * Calculate color distance
   * @param {string} color1 - First color (hex)
   * @param {string} color2 - Second color (hex)
   * @returns {number} Distance
   */
  colorDistance(color1, color2) {
    const rgb1 = this.hexToRgb(color1);
    const rgb2 = this.hexToRgb(color2);
    
    if (!rgb1 || !rgb2) return 255;
    
    return Math.sqrt(
      Math.pow(rgb1.r - rgb2.r, 2) +
      Math.pow(rgb1.g - rgb2.g, 2) +
      Math.pow(rgb1.b - rgb2.b, 2)
    );
  }

  /**
   * Convert hex to RGB
   * @param {string} hex - Hex color
   * @returns {Object} RGB values
   */
  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }

  /**
   * Compare deep features
   * @param {Array} features1 - First feature vector
   * @param {Array} features2 - Second feature vector
   * @returns {number} Similarity score (0 to 1)
   */
  compareFeatures(features1, features2) {
    // Cosine similarity
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;
    
    const length = Math.min(features1.length, features2.length);
    
    for (let i = 0; i < length; i++) {
      dotProduct += features1[i] * features2[i];
      norm1 += features1[i] * features1[i];
      norm2 += features2[i] * features2[i];
    }
    
    norm1 = Math.sqrt(norm1);
    norm2 = Math.sqrt(norm2);
    
    if (norm1 === 0 || norm2 === 0) return 0;
    
    return dotProduct / (norm1 * norm2);
  }

  /**
   * Get matched features
   * @param {Object} features - Extracted features
   * @param {Object} logoData - Known logo data
   * @returns {Array} Matched features
   */
  getMatchedFeatures(features, logoData) {
    const matched = [];
    
    // Check color matches
    if (features.dominantColors && logoData.colors) {
      for (const color of features.dominantColors) {
        for (const logoColor of logoData.colors) {
          if (this.colorDistance(color, logoColor) < 50) {
            matched.push(`Color match: ${color}`);
            break;
          }
        }
      }
    }
    
    return matched;
  }

  /**
   * Analyze for logo impersonation
   * @param {Array} detectedLogos - Detected logos
   * @param {Object} features - Image features
   * @returns {Object} Impersonation analysis
   */
  analyzeImpersonation(detectedLogos, features) {
    if (detectedLogos.length === 0) {
      return {
        detected: false,
        risk: 'low',
        score: 0
      };
    }
    
    // Check for low-quality reproductions
    const topMatch = detectedLogos[0];
    let riskScore = 0;
    const indicators = [];
    
    // Low similarity but still matched
    if (topMatch.similarity < 0.7 && topMatch.similarity > 0.5) {
      riskScore += 0.3;
      indicators.push('Low-quality logo reproduction');
    }
    
    // Poor image quality
    if (features.contrast < 0.3) {
      riskScore += 0.2;
      indicators.push('Poor image quality');
    }
    
    // Multiple brand logos detected (suspicious)
    if (detectedLogos.length > 2) {
      riskScore += 0.3;
      indicators.push('Multiple brand logos detected');
    }
    
    // Unusual colors for the brand
    if (topMatch.matchedFeatures.length < 2) {
      riskScore += 0.2;
      indicators.push('Unusual color scheme for brand');
    }
    
    return {
      detected: riskScore > 0.4,
      risk: riskScore > 0.6 ? 'high' : riskScore > 0.3 ? 'medium' : 'low',
      score: Math.min(1, riskScore),
      indicators: indicators,
      suspectedBrand: topMatch.brand
    };
  }

  /**
   * Calculate overall confidence
   * @param {Array} detectedLogos - Detected logos
   * @returns {number} Confidence score (0 to 1)
   */
  calculateConfidence(detectedLogos) {
    if (detectedLogos.length === 0) return 0;
    
    const topMatch = detectedLogos[0];
    return topMatch.similarity;
  }

  /**
   * Analyze screenshot for phishing indicators
   * @param {string} screenshotUrl - Screenshot URL
   * @param {string} expectedDomain - Expected domain
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeScreenshot(screenshotUrl, expectedDomain) {
    try {
      const logoDetection = await this.detectLogo(screenshotUrl);
      
      if (!logoDetection.success) {
        return logoDetection;
      }
      
      // Check if detected logos match expected domain
      const domainMismatch = this.checkDomainMismatch(
        logoDetection.detectedLogos,
        expectedDomain
      );
      
      return {
        success: true,
        logoDetection: logoDetection,
        domainMismatch: domainMismatch,
        overallRisk: this.calculateOverallRisk(logoDetection, domainMismatch)
      };
      
    } catch (error) {
      console.error('[Logo Detector] Screenshot analysis error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Check for domain mismatch
   * @param {Array} detectedLogos - Detected logos
   * @param {string} domain - Current domain
   * @returns {Object} Mismatch analysis
   */
  checkDomainMismatch(detectedLogos, domain) {
    if (detectedLogos.length === 0) {
      return { detected: false, risk: 'low' };
    }
    
    const domainLower = domain.toLowerCase();
    const topBrand = detectedLogos[0].brand.toLowerCase();
    
    // Check if domain matches detected brand
    const matches = domainLower.includes(topBrand) || topBrand.includes(domainLower);
    
    if (!matches) {
      return {
        detected: true,
        risk: 'high',
        message: `${detectedLogos[0].brand} logo detected on ${domain}`,
        suspectedBrand: detectedLogos[0].brand,
        actualDomain: domain
      };
    }
    
    return { detected: false, risk: 'low' };
  }

  /**
   * Calculate overall risk
   * @param {Object} logoDetection - Logo detection results
   * @param {Object} domainMismatch - Domain mismatch results
   * @returns {Object} Overall risk assessment
   */
  calculateOverallRisk(logoDetection, domainMismatch) {
    let riskScore = 0;
    
    if (logoDetection.impersonation.detected) {
      riskScore += logoDetection.impersonation.score * 0.5;
    }
    
    if (domainMismatch.detected) {
      riskScore += 0.5;
    }
    
    return {
      score: Math.min(1, riskScore),
      level: riskScore > 0.7 ? 'critical' : riskScore > 0.4 ? 'high' : riskScore > 0.2 ? 'medium' : 'low',
      phishingLikely: riskScore > 0.5
    };
  }
}

// Create singleton instance
export const logoDetector = new LogoDetector();

export default logoDetector;
