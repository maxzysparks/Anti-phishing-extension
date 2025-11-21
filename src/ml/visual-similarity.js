/**
 * Visual Similarity Detection
 * Detects logo/brand impersonation using image analysis
 */

export class VisualSimilarity {
  constructor() {
    this.canvas = null;
    this.ctx = null;
    this.knownLogos = new Map();
    this.initialized = false;
  }

  /**
   * Initialize canvas for image processing
   */
  initialize() {
    if (this.initialized) {
      return { success: true };
    }

    try {
      // Create offscreen canvas for image processing
      this.canvas = new OffscreenCanvas(128, 128);
      this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });
      
      // Load known brand logos (simplified hashes)
      this.loadKnownLogos();
      
      this.initialized = true;
      console.log('[Visual] Visual similarity detector initialized');
      
      return { success: true };
    } catch (error) {
      console.error('[Visual] Initialization error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Load known brand logo signatures
   * In production, these would be actual perceptual hashes of brand logos
   */
  loadKnownLogos() {
    // Simplified logo signatures (in production, use actual perceptual hashes)
    this.knownLogos.set('paypal', {
      name: 'PayPal',
      dominantColors: ['#003087', '#009cde', '#012169'],
      aspectRatio: 3.5,
      features: ['blue', 'white', 'text']
    });

    this.knownLogos.set('amazon', {
      name: 'Amazon',
      dominantColors: ['#ff9900', '#146eb4', '#000000'],
      aspectRatio: 3.0,
      features: ['orange', 'arrow', 'smile']
    });

    this.knownLogos.set('microsoft', {
      name: 'Microsoft',
      dominantColors: ['#f25022', '#7fba00', '#00a4ef', '#ffb900'],
      aspectRatio: 1.0,
      features: ['squares', 'colorful', 'grid']
    });

    this.knownLogos.set('apple', {
      name: 'Apple',
      dominantColors: ['#000000', '#555555', '#a6a6a6'],
      aspectRatio: 0.85,
      features: ['apple', 'bite', 'monochrome']
    });

    this.knownLogos.set('google', {
      name: 'Google',
      dominantColors: ['#4285f4', '#ea4335', '#fbbc05', '#34a853'],
      aspectRatio: 4.0,
      features: ['colorful', 'text', 'multicolor']
    });

    console.log('[Visual] Loaded', this.knownLogos.size, 'brand signatures');
  }

  /**
   * Analyze an image for brand logo similarity
   */
  async analyzeImage(imageElement) {
    if (!this.initialized) {
      this.initialize();
    }

    try {
      // Draw image to canvas
      const width = imageElement.naturalWidth || imageElement.width;
      const height = imageElement.naturalHeight || imageElement.height;
      
      if (width === 0 || height === 0) {
        return { error: 'Invalid image dimensions' };
      }

      // Resize to standard size
      this.canvas.width = 128;
      this.canvas.height = 128;
      this.ctx.drawImage(imageElement, 0, 0, 128, 128);

      // Extract features
      const features = this.extractImageFeatures();
      
      // Compare with known logos
      const matches = this.findSimilarLogos(features);

      return {
        features: features,
        matches: matches,
        hasSuspiciousMatch: matches.some(m => m.similarity > 0.7 && m.confidence > 0.6)
      };
    } catch (error) {
      console.error('[Visual] Image analysis error:', error);
      return { error: error.message };
    }
  }

  /**
   * Extract visual features from image
   */
  extractImageFeatures() {
    const imageData = this.ctx.getImageData(0, 0, 128, 128);
    const pixels = imageData.data;

    // Extract dominant colors
    const colorHistogram = this.buildColorHistogram(pixels);
    const dominantColors = this.getDominantColors(colorHistogram, 5);

    // Calculate aspect ratio (simplified)
    const aspectRatio = 1.0; // Would need original dimensions

    // Detect edges (simplified Sobel operator)
    const edgeStrength = this.detectEdges(pixels, 128, 128);

    // Calculate color variance
    const colorVariance = this.calculateColorVariance(pixels);

    // Detect text regions (simplified)
    const hasText = this.detectTextRegions(pixels, 128, 128);

    return {
      dominantColors: dominantColors,
      aspectRatio: aspectRatio,
      edgeStrength: edgeStrength,
      colorVariance: colorVariance,
      hasText: hasText,
      brightness: this.calculateBrightness(pixels),
      contrast: this.calculateContrast(pixels)
    };
  }

  /**
   * Build color histogram
   */
  buildColorHistogram(pixels) {
    const histogram = {};
    
    for (let i = 0; i < pixels.length; i += 4) {
      const r = Math.floor(pixels[i] / 32) * 32;
      const g = Math.floor(pixels[i + 1] / 32) * 32;
      const b = Math.floor(pixels[i + 2] / 32) * 32;
      
      const color = `${r},${g},${b}`;
      histogram[color] = (histogram[color] || 0) + 1;
    }
    
    return histogram;
  }

  /**
   * Get dominant colors from histogram
   */
  getDominantColors(histogram, count) {
    const sorted = Object.entries(histogram)
      .sort((a, b) => b[1] - a[1])
      .slice(0, count);
    
    return sorted.map(([color, freq]) => {
      const [r, g, b] = color.split(',').map(Number);
      return this.rgbToHex(r, g, b);
    });
  }

  /**
   * Convert RGB to hex color
   */
  rgbToHex(r, g, b) {
    return '#' + [r, g, b].map(x => {
      const hex = x.toString(16);
      return hex.length === 1 ? '0' + hex : hex;
    }).join('');
  }

  /**
   * Detect edges using simplified Sobel operator
   */
  detectEdges(pixels, width, height) {
    let edgeSum = 0;
    let edgeCount = 0;

    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        
        // Get grayscale value
        const gray = (pixels[idx] + pixels[idx + 1] + pixels[idx + 2]) / 3;
        
        // Simple edge detection (compare with neighbors)
        const right = (pixels[idx + 4] + pixels[idx + 5] + pixels[idx + 6]) / 3;
        const bottom = (pixels[idx + width * 4] + pixels[idx + width * 4 + 1] + pixels[idx + width * 4 + 2]) / 3;
        
        const edgeStrength = Math.abs(gray - right) + Math.abs(gray - bottom);
        edgeSum += edgeStrength;
        edgeCount++;
      }
    }

    return edgeCount > 0 ? edgeSum / edgeCount : 0;
  }

  /**
   * Calculate color variance
   */
  calculateColorVariance(pixels) {
    let rSum = 0, gSum = 0, bSum = 0;
    const count = pixels.length / 4;

    // Calculate means
    for (let i = 0; i < pixels.length; i += 4) {
      rSum += pixels[i];
      gSum += pixels[i + 1];
      bSum += pixels[i + 2];
    }

    const rMean = rSum / count;
    const gMean = gSum / count;
    const bMean = bSum / count;

    // Calculate variance
    let variance = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      variance += Math.pow(pixels[i] - rMean, 2);
      variance += Math.pow(pixels[i + 1] - gMean, 2);
      variance += Math.pow(pixels[i + 2] - bMean, 2);
    }

    return variance / (count * 3);
  }

  /**
   * Detect text regions (simplified)
   */
  detectTextRegions(pixels, width, height) {
    // Look for high-contrast horizontal patterns typical of text
    let textScore = 0;

    for (let y = 0; y < height - 1; y++) {
      let rowChanges = 0;
      for (let x = 0; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        const gray = (pixels[idx] + pixels[idx + 1] + pixels[idx + 2]) / 3;
        const nextGray = (pixels[idx + 4] + pixels[idx + 5] + pixels[idx + 6]) / 3;
        
        if (Math.abs(gray - nextGray) > 50) {
          rowChanges++;
        }
      }
      
      // Text typically has multiple transitions per row
      if (rowChanges > width * 0.1) {
        textScore++;
      }
    }

    return textScore > height * 0.3;
  }

  /**
   * Calculate average brightness
   */
  calculateBrightness(pixels) {
    let sum = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      sum += (pixels[i] + pixels[i + 1] + pixels[i + 2]) / 3;
    }
    return sum / (pixels.length / 4);
  }

  /**
   * Calculate contrast
   */
  calculateContrast(pixels) {
    let min = 255, max = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      const gray = (pixels[i] + pixels[i + 1] + pixels[i + 2]) / 3;
      min = Math.min(min, gray);
      max = Math.max(max, gray);
    }
    return max - min;
  }

  /**
   * Find similar logos from known brands
   */
  findSimilarLogos(features) {
    const matches = [];

    for (const [key, logo] of this.knownLogos) {
      const similarity = this.calculateLogoSimilarity(features, logo);
      
      if (similarity.score > 0.5) {
        matches.push({
          brand: logo.name,
          similarity: similarity.score,
          confidence: similarity.confidence,
          matchedFeatures: similarity.matchedFeatures
        });
      }
    }

    // Sort by similarity
    matches.sort((a, b) => b.similarity - a.similarity);

    return matches;
  }

  /**
   * Calculate similarity between extracted features and known logo
   */
  calculateLogoSimilarity(features, logo) {
    let score = 0;
    let confidence = 0;
    const matchedFeatures = [];

    // Compare dominant colors
    const colorMatch = this.compareColors(features.dominantColors, logo.dominantColors);
    score += colorMatch * 0.4;
    if (colorMatch > 0.6) {
      matchedFeatures.push('color_match');
      confidence += 0.3;
    }

    // Compare aspect ratio
    const aspectMatch = 1 - Math.abs(features.aspectRatio - logo.aspectRatio) / Math.max(features.aspectRatio, logo.aspectRatio);
    score += aspectMatch * 0.2;
    if (aspectMatch > 0.8) {
      matchedFeatures.push('aspect_ratio');
      confidence += 0.2;
    }

    // Check for text presence
    if (features.hasText && logo.features.includes('text')) {
      score += 0.2;
      matchedFeatures.push('text_present');
      confidence += 0.2;
    }

    // Edge strength (logos typically have strong edges)
    if (features.edgeStrength > 20) {
      score += 0.1;
      confidence += 0.1;
    }

    // Color variance (logos typically have distinct colors)
    if (features.colorVariance > 1000) {
      score += 0.1;
      confidence += 0.1;
    }

    return {
      score: Math.min(score, 1.0),
      confidence: Math.min(confidence, 1.0),
      matchedFeatures: matchedFeatures
    };
  }

  /**
   * Compare two color arrays
   */
  compareColors(colors1, colors2) {
    if (!colors1 || !colors2 || colors1.length === 0 || colors2.length === 0) {
      return 0;
    }

    let matches = 0;
    const threshold = 50; // Color difference threshold

    for (const color1 of colors1) {
      for (const color2 of colors2) {
        const diff = this.colorDistance(color1, color2);
        if (diff < threshold) {
          matches++;
          break;
        }
      }
    }

    return matches / Math.max(colors1.length, colors2.length);
  }

  /**
   * Calculate color distance (simplified)
   */
  colorDistance(hex1, hex2) {
    const rgb1 = this.hexToRgb(hex1);
    const rgb2 = this.hexToRgb(hex2);

    if (!rgb1 || !rgb2) return 255;

    return Math.sqrt(
      Math.pow(rgb1.r - rgb2.r, 2) +
      Math.pow(rgb1.g - rgb2.g, 2) +
      Math.pow(rgb1.b - rgb2.b, 2)
    );
  }

  /**
   * Convert hex to RGB
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
   * Scan page for suspicious images
   */
  async scanPageImages(document) {
    if (!this.initialized) {
      this.initialize();
    }

    const results = [];
    const images = document.querySelectorAll('img');

    console.log('[Visual] Scanning', images.length, 'images');

    for (const img of images) {
      // Skip very small images (likely icons)
      if (img.width < 50 || img.height < 50) {
        continue;
      }

      // Skip images that haven't loaded
      if (!img.complete) {
        continue;
      }

      try {
        const analysis = await this.analyzeImage(img);
        
        if (analysis.hasSuspiciousMatch) {
          results.push({
            element: img,
            src: img.src,
            alt: img.alt,
            analysis: analysis
          });
        }
      } catch (error) {
        console.error('[Visual] Error analyzing image:', error);
      }
    }

    return results;
  }

  /**
   * Dispose resources
   */
  dispose() {
    this.canvas = null;
    this.ctx = null;
    this.initialized = false;
  }
}

// Singleton instance
export const visualSimilarity = new VisualSimilarity();
