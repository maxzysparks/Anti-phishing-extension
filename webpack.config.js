const path = require('path');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    background: './src/background/service-worker.js',
    content: './src/content/content-script.js',
    popup: './src/popup/popup.js',
    'phishtank-worker': './src/workers/phishtank-worker.js'
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
    // IMPORTANT: Service workers need IIFE format, not modules
    environment: {
      module: false
    }
  },
  // Ensure proper module resolution
  resolve: {
    extensions: ['.js'],
    fallback: {
      // TensorFlow.js polyfills for browser environment
      'crypto': false,
      'stream': false,
      'util': false,
      'buffer': false,
      'process': false
    }
  },
  // Optimize for Chrome extension service workers
  optimization: {
    minimize: true,
    // Split chunks to reduce bundle size
    // IMPORTANT: Exclude background service worker from code splitting
    splitChunks: {
      chunks(chunk) {
        // Don't split the background service worker
        return chunk.name !== 'background';
      },
      cacheGroups: {
        tensorflow: {
          test: /[\\/]node_modules[\\/]@tensorflow[\\/]/,
          name: 'tensorflow',
          priority: 20
        },
        vendors: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          priority: 10
        }
      }
    }
  },
  performance: {
    hints: false,
    maxEntrypointSize: 2000000,
    maxAssetSize: 2000000
  },
  // Module rules for TensorFlow.js
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
            plugins: ['@babel/plugin-transform-runtime']
          }
        }
      }
    ]
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        { from: 'public', to: '.' },
        { from: 'src/popup/popup.html', to: 'popup.html' },
        { from: 'src/popup/popup.css', to: 'popup.css' },
        { from: 'src/content/content.css', to: 'content.css' },
        { from: 'src/workers', to: 'workers' }
      ]
    })
  ],
  mode: 'production',
  // Ensure compatibility with Chrome extensions
  target: 'web'
};
