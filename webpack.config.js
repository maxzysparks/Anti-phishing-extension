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
    extensions: ['.js']
  },
  // Optimize for Chrome extension service workers
  optimization: {
    minimize: true,
    // Don't split chunks for service workers
    splitChunks: false
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
