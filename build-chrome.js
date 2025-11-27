const fs = require('fs');
const path = require('path');

console.log('Building Chrome extension...');

// Copy Chrome manifest to dist
const chromeManifest = path.join(__dirname, 'public', 'manifest-chrome.json');
const distManifest = path.join(__dirname, 'dist', 'manifest.json');

if (fs.existsSync(chromeManifest)) {
  fs.copyFileSync(chromeManifest, distManifest);
  console.log('✓ Chrome manifest copied to dist/');
} else {
  console.error('✗ Chrome manifest not found!');
  process.exit(1);
}

console.log('✓ Chrome build complete!');
console.log('  Output: dist/ (Chrome Manifest V3)');
