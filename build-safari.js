const fs = require('fs');
const path = require('path');

console.log('Building Safari extension...');

// Create dist-safari directory if it doesn't exist
const distSafari = path.join(__dirname, 'dist-safari');
if (!fs.existsSync(distSafari)) {
  fs.mkdirSync(distSafari, { recursive: true });
  console.log('✓ Created dist-safari/ directory');
}

// Copy all files from dist to dist-safari
const distChrome = path.join(__dirname, 'dist');
if (fs.existsSync(distChrome)) {
  copyDirectory(distChrome, distSafari);
  console.log('✓ Copied files from dist/ to dist-safari/');
} else {
  console.error('✗ dist/ directory not found! Run "npm run build" first.');
  process.exit(1);
}

// Copy Safari manifest
const safariManifest = path.join(__dirname, 'public', 'manifest-safari.json');
const distManifest = path.join(distSafari, 'manifest.json');

if (fs.existsSync(safariManifest)) {
  fs.copyFileSync(safariManifest, distManifest);
  console.log('✓ Safari manifest copied to dist-safari/');
} else {
  console.error('✗ Safari manifest not found!');
  process.exit(1);
}

console.log('✓ Safari build complete!');
console.log('  Output: dist-safari/ (Safari Manifest V2)');
console.log('');
console.log('Next steps for Safari:');
console.log('  1. Open Terminal on Mac');
console.log('  2. Run: xcrun safari-web-extension-converter dist-safari/');
console.log('  3. Open generated Xcode project');
console.log('  4. Build and test in Safari');

// Helper function to copy directory recursively
function copyDirectory(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}
