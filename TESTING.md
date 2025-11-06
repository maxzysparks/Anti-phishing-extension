# Testing Guide for Anti-Phishing Guardian

This document provides comprehensive testing procedures for the Anti-Phishing Guardian extension.

---

## 📋 Table of Contents

1. [Automated Testing](#automated-testing)
2. [Manual Browser Testing](#manual-browser-testing)
3. [Performance Testing](#performance-testing)
4. [Security Testing](#security-testing)
5. [Test Scenarios](#test-scenarios)

---

## 🤖 Automated Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage report
npm run test:coverage

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration
```

### Coverage Requirements

- **Minimum Coverage:** 70%
- **Target Coverage:** 80%+

### Current Test Suite

**Unit Tests** (`tests/unit/url-parser.test.js`)
- ✅ 50+ test cases
- ✅ URL parsing and validation
- ✅ IP address detection
- ✅ Typosquatting detection
- ✅ Homograph attack detection
- ✅ Threat level calculation

**Integration Tests** (`tests/integration/phishing-detector.test.js`)
- ✅ Complete analysis workflow
- ✅ Whitelist/Blacklist integration
- ✅ Context analysis
- ✅ Batch processing
- ✅ Error handling

---

## 🌐 Manual Browser Testing

### Supported Browsers

| Browser | Minimum Version | Status |
|---------|----------------|--------|
| Chrome | 88+ | ✅ Primary |
| Edge | 88+ | ✅ Supported |
| Firefox | 89+ | ⚠️ Limited |
| Brave | 88+ | ✅ Supported |
| Safari | N/A | ❌ Not Supported |

### Installation for Testing

1. **Build the Extension**
   ```bash
   npm run build
   ```

2. **Load in Chrome/Edge/Brave**
   - Navigate to `chrome://extensions/` (or `edge://extensions/`)
   - Enable "Developer mode" (toggle in top right)
   - Click "Load unpacked"
   - Select the `dist` folder
   - Extension should load without errors

3. **Load in Firefox**
   - Navigate to `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on"
   - Select any file in the `dist` folder
   - Extension will be active until browser restart

### Browser-Specific Testing

#### Chrome Testing Checklist
- [ ] Extension loads without errors
- [ ] Service worker activates
- [ ] Links are scanned in Gmail
- [ ] Links are scanned in Outlook
- [ ] Tooltips display correctly
- [ ] Notifications work
- [ ] Settings persist
- [ ] Database updates successfully

#### Edge Testing Checklist
- [ ] All Chrome tests pass
- [ ] Edge-specific UI renders correctly
- [ ] No console errors

#### Firefox Testing Checklist
- [ ] Extension loads (may show warnings)
- [ ] Basic link scanning works
- [ ] Notifications may differ
- [ ] Check for `browser` API compatibility

---

## ⚡ Performance Testing

### Test Environment Setup

1. **Create Test Email with Many Links**
   - Use Gmail or Outlook
   - Create/forward email with 100+ links
   - Include mix of safe and suspicious links

2. **Monitor Performance**
   - Open Chrome DevTools (F12)
   - Go to Performance tab
   - Start recording
   - Open the test email
   - Stop recording after links are scanned

### Performance Benchmarks

| Metric | Target | Acceptable | Poor |
|--------|--------|------------|------|
| 10 links | <100ms | <200ms | >200ms |
| 50 links | <500ms | <1s | >1s |
| 100 links | <1s | <2s | >2s |
| 500 links | <5s | <10s | >10s |

### Performance Test Scenarios

#### Test 1: Small Email (10-20 links)
```
Expected: Instant scanning (<200ms)
Monitor: No UI lag, smooth scrolling
```

#### Test 2: Medium Email (50-100 links)
```
Expected: Quick scanning (<1s)
Monitor: Brief loading, no freezing
```

#### Test 3: Large Email (500+ links)
```
Expected: Batch processing (<10s)
Monitor: Progressive scanning, UI remains responsive
```

#### Test 4: Memory Usage
```
1. Open email with 500+ links
2. Check Chrome Task Manager (Shift+Esc)
3. Monitor memory usage
4. Expected: <100MB for extension
5. Check for memory leaks (refresh and retest)
```

### Performance Testing Commands

```javascript
// Run in browser console
// Test 1: Measure link scanning time
console.time('scan');
// Open email with links
console.timeEnd('scan');

// Test 2: Check memory usage
console.log(performance.memory);

// Test 3: Monitor performance
PerformanceMonitor.logReport();
```

---

## 🔒 Security Testing

### Security Test Checklist

#### Input Validation
- [ ] Test with malformed URLs
- [ ] Test with extremely long URLs (>2048 chars)
- [ ] Test with special characters
- [ ] Test with encoded characters
- [ ] Test with unicode/punycode

#### XSS Prevention
- [ ] Inject `<script>alert(1)</script>` in URL
- [ ] Test with `javascript:` URLs
- [ ] Test with `data:` URLs
- [ ] Verify tooltips don't execute scripts

#### Storage Security
- [ ] Test storage quota limits
- [ ] Verify data encryption (if applicable)
- [ ] Test with corrupted storage data
- [ ] Verify cache invalidation

#### API Security
- [ ] Test rate limiting (100 req/min)
- [ ] Test with invalid message formats
- [ ] Test cross-extension messaging
- [ ] Verify sender validation

### Security Test Scenarios

