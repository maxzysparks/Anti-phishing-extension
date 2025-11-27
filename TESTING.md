# Testing Guide for Anti-Phishing Guardian

This document provides comprehensive testing procedures for the Anti-Phishing Guardian extension.

---

## Table of Contents

1. [Automated Testing](#automated-testing)
2. [Manual Browser Testing](#manual-browser-testing)
3. [Performance Testing](#performance-testing)
4. [Security Testing](#security-testing)
5. [Test Scenarios](#test-scenarios)

---

## Automated Testing

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

- 50+ test cases
- URL parsing and validation
- IP address detection
- Typosquatting detection
- Homograph attack detection
- Threat level calculation

**Integration Tests** (`tests/integration/phishing-detector.test.js`)

- Complete analysis workflow
- Whitelist/Blacklist integration
- Context analysis
- Batch processing
- Error handling

---

## Manual Browser Testing

### Supported Browsers

| Browser | Minimum Version | Status |
|---------|----------------|--------|
| Chrome | 88+ | Primary |
| Edge | 88+ | Supported |
| Firefox | 89+ | Limited |
| Brave | 88+ | Supported |
| Safari | N/A | Not Supported |

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

## Performance Testing

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

```text
Expected: Instant scanning (<200ms)
Monitor: No UI lag, smooth scrolling
```

#### Test 2: Medium Email (50-100 links)

```text
Expected: Quick scanning (<1s)
Monitor: Brief loading, no freezing
```

#### Test 3: Large Email (500+ links)

```text
Expected: Batch processing (<10s)
Monitor: Progressive scanning, UI remains responsive
```

#### Test 4: Memory Usage

```text
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

## Security Testing

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

#### Scenario 1: Malicious URL Injection

```text
1. Create email with suspicious URLs
2. Test: http://evil.com/login?redirect=javascript:alert(1)
3. Verify: Extension blocks/warns appropriately
4. Check: No script execution in tooltips
```

#### Scenario 2: Homograph Attack

```text
1. Test with IDN homograph domains
2. Example: xn--80ak6aa92e.com (apple.com lookalike)
3. Verify: Extension detects and warns
4. Check: Punycode displayed in tooltip
```

#### Scenario 3: Typosquatting

```text
1. Test common typos of popular sites
2. Examples: gooogle.com, faceboook.com
3. Verify: Extension flags as suspicious
4. Check: Suggests correct domain
```

---

## Test Scenarios

### Scenario 1: Gmail Integration

**Setup:**

1. Open Gmail in Chrome
2. Ensure extension is active
3. Open email with multiple links

**Test Steps:**

1. Hover over each link
2. Verify tooltip appears
3. Check threat level indicator
4. Click suspicious link
5. Verify warning appears

**Expected Results:**

- Tooltips show within 100ms
- Threat levels are accurate
- Warnings block navigation
- Safe links work normally

### Scenario 2: Outlook Integration

**Setup:**

1. Open Outlook Web App
2. Ensure extension is active
3. Open email with links

**Test Steps:**

1. Hover over links
2. Verify scanning works
3. Test with forwarded emails
4. Test with HTML emails

**Expected Results:**

- All links are scanned
- Tooltips display correctly
- No performance issues
- Forwarded emails work

### Scenario 3: Phishing Detection

**Test URLs:**

```text
Safe:
- https://google.com
- https://github.com
- https://microsoft.com

Suspicious:
- http://gooogle.com
- http://paypal-secure.tk
- http://192.168.1.1/login
- http://bit.ly/suspicious

Malicious:
- http://evil-phishing-site.com
- http://xn--80ak6aa92e.com
```

**Test Steps:**

1. Create test email with above URLs
2. Open in Gmail/Outlook
3. Hover over each link
4. Verify threat detection

**Expected Results:**

- Safe URLs: Green indicator
- Suspicious URLs: Yellow indicator
- Malicious URLs: Red indicator
- Accurate threat descriptions

### Scenario 4: Whitelist/Blacklist

**Test Steps:**

1. Add domain to whitelist
2. Verify it's marked safe
3. Add domain to blacklist
4. Verify it's marked dangerous
5. Test with subdomains
6. Test with wildcards

**Expected Results:**

- Whitelist overrides detection
- Blacklist always blocks
- Subdomains handled correctly
- Wildcards work as expected

### Scenario 5: Offline Mode

**Test Steps:**

1. Disconnect from internet
2. Open email with links
3. Hover over links
4. Verify basic scanning works

**Expected Results:**

- Local analysis works
- No API errors
- Cached data used
- Graceful degradation

### Scenario 6: High Volume

**Test Steps:**

1. Create email with 500+ links
2. Open in Gmail
3. Monitor performance
4. Check memory usage
5. Verify all links scanned

**Expected Results:**

- Batch processing works
- No browser freeze
- Memory stays under 100MB
- All links eventually scanned

---

## Regression Testing

### Before Each Release

- [ ] Run full test suite
- [ ] Test in all supported browsers
- [ ] Verify performance benchmarks
- [ ] Check security scenarios
- [ ] Test with real phishing emails
- [ ] Verify database updates
- [ ] Test notification system
- [ ] Check settings persistence
- [ ] Verify analytics tracking
- [ ] Test error handling

### Known Issues

1. **Firefox Compatibility**

   - Some Manifest V3 features limited
   - Service worker may not persist
   - Workaround: Use background scripts

2. **Large Email Performance**

   - Emails with 1000+ links may lag
   - Mitigation: Batch processing implemented
   - Future: Web Workers for parallel processing

3. **Tooltip Positioning**

   - May clip at screen edges
   - Workaround: Auto-repositioning logic
   - Future: Improved positioning algorithm

---

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install
      - run: npm test
      - run: npm run test:coverage
```

### Pre-commit Hooks

```bash
# Install husky
npm install --save-dev husky

# Add pre-commit hook
npx husky add .husky/pre-commit "npm test"
```

---

## Reporting Issues

### Bug Report Template

```markdown
**Description:**
Brief description of the issue

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- Browser: Chrome 120
- Extension Version: 1.0.0
- OS: Windows 11

**Screenshots:**
If applicable

**Console Errors:**
Any error messages
```

### Performance Issue Template

```markdown
**Issue:**
Description of performance problem

**Metrics:**
- Links scanned: 500
- Time taken: 15s
- Memory used: 150MB

**Environment:**
- Browser: Chrome 120
- System: 8GB RAM, i5 processor

**Reproduction:**
Steps to reproduce the issue
```

---

## Test Data

### Sample Phishing URLs

```javascript
const testUrls = {
  safe: [
    'https://google.com',
    'https://github.com',
    'https://microsoft.com'
  ],
  suspicious: [
    'http://gooogle.com',
    'http://paypal-secure.tk',
    'http://192.168.1.1/login'
  ],
  malicious: [
    'http://known-phishing-site.com',
    'http://xn--80ak6aa92e.com'
  ]
};
```

### Test Email Template

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Test Email</h1>
  <p>Safe link: <a href="https://google.com">Google</a></p>
  <p>Suspicious: <a href="http://gooogle.com">Gooogle</a></p>
  <p>Malicious: <a href="http://evil.com">Click here</a></p>
</body>
</html>
```

---

## Conclusion

This testing guide covers all aspects of the Anti-Phishing Guardian extension testing. Follow these procedures before each release to ensure quality and security.

For questions or issues, please open a GitHub issue or contact the development team.
