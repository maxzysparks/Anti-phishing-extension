/**
 * Content script for Gmail and Outlook
 * Detects and analyzes links in emails
 */

console.log('Anti-Phishing Guardian: Content script loaded');

let settings = {};
let processedLinks = new Set();

// Initialize
init();

async function init() {
  // Get settings
  const response = await chrome.runtime.sendMessage({ action: 'getSettings' });
  if (response.success) {
    settings = response.data;
  }

  // Start monitoring
  if (settings.enabled) {
    startMonitoring();
  }
}

/**
 * Start monitoring for links
 */
function startMonitoring() {
  // Scan existing links
  scanLinks();

  // Watch for new links being added
  const observer = new MutationObserver((mutations) => {
    scanLinks();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  console.log('Link monitoring started');
}

/**
 * Scan all links on the page
 */
function scanLinks() {
  const links = document.querySelectorAll('a[href]');
  
  links.forEach(link => {
    const url = link.href;
    
    // Skip if already processed
    if (processedLinks.has(url)) return;
    
    // Skip mailto, tel, and internal links
    if (url.startsWith('mailto:') || url.startsWith('tel:') || url.startsWith('#')) {
      return;
    }

    // Mark as processed
    processedLinks.add(url);

    // CRITICAL: Block link immediately while analyzing
    preventClickDuringAnalysis(link);

    // Analyze the link
    analyzeAndMarkLink(link, url);
  });
}

/**
 * Prevent clicks on link while analysis is in progress
 */
function preventClickDuringAnalysis(linkElement) {
  const analysisHandler = (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    
    // Show loading indicator
    showAnalyzingIndicator(linkElement);
  };
  
  // Add handler with capture phase to intercept early
  linkElement.addEventListener('click', analysisHandler, { capture: true, once: false });
  
  // Store handler reference to remove it later
  linkElement._analysisHandler = analysisHandler;
}

/**
 * Show analyzing indicator
 */
function showAnalyzingIndicator(linkElement) {
  const indicator = document.createElement('span');
  indicator.className = 'apg-analyzing';
  indicator.textContent = '⏳';
  indicator.style.marginLeft = '4px';
  indicator.style.fontSize = '14px';
  indicator.title = 'Analyzing link safety...';
  
  linkElement.appendChild(indicator);
}

/**
 * Remove analyzing indicator
 */
function removeAnalyzingIndicator(linkElement) {
  const indicator = linkElement.querySelector('.apg-analyzing');
  if (indicator) {
    indicator.remove();
  }
}

/**
 * Get email context around link for spam analysis
 */
function getEmailContext(linkElement) {
  // Get surrounding text (300 chars before and after)
  let context = '';
  
  // Try to get the email body
  const emailBody = linkElement.closest('[role="article"]') || 
                    linkElement.closest('.email-body') ||
                    linkElement.closest('[data-message-id]') ||
                    linkElement.closest('.message-content');
  
  if (emailBody) {
    context = emailBody.textContent || '';
  } else {
    // Fallback: get parent paragraph
    const parent = linkElement.closest('p') || linkElement.closest('div');
    if (parent) {
      context = parent.textContent || '';
    }
  }
  
  // Get link text itself
  const linkText = linkElement.textContent || '';
  
  // Get email subject if available
  let subject = '';
  const subjectElement = document.querySelector('[data-legacy-thread-id] h2') ||
                         document.querySelector('.subject') ||
                         document.querySelector('[role="heading"]');
  if (subjectElement) {
    subject = subjectElement.textContent || '';
  }
  
  return {
    surrounding: context.toLowerCase(),
    linkText: linkText.toLowerCase(),
    subject: subject.toLowerCase(),
    fullContext: (subject + ' ' + linkText + ' ' + context).toLowerCase()
  };
}

/**
 * Analyze a link and add visual indicators
 */
async function analyzeAndMarkLink(linkElement, url) {
  try {
    // Get email context for spam analysis
    const emailContext = getEmailContext(linkElement);
    
    // Send to background for analysis with context
    const response = await chrome.runtime.sendMessage({
      action: 'analyzeLink',
      url: url,
      context: emailContext.fullContext
    });

    if (response.success) {
      const analysis = response.data;
      
      // Remove analyzing indicator
      removeAnalyzingIndicator(linkElement);
      
      // CRITICAL: Remove the temporary analysis blocker
      if (linkElement._analysisHandler) {
        linkElement.removeEventListener('click', linkElement._analysisHandler, { capture: true });
        delete linkElement._analysisHandler;
      }
      
      // Add visual indicator based on threat level
      addThreatIndicator(linkElement, analysis);
      
      // Add tooltip on hover
      if (settings.showWarnings) {
        addTooltip(linkElement, analysis);
      }

      // Block dangerous links if setting enabled
      if (settings.blockDangerous && analysis.threatLevel === 'dangerous') {
        blockLink(linkElement, analysis);
      }
    }
  } catch (error) {
    console.error('Error analyzing link:', error);
    // Remove analyzing indicator even on error
    removeAnalyzingIndicator(linkElement);
    
    // Remove blocker on error too
    if (linkElement._analysisHandler) {
      linkElement.removeEventListener('click', linkElement._analysisHandler, { capture: true });
      delete linkElement._analysisHandler;
    }
  }
}

/**
 * Add visual threat indicator to link
 */
function addThreatIndicator(linkElement, analysis) {
  // Remove existing indicator if any
  const existing = linkElement.querySelector('.apg-indicator');
  if (existing) existing.remove();

  // Create indicator
  const indicator = document.createElement('span');
  indicator.className = 'apg-indicator';
  indicator.textContent = analysis.icon;
  indicator.style.cssText = `
    margin-left: 4px !important;
    color: ${analysis.color} !important;
    font-weight: bold !important;
    font-size: 14px !important;
    display: inline !important;
    visibility: visible !important;
    opacity: 1 !important;
  `;
  indicator.title = analysis.description;

  // CRITICAL: Use !important to prevent style overrides
  linkElement.style.cssText += `
    border-bottom: 2px solid ${analysis.color} !important;
    padding-bottom: 2px !important;
  `;

  // Append indicator with Shadow DOM for protection
  const shadow = indicator.attachShadow ? indicator.attachShadow({ mode: 'closed' }) : null;
  if (shadow) {
    const style = document.createElement('style');
    style.textContent = `
      :host {
        margin-left: 4px !important;
        color: ${analysis.color} !important;
        font-weight: bold !important;
        font-size: 14px !important;
      }
    `;
    shadow.appendChild(style);
    const content = document.createElement('span');
    content.textContent = analysis.icon;
    shadow.appendChild(content);
  }
  
  linkElement.appendChild(indicator);

  // Add data attribute with cryptographic hash for integrity
  const integrityHash = btoa(`${analysis.threatLevel}-${Date.now()}`);
  linkElement.setAttribute('data-apg-threat', analysis.threatLevel);
  linkElement.setAttribute('data-apg-integrity', integrityHash);
  
  // Store original analysis for verification
  linkElement._apgAnalysis = Object.freeze(analysis);
  
  // Watch for tampering attempts
  watchForTampering(linkElement, integrityHash);
}

/**
 * Watch for DOM tampering attempts
 */
function watchForTampering(linkElement, integrityHash) {
  // Use MutationObserver to detect tampering
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      // Check if indicator was removed
      if (mutation.type === 'childList' && mutation.removedNodes.length > 0) {
        const indicatorRemoved = Array.from(mutation.removedNodes).some(
          node => node.className === 'apg-indicator'
        );
        
        if (indicatorRemoved) {
          console.warn('[APG] Tampering detected: Indicator removed. Restoring...');
          // Re-add indicator
          if (linkElement._apgAnalysis) {
            addThreatIndicator(linkElement, linkElement._apgAnalysis);
          }
        }
      }
      
      // Check if data attributes were modified
      if (mutation.type === 'attributes') {
        const currentIntegrity = linkElement.getAttribute('data-apg-integrity');
        if (currentIntegrity !== integrityHash) {
          console.warn('[APG] Tampering detected: Attributes modified. Restoring...');
          linkElement.setAttribute('data-apg-integrity', integrityHash);
        }
      }
    });
  });
  
  observer.observe(linkElement, {
    childList: true,
    attributes: true,
    attributeFilter: ['data-apg-threat', 'data-apg-integrity', 'style', 'class']
  });
  
  // Store observer to disconnect later if needed
  linkElement._apgObserver = observer;
}

/**
 * Add tooltip with detailed information
 */
function addTooltip(linkElement, analysis) {
  linkElement.addEventListener('mouseenter', (e) => {
    showTooltip(e, analysis);
  });

  linkElement.addEventListener('mouseleave', () => {
    hideTooltip();
  });
}

/**
 * Show threat tooltip
 * SECURITY: DOM construction without innerHTML to prevent XSS
 */
function showTooltip(event, analysis) {
  // Remove existing tooltip
  hideTooltip();

  const tooltip = document.createElement('div');
  tooltip.id = 'apg-tooltip';
  tooltip.className = 'apg-tooltip';
  
  // SECURITY FIX: Build DOM programmatically (no innerHTML)
  
  // Header
  const header = document.createElement('div');
  header.className = 'apg-tooltip-header';
  header.style.backgroundColor = sanitizeColor(analysis.color);
  
  const icon = document.createElement('span');
  icon.className = 'apg-tooltip-icon';
  icon.textContent = sanitizeText(analysis.icon); // textContent prevents XSS
  
  const title = document.createElement('span');
  title.className = 'apg-tooltip-title';
  title.textContent = sanitizeText(analysis.description);
  
  header.appendChild(icon);
  header.appendChild(title);
  
  // Body
  const body = document.createElement('div');
  body.className = 'apg-tooltip-body';
  
  const urlDiv = document.createElement('div');
  urlDiv.className = 'apg-tooltip-url';
  urlDiv.textContent = sanitizeText(analysis.url); // Prevents XSS
  
  const domainDiv = document.createElement('div');
  domainDiv.className = 'apg-tooltip-domain';
  domainDiv.textContent = `Domain: ${sanitizeText(analysis.domain) || 'N/A'}`;
  
  body.appendChild(urlDiv);
  body.appendChild(domainDiv);

  // Issues list
  if (analysis.issues && analysis.issues.length > 0) {
    const issuesDiv = document.createElement('div');
    issuesDiv.className = 'apg-tooltip-issues';
    
    const issuesTitle = document.createElement('strong');
    issuesTitle.textContent = 'Issues Found:';
    issuesDiv.appendChild(issuesTitle);
    
    const issuesList = document.createElement('ul');
    analysis.issues.forEach(issue => {
      const li = document.createElement('li');
      
      const severitySpan = document.createElement('span');
      severitySpan.style.color = sanitizeColor(
        issue.severity === 'high' ? '#dc3545' : 
        issue.severity === 'medium' ? '#ffc107' : '#6c757d'
      );
      severitySpan.textContent = `[${sanitizeText(issue.severity)}] `;
      
      const messageText = document.createTextNode(sanitizeText(issue.message));
      
      li.appendChild(severitySpan);
      li.appendChild(messageText);
      issuesList.appendChild(li);
    });
    
    issuesDiv.appendChild(issuesList);
    body.appendChild(issuesDiv);
  }

  // Actions
  const actions = document.createElement('div');
  actions.className = 'apg-tooltip-actions';
  
  const whitelistBtn = document.createElement('button');
  whitelistBtn.className = 'apg-btn apg-btn-whitelist';
  whitelistBtn.setAttribute('data-domain', sanitizeText(analysis.domain));
  whitelistBtn.textContent = 'Trust Domain';
  
  const blacklistBtn = document.createElement('button');
  blacklistBtn.className = 'apg-btn apg-btn-blacklist';
  blacklistBtn.setAttribute('data-domain', sanitizeText(analysis.domain));
  blacklistBtn.textContent = 'Block Domain';
  
  actions.appendChild(whitelistBtn);
  actions.appendChild(blacklistBtn);
  body.appendChild(actions);
  
  // Assemble tooltip
  tooltip.appendChild(header);
  tooltip.appendChild(body);

  // Position tooltip
  document.body.appendChild(tooltip);
  
  const rect = event.target.getBoundingClientRect();
  tooltip.style.position = 'fixed';
  tooltip.style.top = (rect.bottom + 10) + 'px';
  tooltip.style.left = rect.left + 'px';
  tooltip.style.zIndex = '10000';

  // Add event listeners for buttons (after DOM is built)
  whitelistBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    addToWhitelist(e.target.dataset.domain);
  });

  blacklistBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    addToBlacklist(e.target.dataset.domain);
  });
}

/**
 * Sanitize text to prevent XSS
 * SECURITY: Essential for user-controlled data
 */
function sanitizeText(text) {
  if (!text) return '';
  
  // Convert to string and limit length
  const str = String(text).substring(0, 1000);
  
  // Remove any potential script tags or HTML
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Sanitize color values
 * SECURITY: Prevent CSS injection
 */
function sanitizeColor(color) {
  if (!color) return '#000000';
  
  // Only allow hex colors
  if (/^#[0-9A-Fa-f]{6}$/.test(color)) {
    return color;
  }
  
  // Predefined safe colors
  const safeColors = {
    'green': '#28a745',
    'yellow': '#ffc107',
    'red': '#dc3545',
    'gray': '#6c757d'
  };
  
  return safeColors[color] || '#000000';
}

/**
 * Hide tooltip
 */
function hideTooltip() {
  const tooltip = document.getElementById('apg-tooltip');
  if (tooltip) {
    tooltip.remove();
  }
}

/**
 * Block a dangerous link
 */
function blockLink(linkElement, analysis) {
  linkElement.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const confirmed = confirm(
      `⚠️ PHISHING WARNING ⚠️\n\n` +
      `This link has been identified as potentially dangerous:\n\n` +
      `${analysis.description}\n\n` +
      `URL: ${analysis.url}\n\n` +
      `Issues found: ${analysis.issueCount}\n\n` +
      `Do you really want to proceed? (NOT RECOMMENDED)`
    );
    
    if (confirmed) {
      window.open(analysis.url, '_blank');
    }
  }, true);
}

/**
 * Add domain to whitelist
 */
async function addToWhitelist(domain) {
  try {
    await chrome.runtime.sendMessage({
      action: 'addToWhitelist',
      domain: domain
    });
    
    hideTooltip();
    processedLinks.clear();
    scanLinks();
    
    alert(`Domain "${domain}" has been added to your whitelist.`);
  } catch (error) {
    console.error('Error adding to whitelist:', error);
  }
}

/**
 * Add domain to blacklist
 */
async function addToBlacklist(domain) {
  try {
    await chrome.runtime.sendMessage({
      action: 'addToBlacklist',
      domain: domain
    });
    
    hideTooltip();
    processedLinks.clear();
    scanLinks();
    
    alert(`Domain "${domain}" has been added to your blacklist.`);
  } catch (error) {
    console.error('Error adding to blacklist:', error);
  }
}

// Listen for settings updates
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'settingsUpdated') {
    settings = request.settings;
    processedLinks.clear();
    scanLinks();
  }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  hideTooltip();
});
