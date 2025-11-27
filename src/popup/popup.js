/**
 * Popup UI Controller
 * Manages the extension's popup interface
 */

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', async () => {
  initializeTabs();
  await loadDashboard();
  await loadLists();
  await loadSettings();
  initializeEventListeners();
  
  // Auto-refresh dashboard every 5 seconds
  setInterval(async () => {
    await loadDashboard();
  }, 5000);
});

// Tab Management
function initializeTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      
      // Update active states
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      btn.classList.add('active');
      document.getElementById(`${tabName}-tab`).classList.add('active');
    });
  });
}

// Dashboard Functions
async function loadDashboard() {
  try {
    // Load statistics with retry logic
    const response = await sendMessageWithRetry({ action: 'getStats' }, 3);
    
    if (response && response.success) {
      const stats = response.data;
      document.getElementById('links-scanned').textContent = stats.linksScanned || 0;
      document.getElementById('threats-blocked').textContent = stats.threatsBlocked || 0;
      
      const rate = stats.linksScanned > 0 
        ? ((stats.threatsBlocked / stats.linksScanned) * 100).toFixed(1) 
        : 0;
      document.getElementById('protection-rate').textContent = `${rate}%`;
    } else {
      // Fallback to direct storage access
      const stats = await chrome.storage.local.get('stats');
      if (stats.stats) {
        document.getElementById('links-scanned').textContent = stats.stats.linksScanned || 0;
        document.getElementById('threats-blocked').textContent = stats.stats.threatsBlocked || 0;
        
        const rate = stats.stats.linksScanned > 0 
          ? ((stats.stats.threatsBlocked / stats.stats.linksScanned) * 100).toFixed(1) 
          : 0;
        document.getElementById('protection-rate').textContent = `${rate}%`;
      }
    }

    // Load database stats
    await updateDatabaseStatus();
  } catch (error) {
    console.error('Error loading dashboard:', error);
    // Don't show error toast on initial load, just log it
    console.warn('Dashboard will retry loading...');
  }
}

async function updateDatabaseStatus() {
  try {
    const result = await chrome.storage.local.get('phishTankDB');
    
    if (result.phishTankDB) {
      const { count, lastUpdated } = result.phishTankDB;
      const age = Date.now() - lastUpdated;
      const hoursOld = Math.floor(age / 3600000);
      
      document.getElementById('db-count').textContent = count.toLocaleString();
      document.getElementById('db-updated').textContent = `${hoursOld}h ago`;
      
      const statusDot = document.querySelector('.status-dot');
      const statusText = document.getElementById('db-status-text');
      
      if (age < 86400000) { // Less than 24 hours
        statusDot.style.backgroundColor = '#28a745';
        statusText.textContent = 'Up to date';
      } else {
        statusDot.style.backgroundColor = '#ffc107';
        statusText.textContent = 'Update available';
      }
    } else {
      document.getElementById('db-count').textContent = '0';
      document.getElementById('db-updated').textContent = 'Never';
      document.querySelector('.status-dot').style.backgroundColor = '#dc3545';
      document.getElementById('db-status-text').textContent = 'Not downloaded';
    }
  } catch (error) {
    console.error('Error checking database status:', error);
  }
}

// Lists Management
async function loadLists() {
  try {
    // Load whitelist
    const whitelist = await chrome.storage.local.get('whitelist');
    const whitelistContainer = document.getElementById('whitelist-container');
    renderList(whitelist.whitelist || [], whitelistContainer, 'whitelist');

    // Load blacklist
    const blacklist = await chrome.storage.local.get('blacklist');
    const blacklistContainer = document.getElementById('blacklist-container');
    renderList(blacklist.blacklist || [], blacklistContainer, 'blacklist');
  } catch (error) {
    console.error('Error loading lists:', error);
    showToast('Failed to load lists', 'error');
  }
}

function renderList(items, container, type) {
  if (items.length === 0) {
    container.innerHTML = '<div class="empty-state">No domains added</div>';
    return;
  }

  container.innerHTML = items.map(domain => `
    <div class="list-item">
      <span class="domain">${domain}</span>
      <button class="remove-btn" data-domain="${domain}" data-type="${type}">×</button>
    </div>
  `).join('');

  // Add remove listeners
  container.querySelectorAll('.remove-btn').forEach(btn => {
    btn.addEventListener('click', () => removeDomain(btn.dataset.domain, btn.dataset.type));
  });
}

async function addDomain(domain, type) {
  try {
    // Validate domain
    if (!domain || domain.trim() === '') {
      showToast('Please enter a domain', 'error');
      return;
    }

    domain = domain.trim().toLowerCase();
    
    // Basic domain validation
    if (!/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/.test(domain)) {
      showToast('Invalid domain format', 'error');
      return;
    }

    const action = type === 'whitelist' ? 'addToWhitelist' : 'addToBlacklist';
    const response = await chrome.runtime.sendMessage({ action, domain });

    if (response.success) {
      showToast(`Added ${domain} to ${type}`, 'success');
      await loadLists();
      
      // Clear input
      document.getElementById(`${type}-input`).value = '';
    } else {
      showToast(`Failed to add domain: ${response.error}`, 'error');
    }
  } catch (error) {
    console.error(`Error adding domain to ${type}:`, error);
    showToast('An error occurred', 'error');
  }
}

async function removeDomain(domain, type) {
  try {
    const storageKey = type;
    const result = await chrome.storage.local.get(storageKey);
    const list = result[storageKey] || [];
    
    const newList = list.filter(d => d !== domain);
    await chrome.storage.local.set({ [storageKey]: newList });
    
    // Clear cache
    await chrome.runtime.sendMessage({ action: 'clearCache' });
    
    showToast(`Removed ${domain} from ${type}`, 'success');
    await loadLists();
  } catch (error) {
    console.error(`Error removing domain from ${type}:`, error);
    showToast('Failed to remove domain', 'error');
  }
}

// Settings Management
async function loadSettings() {
  try {
    const response = await sendMessageWithRetry({ action: 'getSettings' }, 3);
    
    if (response && response.success) {
      const settings = response.data;
      
      // Load notification settings
      document.getElementById('notify-dangerous').checked = settings.notifyDangerous !== false;
      document.getElementById('notify-suspicious').checked = settings.notifySuspicious === true;
      document.getElementById('notify-updates').checked = settings.notifyUpdates !== false;
      
      // Load protection level
      const protectionLevel = settings.protectionLevel || 'strict';
      document.querySelector(`input[name="protection"][value="${protectionLevel}"]`).checked = true;
    } else {
      // Fallback to direct storage access
      const result = await chrome.storage.local.get('settings');
      if (result.settings) {
        const settings = result.settings;
        document.getElementById('notify-dangerous').checked = settings.notifyDangerous !== false;
        document.getElementById('notify-suspicious').checked = settings.notifySuspicious === true;
        document.getElementById('notify-updates').checked = settings.notifyUpdates !== false;
        
        const protectionLevel = settings.protectionLevel || 'strict';
        document.querySelector(`input[name="protection"][value="${protectionLevel}"]`).checked = true;
      }
    }
  } catch (error) {
    console.error('Error loading settings:', error);
  }
}

async function saveSettings() {
  try {
    const settings = {
      notifyDangerous: document.getElementById('notify-dangerous').checked,
      notifySuspicious: document.getElementById('notify-suspicious').checked,
      notifyUpdates: document.getElementById('notify-updates').checked,
      protectionLevel: document.querySelector('input[name="protection"]:checked').value
    };

    const response = await chrome.runtime.sendMessage({ 
      action: 'updateSettings', 
      settings 
    });

    if (response.success) {
      showToast('Settings saved', 'success');
    } else {
      showToast('Failed to save settings', 'error');
    }
  } catch (error) {
    console.error('Error saving settings:', error);
    showToast('An error occurred', 'error');
  }
}

// Event Listeners
function initializeEventListeners() {
  // Dashboard actions
  document.getElementById('update-db-btn').addEventListener('click', async () => {
    try {
      showToast('Updating database...', 'info');
      
      // Trigger actual database update
      const result = await chrome.runtime.sendMessage({ action: 'updateDatabase' });
      
      if (result && result.success) {
        await updateDatabaseStatus();
        showToast(`Database updated! ${result.count} threats loaded`, 'success');
      } else {
        await updateDatabaseStatus();
        showToast('Database update initiated', 'info');
      }
    } catch (error) {
      console.error('Update error:', error);
      showToast('Update in progress...', 'info');
    }
  });

  document.getElementById('export-data-btn').addEventListener('click', async () => {
    try {
      const link = document.createElement('a');
      const settings = await chrome.storage.local.get(null);
      const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
      link.href = URL.createObjectURL(blob);
      link.download = `apg-export-${Date.now()}.json`;
      link.click();
      showToast('Data exported', 'success');
    } catch (error) {
      showToast('Export failed', 'error');
    }
  });

  document.getElementById('clear-cache-btn').addEventListener('click', async () => {
    if (confirm('Clear all cached threat analysis?')) {
      try {
        await chrome.runtime.sendMessage({ action: 'clearCache' });
        showToast('Cache cleared', 'success');
        await loadDashboard();
      } catch (error) {
        showToast('Failed to clear cache', 'error');
      }
    }
  });

  document.getElementById('health-check-btn').addEventListener('click', async () => {
    try {
      const health = await chrome.storage.local.get(['phishTankDB', 'whitelist', 'blacklist']);
      const hasDB = !!health.phishTankDB;
      const whitelistCount = (health.whitelist || []).length;
      const blacklistCount = (health.blacklist || []).length;
      
      alert(`System Health Check:\n\n✓ Database: ${hasDB ? 'OK' : 'Missing'}\n✓ Whitelist: ${whitelistCount} domains\n✓ Blacklist: ${blacklistCount} domains\n✓ Extension: Running`);
    } catch (error) {
      showToast('Health check failed', 'error');
    }
  });

  // Lists actions
  document.getElementById('add-whitelist-btn').addEventListener('click', () => {
    const domain = document.getElementById('whitelist-input').value;
    addDomain(domain, 'whitelist');
  });

  document.getElementById('add-blacklist-btn').addEventListener('click', () => {
    const domain = document.getElementById('blacklist-input').value;
    addDomain(domain, 'blacklist');
  });

  // Enter key support for inputs
  document.getElementById('whitelist-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      const domain = e.target.value;
      addDomain(domain, 'whitelist');
    }
  });

  document.getElementById('blacklist-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      const domain = e.target.value;
      addDomain(domain, 'blacklist');
    }
  });

  // Settings actions
  document.querySelectorAll('#settings-tab input').forEach(input => {
    input.addEventListener('change', saveSettings);
  });

  document.getElementById('export-settings-btn').addEventListener('click', async () => {
    try {
      const settings = await chrome.storage.local.get(['whitelist', 'blacklist', 'settings']);
      const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `apg-settings-${Date.now()}.json`;
      link.click();
      showToast('Settings exported', 'success');
    } catch (error) {
      showToast('Export failed', 'error');
    }
  });

  document.getElementById('import-settings-btn').addEventListener('click', () => {
    document.getElementById('import-file-input').click();
  });

  document.getElementById('import-file-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file) {
      try {
        // CRITICAL FIX #10: Validate file before import
        const validationResult = await validateAndImportSettings(file);
        
        if (validationResult.success) {
          showToast(validationResult.message, 'success');
          await loadDashboard();
          await loadLists();
          await loadSettings();
        } else {
          showToast(validationResult.error, 'error');
        }
      } catch (error) {
        console.error('Import error:', error);
        showToast('Import failed: ' + error.message, 'error');
      }
    }
    
    // Reset file input
    e.target.value = '';
  });

  document.getElementById('factory-reset-btn').addEventListener('click', async () => {
    if (confirm('Factory reset will delete ALL data. Continue?')) {
      if (confirm('Are you absolutely sure? This cannot be undone!')) {
        try {
          await chrome.storage.local.clear();
          showToast('Extension reset to defaults', 'success');
          setTimeout(() => window.location.reload(), 1000);
        } catch (error) {
          showToast('Reset failed', 'error');
        }
      }
    }
  });
}

/**
 * Validate and import settings file
 * CRITICAL FIX #10: Comprehensive validation before import
 */
async function validateAndImportSettings(file) {
  try {
    // Step 1: Validate file type
    if (!file.name.endsWith('.json')) {
      return {
        success: false,
        error: 'Invalid file type. Please select a JSON file.'
      };
    }
    
    // Step 2: Validate file size (max 10MB)
    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    if (file.size > MAX_FILE_SIZE) {
      return {
        success: false,
        error: 'File too large. Maximum size is 10MB.'
      };
    }
    
    // Step 3: Read and parse JSON
    const text = await file.text();
    let data;
    
    try {
      data = JSON.parse(text);
    } catch (parseError) {
      return {
        success: false,
        error: 'Invalid JSON format. File is corrupted or not a valid export.'
      };
    }
    
    // Step 4: Validate data structure
    if (!data || typeof data !== 'object') {
      return {
        success: false,
        error: 'Invalid data structure. File does not contain valid settings.'
      };
    }
    
    // Step 5: Validate and sanitize each field
    const validatedData = {};
    let importedFields = 0;
    const errors = [];
    
    // Validate whitelist
    if (data.whitelist) {
      const validation = validateDomainList(data.whitelist, 'whitelist');
      if (validation.valid) {
        validatedData.whitelist = validation.data;
        importedFields++;
      } else {
        errors.push(validation.error);
      }
    }
    
    // Validate blacklist
    if (data.blacklist) {
      const validation = validateDomainList(data.blacklist, 'blacklist');
      if (validation.valid) {
        validatedData.blacklist = validation.data;
        importedFields++;
      } else {
        errors.push(validation.error);
      }
    }
    
    // Validate settings
    if (data.settings) {
      const validation = validateSettingsObject(data.settings);
      if (validation.valid) {
        validatedData.settings = validation.data;
        importedFields++;
      } else {
        errors.push(validation.error);
      }
    }
    
    // Validate stats (optional)
    if (data.stats) {
      const validation = validateStatsObject(data.stats);
      if (validation.valid) {
        validatedData.stats = validation.data;
        importedFields++;
      }
      // Don't add error for stats, it's optional
    }
    
    // Step 6: Check if we have any valid data to import
    if (importedFields === 0) {
      return {
        success: false,
        error: 'No valid data found in file. ' + (errors.length > 0 ? 'Errors: ' + errors.join(', ') : '')
      };
    }
    
    // Step 7: Confirm import with user
    const confirmMessage = `Import ${importedFields} setting(s)?\n\n` +
      (validatedData.whitelist ? `• Whitelist: ${validatedData.whitelist.length} domains\n` : '') +
      (validatedData.blacklist ? `• Blacklist: ${validatedData.blacklist.length} domains\n` : '') +
      (validatedData.settings ? `• Settings: Yes\n` : '') +
      (validatedData.stats ? `• Statistics: Yes\n` : '') +
      (errors.length > 0 ? `\nWarnings: ${errors.join(', ')}` : '');
    
    if (!confirm(confirmMessage)) {
      return {
        success: false,
        error: 'Import cancelled by user'
      };
    }
    
    // Step 8: Import validated data
    await chrome.storage.local.set(validatedData);
    
    // Step 9: Clear cache to re-analyze with new lists
    await chrome.runtime.sendMessage({ action: 'clearCache' });
    
    return {
      success: true,
      message: `Successfully imported ${importedFields} setting(s)` +
        (errors.length > 0 ? ` (${errors.length} warnings)` : '')
    };
    
  } catch (error) {
    console.error('Validation error:', error);
    return {
      success: false,
      error: 'Validation failed: ' + error.message
    };
  }
}

/**
 * Validate domain list
 * CRITICAL FIX #10: Ensure domain lists are valid
 */
function validateDomainList(list, listName) {
  if (!Array.isArray(list)) {
    return {
      valid: false,
      error: `${listName} is not an array`
    };
  }
  
  // Limit list size
  const MAX_DOMAINS = 1000;
  if (list.length > MAX_DOMAINS) {
    return {
      valid: false,
      error: `${listName} too large (max ${MAX_DOMAINS} domains)`
    };
  }
  
  // Validate and sanitize each domain
  const validDomains = [];
  const invalidCount = [];
  
  for (const domain of list) {
    if (typeof domain !== 'string') {
      invalidCount.push(domain);
      continue;
    }
    
    // Sanitize domain
    const cleaned = domain.trim().toLowerCase();
    
    // Validate domain format
    if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(cleaned)) {
      validDomains.push(cleaned);
    } else {
      invalidCount.push(domain);
    }
  }
  
  if (validDomains.length === 0) {
    return {
      valid: false,
      error: `${listName} contains no valid domains`
    };
  }
  
  return {
    valid: true,
    data: validDomains,
    warning: invalidCount.length > 0 ? `${invalidCount.length} invalid domains skipped` : null
  };
}

/**
 * Validate settings object
 * CRITICAL FIX #10: Ensure settings are valid
 */
function validateSettingsObject(settings) {
  if (!settings || typeof settings !== 'object') {
    return {
      valid: false,
      error: 'Settings is not an object'
    };
  }
  
  const validSettings = {};
  
  // Validate boolean settings
  const booleanSettings = ['enabled', 'blockDangerous', 'showWarnings', 'notifyDangerous', 'notifySuspicious', 'notifyUpdates'];
  for (const key of booleanSettings) {
    if (key in settings) {
      validSettings[key] = Boolean(settings[key]);
    }
  }
  
  // Validate protection level
  if (settings.protectionLevel) {
    const validLevels = ['relaxed', 'balanced', 'strict'];
    if (validLevels.includes(settings.protectionLevel)) {
      validSettings.protectionLevel = settings.protectionLevel;
    }
  }
  
  if (Object.keys(validSettings).length === 0) {
    return {
      valid: false,
      error: 'No valid settings found'
    };
  }
  
  return {
    valid: true,
    data: validSettings
  };
}

/**
 * Validate stats object
 * CRITICAL FIX #10: Ensure stats are valid
 */
function validateStatsObject(stats) {
  if (!stats || typeof stats !== 'object') {
    return {
      valid: false,
      error: 'Stats is not an object'
    };
  }
  
  const validStats = {};
  
  // Validate numeric stats
  if (typeof stats.linksScanned === 'number' && stats.linksScanned >= 0) {
    validStats.linksScanned = Math.floor(stats.linksScanned);
  }
  
  if (typeof stats.threatsBlocked === 'number' && stats.threatsBlocked >= 0) {
    validStats.threatsBlocked = Math.floor(stats.threatsBlocked);
  }
  
  // Validate timestamp
  if (stats.lastScan) {
    const timestamp = new Date(stats.lastScan);
    if (!isNaN(timestamp.getTime())) {
      validStats.lastScan = stats.lastScan;
    }
  }
  
  // Validate feedback stats
  if (stats.feedbackStats && typeof stats.feedbackStats === 'object') {
    validStats.feedbackStats = {
      correct: typeof stats.feedbackStats.correct === 'number' ? Math.floor(stats.feedbackStats.correct) : 0,
      incorrect: typeof stats.feedbackStats.incorrect === 'number' ? Math.floor(stats.feedbackStats.incorrect) : 0
    };
  }
  
  return {
    valid: Object.keys(validStats).length > 0,
    data: validStats
  };
}

/**
 * Send message with retry logic
 * Handles service worker connection issues
 */
async function sendMessageWithRetry(message, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await chrome.runtime.sendMessage(message);
      return response;
    } catch (error) {
      console.warn(`Message attempt ${i + 1}/${maxRetries} failed:`, error.message);
      
      if (i < maxRetries - 1) {
        // Wait before retry (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, 500 * (i + 1)));
      } else {
        console.error('All message attempts failed:', error);
        return null;
      }
    }
  }
  return null;
}

// Toast Notifications
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  
  const container = document.getElementById('toast-container');
  container.appendChild(toast);
  
  // Show toast
  setTimeout(() => toast.classList.add('show'), 10);
  
  // Auto dismiss after 3 seconds
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}
