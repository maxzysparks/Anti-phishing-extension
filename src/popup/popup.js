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
    // Load statistics
    const response = await chrome.runtime.sendMessage({ action: 'getStats' });
    
    if (response.success) {
      const stats = response.data;
      document.getElementById('links-scanned').textContent = stats.linksScanned || 0;
      document.getElementById('threats-blocked').textContent = stats.threatsBlocked || 0;
      
      const rate = stats.linksScanned > 0 
        ? ((stats.threatsBlocked / stats.linksScanned) * 100).toFixed(1) 
        : 0;
      document.getElementById('protection-rate').textContent = `${rate}%`;
    }

    // Load database stats
    await updateDatabaseStatus();
  } catch (error) {
    console.error('Error loading dashboard:', error);
    showToast('Failed to load dashboard', 'error');
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
    const response = await chrome.runtime.sendMessage({ action: 'getSettings' });
    
    if (response.success) {
      const settings = response.data;
      
      // Load notification settings
      document.getElementById('notify-dangerous').checked = settings.notifyDangerous !== false;
      document.getElementById('notify-suspicious').checked = settings.notifySuspicious === true;
      document.getElementById('notify-updates').checked = settings.notifyUpdates !== false;
      
      // Load protection level
      const protectionLevel = settings.protectionLevel || 'strict';
      document.querySelector(`input[name="protection"][value="${protectionLevel}"]`).checked = true;
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
      // The database updates automatically on install and via scheduled alarms
      // Just refresh the status display
      await updateDatabaseStatus();
      showToast('Database status refreshed', 'success');
    } catch (error) {
      showToast('Failed to refresh database status', 'error');
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
        const text = await file.text();
        const data = JSON.parse(text);
        await chrome.storage.local.set(data);
        showToast('Settings imported', 'success');
        await loadDashboard();
        await loadLists();
        await loadSettings();
      } catch (error) {
        showToast('Import failed', 'error');
      }
    }
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
