/**
 * Onboarding JavaScript
 * CRITICAL FIX #11: User onboarding functionality
 */

let currentStep = 1;
const totalSteps = 5;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  console.log('[Onboarding] Initializing...');
  
  // Check database status on final step
  checkDatabaseStatus();
  
  // Set up progress dot click handlers
  setupProgressDots();
});

/**
 * Navigate to next step
 */
function nextStep() {
  if (currentStep < totalSteps) {
    goToStep(currentStep + 1);
  }
}

/**
 * Navigate to previous step
 */
function prevStep() {
  if (currentStep > 1) {
    goToStep(currentStep - 1);
  }
}

/**
 * Go to specific step
 */
function goToStep(step) {
  if (step < 1 || step > totalSteps) return;
  
  // Hide current step
  const currentStepEl = document.getElementById(`step-${currentStep}`);
  if (currentStepEl) {
    currentStepEl.classList.remove('active');
  }
  
  // Update current step
  currentStep = step;
  
  // Show new step
  const newStepEl = document.getElementById(`step-${currentStep}`);
  if (newStepEl) {
    newStepEl.classList.add('active');
  }
  
  // Update progress indicator
  updateProgressIndicator();
  
  // Check database status if on final step
  if (currentStep === totalSteps) {
    checkDatabaseStatus();
  }
}

/**
 * Update progress indicator
 */
function updateProgressIndicator() {
  const dots = document.querySelectorAll('.progress-dot');
  dots.forEach((dot, index) => {
    const stepNum = index + 1;
    if (stepNum === currentStep) {
      dot.classList.add('active');
    } else {
      dot.classList.remove('active');
    }
  });
}

/**
 * Set up progress dot click handlers
 */
function setupProgressDots() {
  const dots = document.querySelectorAll('.progress-dot');
  dots.forEach((dot, index) => {
    dot.addEventListener('click', () => {
      goToStep(index + 1);
    });
  });
}

/**
 * Check database download status
 */
async function checkDatabaseStatus() {
  try {
    const result = await chrome.storage.local.get('phishTankDB');
    const dbStatus = document.getElementById('db-status');
    const dbText = document.getElementById('db-text');
    
    if (result.phishTankDB && result.phishTankDB.count > 0) {
      // Database is ready
      dbStatus.textContent = '✓';
      dbStatus.classList.remove('loading');
      dbText.textContent = `Threat database ready (${result.phishTankDB.count.toLocaleString()} threats)`;
    } else {
      // Still downloading
      dbStatus.textContent = '⏳';
      dbStatus.classList.add('loading');
      dbText.textContent = 'Downloading threat database...';
      
      // Check again in 2 seconds
      setTimeout(checkDatabaseStatus, 2000);
    }
  } catch (error) {
    console.error('[Onboarding] Error checking database:', error);
  }
}

/**
 * Skip onboarding
 */
async function skipOnboarding() {
  if (confirm('Skip the tutorial? You can always access help from the extension popup.')) {
    await finishOnboarding();
  }
}

/**
 * Finish onboarding
 */
async function finishOnboarding() {
  try {
    // Mark onboarding as complete
    await chrome.storage.local.set({ onboardingComplete: true });
    
    console.log('[Onboarding] Complete!');
    
    // Close onboarding tab and open popup
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) {
      // Open extension popup (if possible)
      try {
        await chrome.action.openPopup();
      } catch (popupError) {
        // If popup can't be opened programmatically, just close the tab
        console.log('[Onboarding] Popup cannot be opened programmatically');
      }
      
      // Close onboarding tab
      await chrome.tabs.remove(tabs[0].id);
    }
  } catch (error) {
    console.error('[Onboarding] Error finishing onboarding:', error);
    // Fallback: just close the window
    window.close();
  }
}

// Make functions globally available
window.nextStep = nextStep;
window.prevStep = prevStep;
window.goToStep = goToStep;
window.skipOnboarding = skipOnboarding;
window.finishOnboarding = finishOnboarding;
