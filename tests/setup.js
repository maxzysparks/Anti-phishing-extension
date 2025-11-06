/**
 * Jest Test Setup
 * Mocks Chrome Extension APIs and global objects
 */

// Mock Chrome Extension APIs
global.chrome = {
  runtime: {
    id: 'test-extension-id',
    sendMessage: jest.fn((message, callback) => {
      if (callback) {
        callback({ success: true, data: {} });
      }
      return Promise.resolve({ success: true, data: {} });
    }),
    onMessage: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    onInstalled: {
      addListener: jest.fn()
    },
    onStartup: {
      addListener: jest.fn()
    },
    getManifest: jest.fn(() => ({
      version: '1.0.0',
      name: 'Anti-Phishing Guardian'
    })),
    getURL: jest.fn((path) => `chrome-extension://test-id/${path}`),
    lastError: null
  },
  
  storage: {
    local: {
      get: jest.fn((keys) => {
        return Promise.resolve({});
      }),
      set: jest.fn((items) => {
        return Promise.resolve();
      }),
      remove: jest.fn((keys) => {
        return Promise.resolve();
      }),
      clear: jest.fn(() => {
        return Promise.resolve();
      })
    },
    sync: {
      get: jest.fn((keys) => {
        return Promise.resolve({});
      }),
      set: jest.fn((items) => {
        return Promise.resolve();
      }),
      remove: jest.fn((keys) => {
        return Promise.resolve();
      }),
      clear: jest.fn(() => {
        return Promise.resolve();
      })
    }
  },
  
  notifications: {
    create: jest.fn((id, options, callback) => {
      if (callback) callback('notification-id');
      return Promise.resolve('notification-id');
    }),
    clear: jest.fn((id, callback) => {
      if (callback) callback(true);
      return Promise.resolve(true);
    })
  },
  
  alarms: {
    create: jest.fn(),
    clear: jest.fn(),
    onAlarm: {
      addListener: jest.fn()
    }
  },
  
  permissions: {
    contains: jest.fn((permissions) => {
      return Promise.resolve(true);
    }),
    request: jest.fn((permissions) => {
      return Promise.resolve(true);
    })
  },
  
  tabs: {
    query: jest.fn(() => Promise.resolve([])),
    sendMessage: jest.fn(() => Promise.resolve({ success: true })),
    create: jest.fn(() => Promise.resolve({ id: 1 }))
  }
};

// Mock browser APIs
global.browser = global.chrome;

// Mock fetch API
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve([]),
    text: () => Promise.resolve(''),
    headers: new Headers()
  })
);

// Mock performance API
global.performance = {
  now: jest.fn(() => Date.now()),
  memory: {
    usedJSHeapSize: 10000000,
    totalJSHeapSize: 20000000,
    jsHeapSizeLimit: 100000000
  }
};

// Mock navigator.storage
global.navigator.storage = {
  estimate: jest.fn(() =>
    Promise.resolve({
      usage: 1000000,
      quota: 10000000
    })
  )
};

// Mock URL constructor for tests
global.URL = class URL {
  constructor(url) {
    try {
      const parsed = new window.URL(url);
      this.href = parsed.href;
      this.protocol = parsed.protocol;
      this.hostname = parsed.hostname;
      this.pathname = parsed.pathname;
      this.search = parsed.search;
      this.hash = parsed.hash;
      this.port = parsed.port;
      this.username = parsed.username;
      this.password = parsed.password;
      this.origin = parsed.origin;
      this.searchParams = parsed.searchParams;
    } catch (e) {
      throw new TypeError('Invalid URL');
    }
  }
};

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Mock Worker
global.Worker = class Worker {
  constructor(url) {
    this.url = url;
    this.onmessage = null;
    this.onerror = null;
  }
  
  postMessage(message) {
    // Simulate worker response
    setTimeout(() => {
      if (this.onmessage) {
        this.onmessage({
          data: {
            action: 'ready',
            id: message.id,
            data: {}
          }
        });
      }
    }, 0);
  }
  
  terminate() {
    // Mock terminate
  }
  
  addEventListener(event, handler) {
    if (event === 'message') {
      this.onmessage = handler;
    } else if (event === 'error') {
      this.onerror = handler;
    }
  }
  
  removeEventListener() {
    // Mock remove
  }
};

// Mock MutationObserver
global.MutationObserver = class MutationObserver {
  constructor(callback) {
    this.callback = callback;
  }
  
  observe() {
    // Mock observe
  }
  
  disconnect() {
    // Mock disconnect
  }
  
  takeRecords() {
    return [];
  }
};

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor(callback) {
    this.callback = callback;
  }
  
  observe() {
    // Mock observe
  }
  
  unobserve() {
    // Mock unobserve
  }
  
  disconnect() {
    // Mock disconnect
  }
};

// Setup and teardown
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
  
  // Reset chrome.runtime.lastError
  chrome.runtime.lastError = null;
});

afterEach(() => {
  // Clean up after each test
  jest.restoreAllMocks();
});

// Global test utilities
global.testUtils = {
  // Wait for async operations
  wait: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Create mock analysis result
  createMockAnalysis: (threatLevel = 'safe') => ({
    url: 'https://example.com',
    domain: 'example.com',
    hostname: 'example.com',
    threatLevel,
    issues: [],
    isLegitimate: threatLevel === 'safe',
    timestamp: Date.now()
  }),
  
  // Create mock storage data
  createMockStorage: (data = {}) => {
    chrome.storage.local.get.mockResolvedValue(data);
    chrome.storage.sync.get.mockResolvedValue(data);
  },
  
  // Simulate storage error
  simulateStorageError: (error = new Error('Storage error')) => {
    chrome.storage.local.get.mockRejectedValue(error);
    chrome.storage.local.set.mockRejectedValue(error);
  }
};

// Export for use in tests
export { chrome, testUtils };
