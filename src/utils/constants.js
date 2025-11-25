// Configuration constants for the anti-phishing extension

export const THREAT_LEVELS = {
  SAFE: 'safe',
  SUSPICIOUS: 'suspicious',
  DANGEROUS: 'dangerous',
  UNKNOWN: 'unknown'
};

export const STORAGE_KEYS = {
  WHITELIST: 'whitelist',
  BLACKLIST: 'blacklist',
  SETTINGS: 'settings',
  CACHE: 'threatCache',
  STATS: 'stats'
};

export const DEFAULT_SETTINGS = {
  enabled: true,
  showWarnings: true,
  blockDangerous: false,
  checkOnHover: true,
  cacheExpiry: 3600000, // 1 hour in milliseconds
  sensitivityLevel: 'medium' // low, medium, high
};

// Common phishing indicators (EXPANDED for aggressive spam detection)
export const PHISHING_KEYWORDS = [
  // Account-related urgency
  'verify', 'account', 'suspended', 'confirm', 'update', 'validate',
  'reactivate', 'locked', 'blocked', 'restricted', 'frozen',
  
  // Urgency & pressure tactics
  'urgent', 'immediately', 'act now', 'limited time', 'expire', 'expires',
  'deadline', 'final notice', 'last chance', 'hurry', 'act fast',
  
  // Security threats
  'password', 'security', 'alert', 'warning', 'unusual activity',
  'suspicious', 'unauthorized', 'breach', 'compromised', 'hacked',
  
  // Financial & prize scams
  'winner', 'prize', 'reward', 'congratulations', 'won', 'lottery',
  'million', 'inheritance', 'fund', 'transfer', 'claim',
  
  // CTA & action words (common in spam)
  'click here', 'click below', 'verify now', 'confirm now', 'update now',
  'download', 'open attachment', 'see details', 'view message',
  
  // Financial urgency
  'refund', 'tax', 'irs', 'payment', 'invoice', 'overdue', 'debt',
  'owed', 'billing', 'charge', 'transaction', 'purchase',
  
  // Too-good-to-be-true
  'free', 'guarantee', 'risk-free', 'no cost', '100%', 'amazing offer',
  'special promotion', 'exclusive', 'selected', 'qualified',
  
  // Credential harvesting
  'login', 'sign in', 'credentials', 'username', 'ssn', 'social security',
  're-enter', 'provide', 'submit', 'fill out',
  
  // Impersonation
  'customer service', 'support team', 'helpdesk', 'admin', 'administrator',
  'official', 'authorized', 'representative'
];

// SPAM-specific indicators (very high weight)
// FIXED: Removed legitimate marketing terms like 'unsubscribe' to reduce false positives
export const SPAM_INDICATORS = [
  'viagra', 'cialis', 'pharmacy online', 'cheap pills', 'medication online',
  'work from home', 'make money fast', 'earn $$$', 'get paid to', 'income opportunity',
  'mlm', 'multi-level marketing', 'investment opportunity', 'crypto gains',
  'forex trading', 'trading bot', 'guaranteed profit', 'risk-free investment',
  'enlarge', 'enhancement pills', 'replica watches', 'luxury replica',
  'nigerian prince', 'beneficiary', 'next of kin', 'offshore account',
  'wire transfer', 'western union', 'money gram', 'cashiers check'
];

// Suspicious TLDs
export const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
  '.club', '.work', '.click', '.link', '.bid', '.country'
];

// Legitimate domains (common email providers, banks, etc.)
export const LEGITIMATE_DOMAINS = [
  'google.com', 'gmail.com', 'outlook.com', 'microsoft.com',
  'apple.com', 'amazon.com', 'paypal.com', 'facebook.com',
  'twitter.com', 'linkedin.com', 'github.com', 'dropbox.com',
  // Major Banks
  'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
  'usbank.com', 'pnc.com', 'capitalone.com', 'tdbank.com',
  'barclays.com', 'hsbc.com', 'santander.com', 'deutsche-bank.com',
  // Payment Services
  'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
  // Crypto Exchanges
  'coinbase.com', 'binance.com', 'kraken.com', 'gemini.com',
  // E-commerce
  'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
  // Streaming
  'netflix.com', 'hulu.com', 'disneyplus.com', 'spotify.com',
  // Social Media
  'instagram.com', 'tiktok.com', 'snapchat.com', 'reddit.com',
  // Email Services
  'yahoo.com', 'protonmail.com', 'zoho.com', 'aol.com',
  // Book & Media Services
  'bookbub.com', 'goodreads.com', 'audible.com', 'scribd.com',
  'kobo.com', 'barnesandnoble.com', 'bn.com',
  // Newsletter & Marketing Services (legitimate tracking domains)
  'mailchimp.com', 'constantcontact.com', 'sendgrid.net', 'aweber.com',
  'getresponse.com', 'activecampaign.com', 'convertkit.com',
  'substack.com', 'beehiiv.com', 'buttondown.email'
];

// Legitimate tracking/redirect domains (used by legitimate services)
export const LEGITIMATE_TRACKING_DOMAINS = [
  'outbound.bookbub.com', 'click.e.bookbub.com', 'links.bookbub.com',
  'click.amazon.com', 'amzn.to', 'amazon.com/gp',
  'click.e.netflix.com', 'click.e.spotify.com',
  'click.e.linkedin.com', 'click.e.twitter.com',
  'mandrillapp.com', 'sendgrid.net', 'mailgun.org',
  // Social Media Redirect Domains (Facebook, Twitter, Instagram, etc.)
  'l.facebook.com', 'lm.facebook.com', 'l.instagram.com', 'l.messenger.com',
  't.co', 'twitter.com/i/redirect', 'l.twitter.com',
  'youtube.com/redirect', 'youtu.be',
  // Bank & Financial Institution Redirects
  'links.chase.com', 'secure.chase.com', 'click.chase.com',
  'links.bankofamerica.com', 'secure.bankofamerica.com',
  'links.wellsfargo.com', 'secure.wellsfargo.com',
  'links.citi.com', 'online.citi.com', 'secure.citi.com',
  'links.capitalone.com', 'secure.capitalone.com',
  'links.usbank.com', 'secure.usbank.com',
  // Generic patterns for legitimate services
  'email.mg.', 'email.', 'link.', 'links.', 'click.', 'go.', 'track.',
  'secure.', 'online.', 'redirect.', 'r.', 'url.'
];

// Comprehensive list of popular domains to protect against typosquatting
export const TYPOSQUATTING_TARGETS = [
  // Tech Giants
  'google', 'facebook', 'amazon', 'microsoft', 'apple',
  'netflix', 'instagram', 'twitter', 'linkedin', 'youtube',
  'tiktok', 'snapchat', 'reddit', 'discord', 'telegram',
  'whatsapp', 'zoom', 'slack', 'github', 'gitlab',
  // Financial Services
  'paypal', 'stripe', 'square', 'venmo', 'cashapp',
  'coinbase', 'binance', 'kraken', 'gemini', 'robinhood',
  // Banks (US)
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'usbank',
  'pnc', 'capitalone', 'tdbank', 'bofa', 'citi',
  // Banks (International)
  'barclays', 'hsbc', 'santander', 'deutschebank', 'bnpparibas',
  'creditsuis se', 'ing', 'natwest', 'lloydsbank', 'rbs',
  // E-commerce
  'ebay', 'walmart', 'target', 'bestbuy', 'costco',
  'homedepot', 'lowes', 'alibaba', 'aliexpress', 'etsy',
  // Streaming/Entertainment
  'spotify', 'hulu', 'disneyplus', 'hbomax', 'primevideo',
  'twitch', 'vimeo', 'soundcloud', 'pandora',
  // Email Providers
  'gmail', 'outlook', 'yahoo', 'protonmail', 'icloud',
  // Cloud Services  
  'dropbox', 'onedrive', 'googledrive', 'icloud', 'box',
  // Gaming
  'steam', 'epicgames', 'playstation', 'xbox', 'nintendo',
  'roblox', 'minecraft', 'fortnite', 'ea', 'ubisoft',
  // Government/Official
  'irs', 'usps', 'fedex', 'ups', 'dhl',
  // Education
  'coursera', 'udemy', 'edx', 'khanacademy', 'duolingo',
  // Others
  'adobe', 'salesforce', 'shopify', 'wordpress', 'squarespace'
];

// URL shorteners to flag for further checking
export const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
  'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link'
];

// Regex patterns for detection
export const PATTERNS = {
  IP_ADDRESS: /^(?:\d{1,3}\.){3}\d{1,3}$/,
  SUSPICIOUS_CHARS: /[^a-zA-Z0-9.-]/,
  MULTIPLE_DOTS: /\.{2,}/,
  HYPHEN_SUBDOMAIN: /^[^.]*-[^.]*\./,
  ENCODED_CHARS: /%[0-9A-Fa-f]{2}/
};

export const CACHE_DURATION = {
  SAFE: 86400000,      // 24 hours
  SUSPICIOUS: 3600000, // 1 hour
  DANGEROUS: 604800000 // 7 days
};
