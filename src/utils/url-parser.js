import { 
  PATTERNS, 
  SUSPICIOUS_TLDS, 
  LEGITIMATE_DOMAINS, 
  URL_SHORTENERS,
  TYPOSQUATTING_TARGETS
} from './constants.js';

/**
 * Parse and analyze a URL for phishing indicators
 */
export class URLParser {
  constructor(url) {
    this.url = url;
    this.parsed = null;
    this.domain = null;
    this.hostname = null;
    this.protocol = null;
    
    this.parseURL();
  }

  parseURL() {
    try {
      this.parsed = new URL(this.url);
      this.hostname = this.parsed.hostname.toLowerCase();
      this.domain = this.extractDomain(this.hostname);
      this.protocol = this.parsed.protocol;
      
      // Extract username if present (for username@host attacks)
      this.username = this.parsed.username;
    } catch (e) {
      console.error('Invalid URL:', this.url);
      this.parsed = null;
    }
  }

  /**
   * Extract the main domain from hostname
   */
  extractDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  }

  /**
   * Check if URL uses IP address instead of domain
   */
  isIPAddress() {
    return PATTERNS.IP_ADDRESS.test(this.hostname);
  }

  /**
   * Check if URL uses suspicious TLD
   */
  hasSuspiciousTLD() {
    return SUSPICIOUS_TLDS.some(tld => this.hostname.endsWith(tld));
  }

  /**
   * Check if URL contains encoded characters
   */
  hasEncodedChars() {
    return PATTERNS.ENCODED_CHARS.test(this.url);
  }

  /**
   * Check if URL has multiple dots in domain
   */
  hasMultipleDots() {
    return PATTERNS.MULTIPLE_DOTS.test(this.hostname);
  }

  /**
   * Check if URL is a known URL shortener
   */
  isURLShortener() {
    return URL_SHORTENERS.some(shortener => this.domain === shortener);
  }

  /**
   * Check if domain is legitimate
   */
  isLegitimate() {
    return LEGITIMATE_DOMAINS.some(domain => 
      this.domain === domain || this.hostname.endsWith(`.${domain}`)
    );
  }

  /**
   * Check for homograph attacks (lookalike characters)
   * Expanded to cover 50+ character mappings
   */
  hasHomographAttack() {
    // Comprehensive homograph character mappings
    const homographs = {
      'a': ['а', 'ɑ', 'α', 'ạ', 'ă', 'ą', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā', 'ȧ', 'ấ', 'ầ', 'ẩ', 'ẫ', 'ậ', 'ắ', 'ằ', 'ẳ', 'ẵ', 'ặ'],
      'b': ['Ь', 'ь', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
      'c': ['с', 'ϲ', 'ċ', 'ç', 'ć', 'ĉ', 'č', 'ḉ'],
      'd': ['ԁ', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ', 'ď', 'đ'],
      'e': ['е', 'ε', 'ė', 'ę', 'è', 'é', 'ê', 'ë', 'ē', 'ě', 'ȩ', 'ḕ', 'ḗ', 'ḙ', 'ḛ', 'ḝ', 'ế', 'ề', 'ể', 'ễ', 'ệ'],
      'f': ['ḟ', 'ƒ'],
      'g': ['ġ', 'ģ', 'ĝ', 'ǧ', 'ǵ', 'ḡ'],
      'h': ['һ', 'ḣ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ĥ', 'ħ'],
      'i': ['і', 'ι', '1', 'l', '|', 'ı', 'ï', 'ì', 'í', 'î', 'ĩ', 'ī', 'ĭ', 'į', 'ǐ', 'ȉ', 'ȋ', 'ḭ', 'ḯ', 'ỉ', 'ị'],
      'j': ['ј', 'ĵ', 'ǰ'],
      'k': ['к', 'ķ', 'ḱ', 'ḳ', 'ḵ'],
      'l': ['ӏ', '1', 'I', '|', 'ĺ', 'ļ', 'ľ', 'ḷ', 'ḹ', 'ḻ', 'ḽ', 'ł'],
      'm': ['м', 'ṁ', 'ṃ'],
      'n': ['ո', 'ṅ', 'ṇ', 'ṉ', 'ṋ', 'ń', 'ņ', 'ň', 'ñ', 'ǹ', 'ȵ'],
      'o': ['о', 'ο', '0', 'ȯ', 'ọ', 'ỏ', 'ō', 'ŏ', 'ő', 'ò', 'ó', 'ô', 'õ', 'ö', 'ơ', 'ǒ', 'ǫ', 'ǭ', 'ȍ', 'ȏ', 'ȫ', 'ȭ', 'ȯ', 'ȱ', 'ṍ', 'ṏ', 'ṑ', 'ṓ', 'ố', 'ồ', 'ổ', 'ỗ', 'ộ', 'ớ', 'ờ', 'ở', 'ỡ', 'ợ'],
      'p': ['р', 'ρ', 'ṕ', 'ṗ'],
      'q': ['ԛ', 'զ'],
      'r': ['г', 'ṙ', 'ṛ', 'ṝ', 'ṟ', 'ŕ', 'ŗ', 'ř', 'ȑ', 'ȓ'],
      's': ['ѕ', 'ś', 'ṡ', 'ṣ', 'ṥ', 'ṧ', 'ṩ', 'ŝ', 'š', 'ș'],
      't': ['т', 'ṫ', 'ṭ', 'ṯ', 'ṱ', 'ţ', 'ť', 'ț'],
      'u': ['υ', 'ս', 'ü', 'ù', 'ú', 'û', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ư', 'ǔ', 'ǖ', 'ǘ', 'ǚ', 'ǜ', 'ȕ', 'ȗ', 'ụ', 'ủ', 'ứ', 'ừ', 'ử', 'ữ', 'ự'],
      'v': ['ν', 'v', 'ṽ', 'ṿ'],
      'w': ['ѡ', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ', 'ŵ'],
      'x': ['х', 'χ', 'ẋ', 'ẍ'],
      'y': ['у', 'γ', 'ỳ', 'ý', 'ŷ', 'ÿ', 'ȳ', 'ẏ', 'ỵ', 'ỷ', 'ỹ'],
      'z': ['ź', 'ż', 'ž', 'ẑ', 'ẓ', 'ẕ']
    };

    // Check for any lookalike characters
    for (const [latin, lookalikes] of Object.entries(homographs)) {
      for (const lookalike of lookalikes) {
        if (this.hostname.includes(lookalike)) {
          return true;
        }
      }
    }
    
    // Check for mixed scripts (e.g., Latin + Cyrillic)
    const scripts = this.detectMixedScripts(this.hostname);
    if (scripts.size > 1) {
      return true;
    }
    
    return false;
  }

  /**
   * Detect mixed character scripts in domain
   */
  detectMixedScripts(text) {
    const scripts = new Set();
    
    for (const char of text) {
      const code = char.charCodeAt(0);
      
      // Basic Latin
      if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
        scripts.add('Latin');
      }
      // Cyrillic
      else if (code >= 0x0400 && code <= 0x04FF) {
        scripts.add('Cyrillic');
      }
      // Greek
      else if (code >= 0x0370 && code <= 0x03FF) {
        scripts.add('Greek');
      }
      // Armenian
      else if (code >= 0x0530 && code <= 0x058F) {
        scripts.add('Armenian');
      }
    }
    
    return scripts;
  }

  /**
   * Check for typosquatting (misspelled popular domains)
   * Now checks 100+ popular brands and services
   */
  isTyposquatting() {
    for (const targetDomain of TYPOSQUATTING_TARGETS) {
      // Check if target appears in hostname
      if (this.hostname.includes(targetDomain)) {
        // Check various TLD combinations
        const commonTLDs = ['.com', '.net', '.org', '.co', '.io'];
        
        for (const tld of commonTLDs) {
          const expected = `${targetDomain}${tld}`;
          
          // If it's not an exact match, check Levenshtein distance
          if (this.domain !== expected && this.hostname !== expected) {
            const distance = this.levenshteinDistance(this.domain, expected);
            
            // Distance of 1-2 suggests typosquatting
            if (distance > 0 && distance <= 2) {
              return true;
            }
          }
        }
        
        // Check for character substitutions (e.g., paypa1.com instead of paypal.com)
        if (this.hasCharacterSubstitution(targetDomain)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check for common character substitutions in typosquatting
   */
  hasCharacterSubstitution(targetDomain) {
    const substitutions = {
      'a': ['4', '@'],
      'e': ['3'],
      'i': ['1', 'l', '!'],
      'o': ['0'],
      's': ['5', '$'],
      'l': ['1', 'i'],
      't': ['7']
    };
    
    // Check if hostname contains target with substituted characters
    let pattern = targetDomain;
    for (const [char, subs] of Object.entries(substitutions)) {
      for (const sub of subs) {
        const substituted = targetDomain.replace(new RegExp(char, 'g'), sub);
        if (this.hostname.includes(substituted)) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Calculate Levenshtein distance for typosquatting detection
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Check if URL has excessively long domain
   */
  hasLongDomain() {
    return this.hostname.length > 50;
  }

  /**
   * Check if URL uses non-standard port
   */
  hasNonStandardPort() {
    const port = this.parsed?.port;
    if (!port) return false;
    
    const standardPorts = ['80', '443', '8080', '8443'];
    return !standardPorts.includes(port);
  }

  /**
   * Check if protocol is insecure (not HTTPS)
   */
  isInsecure() {
    return this.protocol === 'http:';
  }

  /**
   * Check for dangerous URL schemes
   */
  hasDangerousScheme() {
    const dangerousSchemes = ['javascript:', 'data:', 'blob:', 'file:', 'vbscript:'];
    return dangerousSchemes.some(scheme => this.protocol === scheme);
  }

  /**
   * Check for username in URL (phishing technique)
   */
  hasUsernameInURL() {
    return this.username && this.username.length > 0;
  }

  /**
   * Check for subdomain impersonation
   */
  hasSubdomainImpersonation() {
    const popularDomains = [
      'paypal', 'amazon', 'google', 'microsoft', 'apple', 
      'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
      'bankofamerica', 'chase', 'wellsfargo', 'citibank'
    ];
    
    // Check if a popular domain appears as a subdomain
    for (const domain of popularDomains) {
      if (this.hostname.includes(domain) && !this.domain.startsWith(domain)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for path-based spoofing
   */
  hasPathSpoofing() {
    const path = this.parsed?.pathname || '';
    const popularDomains = [
      'paypal.com', 'amazon.com', 'google.com', 'microsoft.com', 
      'apple.com', 'facebook.com', 'netflix.com', 'bankofamerica.com',
      'chase.com', 'wellsfargo.com'
    ];
    
    return popularDomains.some(domain => path.includes(domain));
  }

  /**
   * Check for double-encoded URLs
   */
  hasDoubleEncoding() {
    // Check for patterns like %25 (encoded %)
    return /%25/.test(this.url);
  }

  /**
   * Check for punycode (internationalized domain names)
   */
  hasPunycode() {
    return /xn--/.test(this.hostname);
  }

  /**
   * Get all detected issues
   */
  getIssues() {
    const issues = [];

    if (!this.parsed) {
      issues.push({ type: 'invalid_url', severity: 'high', message: 'Invalid URL format' });
      return issues;
    }

    // CRITICAL: Check for dangerous schemes first
    if (this.hasDangerousScheme()) {
      issues.push({ type: 'dangerous_scheme', severity: 'high', message: 'URL uses dangerous protocol (javascript/data/blob/file)' });
    }

    if (this.hasUsernameInURL()) {
      issues.push({ type: 'username_in_url', severity: 'high', message: 'URL contains username (common phishing technique)' });
    }

    if (this.hasSubdomainImpersonation()) {
      issues.push({ type: 'subdomain_impersonation', severity: 'high', message: 'Popular brand appears as subdomain (spoofing attempt)' });
    }

    if (this.hasPathSpoofing()) {
      issues.push({ type: 'path_spoofing', severity: 'high', message: 'Trusted domain name appears in URL path (deception technique)' });
    }

    if (this.hasDoubleEncoding()) {
      issues.push({ type: 'double_encoding', severity: 'high', message: 'URL contains double-encoded characters (obfuscation attempt)' });
    }

    if (this.hasPunycode()) {
      issues.push({ type: 'punycode', severity: 'medium', message: 'URL uses internationalized domain name (possible homograph attack)' });
    }

    if (this.isIPAddress()) {
      issues.push({ type: 'ip_address', severity: 'high', message: 'URL uses IP address instead of domain name' });
    }

    if (this.hasSuspiciousTLD()) {
      issues.push({ type: 'suspicious_tld', severity: 'medium', message: 'URL uses a suspicious top-level domain' });
    }

    if (this.hasEncodedChars()) {
      issues.push({ type: 'encoded_chars', severity: 'medium', message: 'URL contains encoded characters' });
    }

    if (this.hasMultipleDots()) {
      issues.push({ type: 'multiple_dots', severity: 'low', message: 'URL has unusual dot patterns' });
    }

    if (this.isURLShortener()) {
      issues.push({ type: 'url_shortener', severity: 'low', message: 'URL is shortened (destination unknown)' });
    }

    if (this.hasHomographAttack()) {
      issues.push({ type: 'homograph', severity: 'high', message: 'URL contains lookalike characters' });
    }

    if (this.isTyposquatting()) {
      issues.push({ type: 'typosquatting', severity: 'high', message: 'URL appears to mimic a popular domain' });
    }

    if (this.hasLongDomain()) {
      issues.push({ type: 'long_domain', severity: 'low', message: 'URL has an unusually long domain' });
    }

    if (this.hasNonStandardPort()) {
      issues.push({ type: 'non_standard_port', severity: 'medium', message: 'URL uses non-standard port' });
    }

    if (this.isInsecure()) {
      issues.push({ type: 'insecure', severity: 'medium', message: 'URL uses insecure HTTP protocol' });
    }

    return issues;
  }

  /**
   * Get overall threat assessment
   */
  getThreatLevel() {
    const issues = this.getIssues();
    
    if (this.isLegitimate()) {
      return 'safe';
    }

    const highSeverity = issues.filter(i => i.severity === 'high').length;
    const mediumSeverity = issues.filter(i => i.severity === 'medium').length;

    if (highSeverity >= 2 || (highSeverity >= 1 && mediumSeverity >= 1)) {
      return 'dangerous';
    } else if (highSeverity >= 1 || mediumSeverity >= 2) {
      return 'suspicious';
    } else if (issues.length > 0) {
      return 'suspicious';
    }

    return 'unknown';
  }
}

/**
 * Quick function to analyze a URL
 */
export function analyzeURL(url) {
  const parser = new URLParser(url);
  return {
    url: url,
    domain: parser.domain,
    hostname: parser.hostname,
    threatLevel: parser.getThreatLevel(),
    issues: parser.getIssues(),
    isLegitimate: parser.isLegitimate()
  };
}
