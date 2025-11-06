# Anti-Phishing Guardian 🛡️

A powerful browser extension that detects and blocks phishing links in Gmail and Outlook, protecting you from malicious websites and email scams.

## Features

### Core Functionality

- **Real-time Link Analysis**: Automatically scans all links in Gmail and Outlook emails
- **Visual Threat Indicators**: Color-coded warnings (Green = Safe, Yellow = Suspicious, Red = Dangerous)
- **Interactive Tooltips**: Hover over links to see detailed threat analysis
- **Manual Link Checker**: Check any URL manually through the extension popup
- **Smart Caching**: Reduces API calls and improves performance

### Detection Capabilities

- **IP Address Detection**: Flags links using IP addresses instead of domains
- **Suspicious TLD Detection**: Identifies risky top-level domains (.tk, .ml, .xyz, etc.)
- **Typosquatting Detection**: Catches misspelled popular domains (gooogle.com, paypa1.com)
- **Homograph Attack Detection**: Identifies lookalike characters (раура1.com using Cyrillic)
- **URL Shortener Detection**: Flags shortened URLs that hide destinations
- **Encoded Characters Detection**: Identifies suspicious URL encoding
- **Insecure Protocol Detection**: Warns about HTTP vs HTTPS
- **Pattern Matching**: Uses phishing keyword detection
- **Whitelist/Blacklist**: Manage trusted and blocked domains

### User Experience

- **Non-intrusive**: Works silently in the background
- **Customizable Settings**: Enable/disable features as needed
- **Statistics Dashboard**: Track scanned links and blocked threats
- **One-Click Actions**: Trust or block domains instantly
- **Privacy-First**: No data collection, all processing is local

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Modern web browser (Chrome, Edge, or Brave)

### Setup Instructions

1. **Clone the Repository**

```bash
git clone https://github.com/maxzysparks/Anti-phishing-plugin.git
cd Anti-phishing-plugin
```

1. **Install Dependencies**

```bash
npm install
```

1. **Build the Extension**

```bash
# Development build (with watch mode)
npm run dev

# Production build
npm run build
```

1. **Create Icon Files**

   - Navigate to `public/icons/`
   - Create or add icon files: `icon16.png`, `icon48.png`, `icon128.png`
   - See `ICONS_INFO.txt` for details

1. **Load Extension in Browser**

   **Chrome/Edge/Brave:**

   - Open browser and navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top right)
   - Click "Load unpacked"
   - Select the `dist` folder from your project directory

   **Firefox:**

   - Navigate to `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on"
   - Select any file in the `dist` folder

## Usage

### Getting Started

1. **Install the Extension**: Follow installation instructions above
2. **Navigate to Gmail or Outlook**: Open your email in the browser
3. **Automatic Protection**: Links are automatically scanned and marked
4. **View Warnings**: Hover over links to see detailed threat information

### Understanding Threat Levels

- **🟢 Safe (Green)**: Link appears legitimate and safe
- **🟡 Suspicious (Yellow)**: Link has some suspicious characteristics
- **🔴 Dangerous (Red)**: Link is likely a phishing attempt
- **⚪ Unknown (Gray)**: Link couldn't be fully analyzed

### Manual Link Checking

1. Click the extension icon in your browser toolbar
2. Enter any URL in the "Check a Link" field
3. Click "Check" to see detailed analysis
4. Review threat level and detected issues

### Managing Domains

#### Whitelist a Domain

- Hover over a link
- Click "Trust Domain" in the tooltip
- Domain will be marked as safe

#### Blacklist a Domain

- Hover over a link
- Click "Block Domain" in the tooltip
- Domain will be blocked with warnings

### Settings

Access settings through the extension popup:

- **Enable Protection**: Turn extension on/off
- **Show Warning Tooltips**: Display/hide hover tooltips
- **Block Dangerous Links**: Prevent dangerous links from opening

## Development

### Project Structure

```text
anti-phishing-plugin/
├── src/
│   ├── background/
│   │   └── service-worker.js      # Background script
│   ├── content/
│   │   ├── content-script.js      # Content script for Gmail/Outlook
│   │   └── content.css            # Content script styles
│   ├── popup/
│   │   ├── popup.html             # Extension popup
│   │   ├── popup.css              # Popup styles
│   │   └── popup.js               # Popup logic
│   └── utils/
│       ├── constants.js           # Configuration constants
│       ├── phishing-detector.js   # Main detection engine
│       ├── storage.js             # Storage helpers
│       └── url-parser.js          # URL analysis
├── public/
│   ├── icons/                     # Extension icons
│   └── manifest.json              # Extension manifest
├── dist/                          # Built extension (generated)
├── webpack.config.js              # Webpack configuration
├── package.json                   # Dependencies
└── README.md                      # This file
```

### Key Technologies

- **JavaScript ES6+**: Modern JavaScript features
- **Chrome Extension APIs**: Manifest V3
- **Webpack**: Module bundling
- **Chrome Storage API**: Data persistence
- **MutationObserver**: DOM monitoring

### Development Workflow

1. **Make Changes**: Edit source files in `src/`
2. **Watch Mode**: Run `npm run dev` for auto-rebuild
3. **Reload Extension**: Click reload button in `chrome://extensions/`
4. **Test Changes**: Test in Gmail/Outlook
5. **Debug**: Use browser DevTools (Console, Network, etc.)

### Adding New Detection Rules

1. Open `src/utils/url-parser.js`
2. Add detection method to `URLParser` class
3. Update `getIssues()` method to include new check
4. Test thoroughly with various URLs

### Customizing Constants

Edit `src/utils/constants.js` to modify:

- Phishing keywords
- Suspicious TLDs
- Legitimate domains
- URL shorteners
- Cache durations

## Privacy & Security

### Privacy Commitment

- **No Data Collection**: Extension doesn't collect or store personal information
- **Local Processing**: All analysis happens on your device
- **No External Servers**: No data sent to external servers (except optional API calls)
- **No Tracking**: No analytics or user tracking
- **Open Source**: Code is transparent and auditable

### Permissions Explained

- **storage**: Save settings and cache locally
- **activeTab**: Access current tab for manual URL checking
- **host_permissions**: Access Gmail and Outlook to analyze links

## Contributing

Contributions are welcome! Here's how you can help:

### Reporting Bugs

1. Check existing issues
2. Create detailed bug report
3. Include steps to reproduce
4. Provide browser version and screenshots

### Suggesting Features

1. Open an issue with `[Feature Request]` prefix
2. Describe the feature and use case
3. Explain expected behavior

### Code Contributions

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes and test thoroughly
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open Pull Request

## Roadmap

### Phase 2: Enhanced Features (Future)

- [ ] Integration with Supabase backend
- [ ] Community threat intelligence sharing
- [ ] Cloud sync of settings across devices
- [ ] Machine learning-based detection
- [ ] Support for more email clients
- [ ] Multi-language support
- [ ] Browser notifications
- [ ] Detailed analytics dashboard

## Troubleshooting

### Extension Not Loading

- Check if you're in developer mode
- Verify all required files exist
- Check browser console for errors
- Rebuild: `npm run build`

### Links Not Being Detected

- Refresh the email page
- Check if extension is enabled
- Verify email domain is in manifest permissions
- Check browser console for errors

### Tooltips Not Showing

- Check "Show Warning Tooltips" setting
- Ensure content.css is loaded
- Try disabling other extensions

### Performance Issues

- Clear cache (in extension popup)
- Reduce cache duration in constants
- Check for console errors

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Maxwell Onyeka

- GitHub: [@maxzysparks](https://github.com/maxzysparks)
- Repository: [Anti-phishing-plugin](https://github.com/maxzysparks/Anti-phishing-plugin)
