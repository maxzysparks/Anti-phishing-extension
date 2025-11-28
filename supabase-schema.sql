-- Anti-Phishing Guardian - Supabase Database Schema
-- Run this SQL in your Supabase SQL Editor

-- ============================================
-- 1. PHISHING URLS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS phishing_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url TEXT NOT NULL UNIQUE,
  domain TEXT NOT NULL,
  threat_level TEXT NOT NULL CHECK (threat_level IN ('safe', 'suspicious', 'dangerous')),
  verified BOOLEAN DEFAULT false,
  source TEXT DEFAULT 'community',
  confidence_score DECIMAL(3,2) DEFAULT 0.5,
  first_reported TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  report_count INTEGER DEFAULT 1,
  metadata JSONB DEFAULT '{}'::jsonb,
  
  -- Indexes for fast lookups
  CONSTRAINT valid_confidence CHECK (confidence_score >= 0 AND confidence_score <= 1)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_phishing_urls_url ON phishing_urls(url);
CREATE INDEX IF NOT EXISTS idx_phishing_urls_domain ON phishing_urls(domain);
CREATE INDEX IF NOT EXISTS idx_phishing_urls_threat_level ON phishing_urls(threat_level);
CREATE INDEX IF NOT EXISTS idx_phishing_urls_verified ON phishing_urls(verified);

-- ============================================
-- 2. USER FEEDBACK TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS user_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  detected_threat_level TEXT NOT NULL,
  feedback_type TEXT NOT NULL CHECK (feedback_type IN ('correct', 'incorrect', 'false_positive', 'false_negative')),
  user_comment TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  metadata JSONB DEFAULT '{}'::jsonb
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_feedback_url ON user_feedback(url);
CREATE INDEX IF NOT EXISTS idx_user_feedback_domain ON user_feedback(domain);
CREATE INDEX IF NOT EXISTS idx_user_feedback_type ON user_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON user_feedback(created_at DESC);

-- ============================================
-- 3. STATISTICS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS extension_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  date DATE NOT NULL DEFAULT CURRENT_DATE,
  links_scanned INTEGER DEFAULT 0,
  threats_blocked INTEGER DEFAULT 0,
  false_positives INTEGER DEFAULT 0,
  false_negatives INTEGER DEFAULT 0,
  unique_users INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  UNIQUE(date)
);

-- Create index
CREATE INDEX IF NOT EXISTS idx_extension_stats_date ON extension_stats(date DESC);

-- ============================================
-- 4. WHITELIST TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS whitelist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain TEXT NOT NULL UNIQUE,
  added_by TEXT DEFAULT 'user',
  reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index
CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist(domain);

-- ============================================
-- 5. BLACKLIST TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS blacklist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain TEXT NOT NULL UNIQUE,
  added_by TEXT DEFAULT 'user',
  reason TEXT,
  threat_level TEXT DEFAULT 'dangerous',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index
CREATE INDEX IF NOT EXISTS idx_blacklist_domain ON blacklist(domain);

-- ============================================
-- 6. ENABLE ROW LEVEL SECURITY (RLS)
-- ============================================
ALTER TABLE phishing_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE extension_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE blacklist ENABLE ROW LEVEL SECURITY;

-- ============================================
-- 7. CREATE POLICIES (Allow public read, authenticated write)
-- ============================================

-- Phishing URLs: Everyone can read, only service can write
CREATE POLICY "Allow public read access" ON phishing_urls
  FOR SELECT USING (true);

CREATE POLICY "Allow service write access" ON phishing_urls
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow service update access" ON phishing_urls
  FOR UPDATE USING (true);

-- User Feedback: Everyone can submit
CREATE POLICY "Allow public feedback submission" ON user_feedback
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read feedback" ON user_feedback
  FOR SELECT USING (true);

-- Stats: Everyone can read
CREATE POLICY "Allow public read stats" ON extension_stats
  FOR SELECT USING (true);

CREATE POLICY "Allow service write stats" ON extension_stats
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow service update stats" ON extension_stats
  FOR UPDATE USING (true);

-- Whitelist: Everyone can read and write
CREATE POLICY "Allow public read whitelist" ON whitelist
  FOR SELECT USING (true);

CREATE POLICY "Allow public write whitelist" ON whitelist
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public delete whitelist" ON whitelist
  FOR DELETE USING (true);

-- Blacklist: Everyone can read and write
CREATE POLICY "Allow public read blacklist" ON blacklist
  FOR SELECT USING (true);

CREATE POLICY "Allow public write blacklist" ON blacklist
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public delete blacklist" ON blacklist
  FOR DELETE USING (true);

-- ============================================
-- 8. CREATE FUNCTIONS
-- ============================================

-- Function to update last_updated timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.last_updated = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for phishing_urls
CREATE TRIGGER update_phishing_urls_updated_at
  BEFORE UPDATE ON phishing_urls
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Function to increment report count
CREATE OR REPLACE FUNCTION increment_report_count(url_to_update TEXT)
RETURNS void AS $$
BEGIN
  UPDATE phishing_urls
  SET report_count = report_count + 1,
      last_updated = NOW()
  WHERE url = url_to_update;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 9. INSERT SAMPLE DATA (Optional)
-- ============================================

-- Insert some known phishing domains for testing
INSERT INTO phishing_urls (url, domain, threat_level, verified, source, confidence_score) VALUES
  ('http://secure-login-verify.tk', 'secure-login-verify.tk', 'dangerous', true, 'admin', 0.95),
  ('http://account-verify-secure.ml', 'account-verify-secure.ml', 'dangerous', true, 'admin', 0.92),
  ('http://banking-secure-login.ga', 'banking-secure-login.ga', 'dangerous', true, 'admin', 0.90),
  ('http://microsoft-support-alert.xyz', 'microsoft-support-alert.xyz', 'dangerous', true, 'admin', 0.88),
  ('http://apple-security-alert.top', 'apple-security-alert.top', 'dangerous', true, 'admin', 0.85)
ON CONFLICT (url) DO NOTHING;

-- ============================================
-- SETUP COMPLETE!
-- ============================================
-- Next steps:
-- 1. Run this SQL in Supabase SQL Editor
-- 2. Verify tables were created in Table Editor
-- 3. Test the extension connection
