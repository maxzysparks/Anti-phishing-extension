/**
 * Supabase Configuration
 * Connects to Supabase backend for phishing database
 */

import { createClient } from '@supabase/supabase-js';

// Supabase credentials
const SUPABASE_URL = 'https://slphqzxyshthrlxnmvki.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNscGhxenh5c2h0aHJseG5tdmtpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQyOTUxNjcsImV4cCI6MjA3OTg3MTE2N30.cKXtt90uQ38hap5EerY1-K6IHicE6nvJwGE5GlLKZz8';

// Create Supabase client
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: false, // Don't persist auth in extension
    autoRefreshToken: false
  },
  db: {
    schema: 'public'
  },
  global: {
    headers: {
      'x-client-info': 'anti-phishing-guardian-extension'
    }
  }
});

// Test connection
export async function testConnection() {
  try {
    const { data, error } = await supabase
      .from('phishing_urls')
      .select('count')
      .limit(1);
    
    if (error) {
      console.error('[Supabase] Connection test failed:', error);
      return false;
    }
    
    console.log('[Supabase] Connection successful!');
    return true;
  } catch (err) {
    console.error('[Supabase] Connection error:', err);
    return false;
  }
}

export default supabase;
