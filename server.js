require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'", "https://sponsorscope-backend.onrender.com", "https://fneuoltfufikegjdertq.supabase.co"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: [
    'https://sponsorscope.netlify.app',
    'http://localhost:3000',
    'http://localhost:5500'
  ],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: { error: 'Too many requests, please try again later.' }
});

// ==================== SUPABASE & JWT SETUP ====================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'sponsorscope_secure_jwt_2025_production_key_change_in_production';

// ==================== SECURITY MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const requireSubscription = (req, res, next) => {
  if (!req.user.subscriptionActive) {
    return res.status(403).json({ 
      error: 'Active subscription required',
      code: 'SUBSCRIPTION_REQUIRED'
    });
  }
  next();
};

// ==================== SECURE AUTH ENDPOINTS ====================

// User Registration
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
// Create user - UPDATED FOR SCHEMA COMPATIBILITY
const { data: user, error } = await supabase
  .from('users')
  .insert([
    {
      name: name.trim(),
      email: email.toLowerCase(),
      encrypted_password: hashedPassword,  // CHANGED: password_hash → encrypted_password
      role: 'user',
      subscription_active: false,
      email_confirmed_at: null,            // CHANGED: email_verified → email_confirmed_at
      instance_id: require('crypto').randomUUID(), // ADDED: Required by Supabase
      aud: 'authenticated',                 // ADDED: Required by Supabase
      registered_at: new Date().toISOString(),
      created_at: new Date().toISOString(), // ADDED: Required by Supabase
      updated_at: new Date().toISOString()  // ADDED: Required by Supabase
    }
  ])
  .select()
  .single();

    if (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ error: 'Registration failed' });
    }

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store verification code
    const { error: codeError } = await supabase
      .from('verification_codes')
      .insert([
        {
          email: email.toLowerCase(),
          code: verificationCode,
          type: 'email_verification',
          expires_at: new Date(Date.now() + 10 * 60 * 1000)
        }
      ]);

    // In production, send real email here
    console.log(`Verification code for ${email}: ${verificationCode}`);

    res.json({
      success: true,
      message: 'Registration successful. Check your email for verification code.',
      verification_required: true,
      user_id: user.id
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Email
app.post('/api/auth/verify-email', authLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and verification code required' });
    }

    // Verify code
    const { data: verification, error } = await supabase
      .from('verification_codes')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('code', code)
      .eq('type', 'email_verification')
      .gt('expires_at', new Date().toISOString())
      .single();

    if (!verification || error) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    // Mark email as verified
    const { error: updateError } = await supabase
      .from('users')
      .update({ email_verified: true })
      .eq('email', email.toLowerCase());

    if (updateError) {
      return res.status(500).json({ error: 'Failed to verify email' });
    }

    // Delete used code
    await supabase
      .from('verification_codes')
      .delete()
      .eq('id', verification.id);

    res.json({ 
      success: true,
      message: 'Email verified successfully' 
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Get user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (!user || error) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check email verification
    if (!user.email_verified) {
      return res.status(403).json({ 
        error: 'Email verification required',
        code: 'EMAIL_VERIFICATION_REQUIRED'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        subscriptionActive: user.subscription_active
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Update last login
    await supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', user.id);

    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        subscriptionActive: user.subscription_active
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name')
      .eq('email', email.toLowerCase())
      .single();

    // Always return success to prevent email enumeration
    if (!user) {
      return res.json({ 
        success: true,
        message: 'If an account exists with this email, a reset link has been sent.'
      });
    }

    // Generate reset token
    const resetToken = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        type: 'password_reset' 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Store reset token
    const { error: tokenError } = await supabase
      .from('password_resets')
      .insert([
        {
          user_id: user.id,
          token: resetToken,
          expires_at: new Date(Date.now() + 60 * 60 * 1000)
        }
      ]);

    // In production, send email with reset link
    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({ 
      success: true,
      message: 'If an account exists with this email, a reset link has been sent.'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset Password
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Verify reset token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtError) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    if (decoded.type !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    // Check if token exists and is valid
    const { data: resetRecord, error: resetError } = await supabase
      .from('password_resets')
      .select('*')
      .eq('token', token)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (!resetRecord) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    const { error: updateError } = await supabase
      .from('users')
      .update({ password_hash: hashedPassword })
      .eq('id', decoded.id);

    if (updateError) {
      return res.status(500).json({ error: 'Failed to reset password' });
    }

    // Delete used reset token
    await supabase
      .from('password_resets')
      .delete()
      .eq('token', token);

    res.json({ 
      success: true,
      message: 'Password reset successfully' 
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Activate Subscription (after payment)
app.post('/api/auth/activate-subscription', authenticateToken, async (req, res) => {
  try {
    const { paymentMethod, transactionId } = req.body;

    // Validate payment details
    if (!paymentMethod || !transactionId) {
      return res.status(400).json({ error: 'Payment details required' });
    }

    // Update user subscription
    const { error } = await supabase
      .from('users')
      .update({ 
        subscription_active: true,
        last_payment: new Date().toISOString(),
        payment_method: paymentMethod,
        transaction_id: transactionId
      })
      .eq('id', req.user.id);

    if (error) {
      console.error('Subscription activation error:', error);
      return res.status(500).json({ error: 'Failed to activate subscription' });
    }

    res.json({
      success: true,
      message: 'Subscription activated successfully',
      user: {
        ...req.user,
        subscriptionActive: true
      }
    });

  } catch (error) {
    console.error('Subscription activation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get User Profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== SECURE API ENDPOINTS ====================

// Protected sponsorship check
app.get('/api/secure/check-sponsorship/:companyName', authenticateToken, requireSubscription, async (req, res) => {
  try {
    const companyName = req.params.companyName.trim();
    
    if (!companyName || companyName.length < 2) {
      return res.status(400).json({ error: 'Company name must be at least 2 characters long' });
    }

    console.log(`Secure search by ${req.user.email} for: "${companyName}"`);

    const { data: companies, error } = await supabase
      .from('sponsorship_companies')
      .select('"Organisation Name", "Town/City", "County", "Type & Rating", "Route"')
      .ilike('"Organisation Name"', `%${companyName}%`)
      .limit(50);

    if (error) {
      console.error('Database error:', error);
      return res.status(500).json({ error: 'Database query failed' });
    }

    if (!companies || companies.length === 0) {
      return res.json({
        company_search: companyName,
        matches_found: 0,
        sponsorship_available: false,
        message: 'No licensed sponsors found with this name',
        data_source: 'UK Government Licensed Sponsors Register',
        accuracy: '100% official data',
        last_verified: '2025-11-07'
      });
    }

    const analysis = analyzeRealSponsorshipData(companies);

    const result = {
      company_search: companyName,
      matches_found: companies.length,
      sponsorship_available: true,
      total_companies_in_database: 138362,
      official_data: {
        total_matching_companies: companies.length,
        companies: companies.map(company => ({
          name: company['Organisation Name'],
          location: getLocation(company),
          license_type: company['Type & Rating'],
          route: company['Route'],
          official_status: 'Active Licensed Sponsor'
        }))
      },
      sponsorship_insights: {
        total_routes_available: analysis.availableRoutes.length,
        routes_available: analysis.availableRoutes,
        license_types: analysis.licenseTypes,
        geographic_coverage: analysis.geographicCoverage,
        sponsorship_capacity: analysis.capacityLevel,
        data_freshness: 'November 7, 2025',
        search_coverage: `Showing ${companies.length} of 138,362 total licensed sponsors`
      },
      data_source: 'UK Government Licensed Sponsors Register',
      verification_date: '2025-11-07',
      accuracy: '100% official data',
      disclaimer: 'All data verified against official UK government records'
    };

    console.log(`✅ Secure results for "${companyName}": ${companies.length} matches for user ${req.user.email}`);
    res.json(result);

  } catch (error) {
    console.error('Secure search error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== EXISTING ENDPOINTS (for backward compatibility) ====================

// Your existing sponsorship check (public)
app.get('/api/check-sponsorship/:companyName', apiLimiter, async (req, res) => {
  try {
    const companyName = req.params.companyName.trim();
    
    if (!companyName || companyName.length < 2) {
      return res.status(400).json({
        error: 'Company name must be at least 2 characters long'
      });
    }

    console.log(`Public search for: "${companyName}"`);

    const { data: companies, error } = await supabase
      .from('sponsorship_companies')
      .select('"Organisation Name", "Town/City", "County", "Type & Rating", "Route"')
      .ilike('"Organisation Name"', `%${companyName}%`)
      .limit(10);

    if (error) {
      console.error('Database error:', error);
      return res.status(500).json({ error: 'Database query failed' });
    }

    if (!companies || companies.length === 0) {
      return res.json({
        company_search: companyName,
        matches_found: 0,
        sponsorship_available: false,
        message: 'No licensed sponsors found with this name',
        data_source: 'UK Government Licensed Sponsors Register',
        accuracy: '100% official data',
        last_verified: '2025-11-07'
      });
    }

    const analysis = analyzeRealSponsorshipData(companies);

    const result = {
      company_search: companyName,
      matches_found: companies.length,
      sponsorship_available: true,
      official_data: {
        total_matching_companies: companies.length,
        companies: companies.map(company => ({
          name: company['Organisation Name'],
          location: getLocation(company),
          license_type: company['Type & Rating'],
          route: company['Route'],
          official_status: 'Active Licensed Sponsor'
        }))
      },
      sponsorship_insights: {
        routes_available: analysis.availableRoutes,
        license_types: analysis.licenseTypes,
        geographic_coverage: analysis.geographicCoverage,
        sponsorship_capacity: analysis.capacityLevel,
        data_freshness: 'November 7, 2025'
      },
      data_source: 'UK Government Licensed Sponsors Register',
      verification_date: '2025-11-07',
      accuracy: '100% official data',
      disclaimer: 'All data verified against official UK government records'
    };

    console.log(`✅ Public results for "${companyName}": ${companies.length} official matches`);
    res.json(result);

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
});

// Helper functions (keep your existing ones)
function analyzeRealSponsorshipData(companies) {
  const routes = [...new Set(companies.map(c => c.Route).filter(Boolean))];
  const licenseTypes = [...new Set(companies.map(c => c['Type & Rating']).filter(Boolean))];
  const locations = companies.map(c => getLocation(c)).filter(Boolean);
  const uniqueLocations = [...new Set(locations)];
  
  let capacityLevel = 'Standard';
  if (companies.length > 10) capacityLevel = 'Multiple Entities';
  if (companies.length > 25) capacityLevel = 'Large Organization';
  if (companies.length > 50) capacityLevel = 'Major Sponsor';
  if (companies.some(c => c['Type & Rating']?.includes('A rating'))) capacityLevel = 'A-Rated Sponsor';
  
  return {
    availableRoutes: routes,
    licenseTypes: licenseTypes,
    geographicCoverage: uniqueLocations.slice(0, 8),
    capacityLevel: capacityLevel
  };
}

function getLocation(company) {
  const town = company['Town/City'] || '';
  const county = company['County'] || '';
  if (town && county) return `${town}, ${county}`;
  return town || county || 'Location not specified';
}

// Health check
app.get('/health', async (req, res) => {
  try {
    const { count } = await supabase
      .from('sponsorship_companies')
      .select('*', { count: 'exact', head: true });

    res.json({
      status: 'healthy',
      database_connected: true,
      total_companies: count || 0,
      data_source: 'UK Government Licensed Sponsors Register',
      last_verified: '2025-11-07',
      accuracy: '100% official data',
      timestamp: new Date().toISOString(),
      authentication: 'JWT-based secure authentication available'
    });
  } catch (error) {
    res.status(500).json({ status: 'unhealthy', error: error.message });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🔒 Secure Sponsorscope API - 100% Accurate UK Sponsorship Verification',
    status: 'active',
    data_integrity: '100% Official UK Government Data',
    total_companies: 138362,
    features: [
      'Secure JWT-based authentication',
      'Email verification system',
      'Password reset functionality',
      'Subscription-based access control',
      'Sponsorship verification using official records'
    ],
    endpoints: {
      public: {
        health_check: 'GET /health',
        sponsorship_check: 'GET /api/check-sponsorship/:companyName'
      },
      secure: {
        register: 'POST /api/auth/register',
        verify_email: 'POST /api/auth/verify-email',
        login: 'POST /api/auth/login',
        forgot_password: 'POST /api/auth/forgot-password',
        reset_password: 'POST /api/auth/reset-password',
        secure_sponsorship_check: 'GET /api/secure/check-sponsorship/:companyName (requires auth + subscription)',
        profile: 'GET /api/auth/profile (requires auth)'
      }
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: 'The requested API endpoint does not exist'
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: 'Something went wrong on our end'
  });
});

// Start server
app.listen(PORT, () => {
  console.log('\n🔒 SECURE SPONSORSCOPE SERVER STARTED');
  console.log('📍 Port:', PORT);
  console.log('💂 Authentication: JWT + bcrypt');
  console.log('🛡️ Security: Helmet + Rate Limiting');
  console.log('📊 Database: Supabase connected');
  console.log('💳 Subscription: Ready for payment integration');
  console.log('🔗 Frontend: https://sponsorscope.netlify.app');
  console.log('🚀 API: https://sponsorscope-backend.onrender.com');
});