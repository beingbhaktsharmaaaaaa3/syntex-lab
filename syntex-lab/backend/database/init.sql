-- Syntex Solutions - Database Schema
-- Version: 2.4.1

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    address TEXT,
    department VARCHAR(50),
    job_title VARCHAR(100),
    avatar VARCHAR(255) DEFAULT '/img/avatar-default.png',
    bio TEXT,
    api_key VARCHAR(64),
    secret_note TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    two_factor_secret VARCHAR(32),
    login_attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(200) UNIQUE,
    description TEXT,
    short_desc VARCHAR(300),
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    sku VARCHAR(50) UNIQUE,
    stock INTEGER DEFAULT 999,
    image_url VARCHAR(255),
    features TEXT,
    version VARCHAR(20),
    license_type VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    author_name VARCHAR(100),
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    content TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    coupon_code VARCHAR(20),
    discount DECIMAL(10,2) DEFAULT 0.00,
    shipping_address TEXT,
    billing_address TEXT,
    notes TEXT,
    invoice_number VARCHAR(50),
    license_key VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blog_posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(300) NOT NULL,
    slug VARCHAR(300) UNIQUE,
    content TEXT NOT NULL,
    excerpt TEXT,
    author_id INTEGER REFERENCES users(id),
    category VARCHAR(50),
    tags TEXT,
    status VARCHAR(20) DEFAULT 'published',
    views INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    post_id INTEGER REFERENCES blog_posts(id),
    user_id INTEGER REFERENCES users(id),
    author_name VARCHAR(100),
    content TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tickets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    subject VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    priority VARCHAR(20) DEFAULT 'medium',
    category VARCHAR(50),
    assigned_to INTEGER REFERENCES users(id),
    internal_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ticket_replies (
    id SERIAL PRIMARY KEY,
    ticket_id INTEGER REFERENCES tickets(id),
    user_id INTEGER REFERENCES users(id),
    message TEXT NOT NULL,
    is_staff BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(200),
    message TEXT,
    type VARCHAR(20) DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    link VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupons (
    id SERIAL PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 100,
    used_count INTEGER DEFAULT 0,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupon_uses (
    id SERIAL PRIMARY KEY,
    coupon_id INTEGER REFERENCES coupons(id),
    user_id INTEGER REFERENCES users(id),
    order_id INTEGER REFERENCES orders(id),
    used_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100),
    resource VARCHAR(100),
    resource_id INTEGER,
    ip_address VARCHAR(50),
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(100),
    permissions TEXT DEFAULT 'read',
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    original_name VARCHAR(255),
    stored_name VARCHAR(255),
    file_path VARCHAR(500),
    file_size INTEGER,
    mime_type VARCHAR(100),
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions_custom (
    id SERIAL PRIMARY KEY,
    session_token VARCHAR(128) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

-- ── v3.0 additions ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id),
    title           VARCHAR(300) NOT NULL,
    vuln_type       VARCHAR(50),
    severity        VARCHAR(20) DEFAULT 'medium',
    cvss_score      DECIMAL(3,1),
    affected_url    TEXT,
    steps           TEXT,
    impact          TEXT,
    proof_of_concept TEXT,
    suggested_fix   TEXT,
    status          VARCHAR(30) DEFAULT 'new',
    triage_notes    TEXT,
    triaged_by      INTEGER REFERENCES users(id),
    duplicate_of    INTEGER REFERENCES reports(id),
    bounty_amount   DECIMAL(10,2) DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hall_of_fame (
    id              SERIAL PRIMARY KEY,
    researcher_name VARCHAR(100) NOT NULL,
    handle          VARCHAR(50)  NOT NULL,
    bugs_found      INTEGER DEFAULT 0,
    critical_bugs   INTEGER DEFAULT 0,
    total_bounty    DECIMAL(10,2) DEFAULT 0,
    rank            INTEGER,
    country         VARCHAR(50),
    joined_year     INTEGER,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hint_unlocks (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    vuln_slug   VARCHAR(100),
    level       INTEGER,
    unlocked_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS challenge_completions (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id),
    challenge_id VARCHAR(100),
    completed_at TIMESTAMP DEFAULT NOW()
);

-- ── v3.1 — Flag verification system ─────────────────────────────

CREATE TABLE IF NOT EXISTS vuln_flags (
    id             SERIAL PRIMARY KEY,
    slug           VARCHAR(100) UNIQUE NOT NULL,
    flag_value     VARCHAR(200) NOT NULL,
    vuln_title     VARCHAR(200),
    category       VARCHAR(50),
    points         INTEGER DEFAULT 100,
    location_hint  VARCHAR(300),
    created_at     TIMESTAMP DEFAULT NOW()
);

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS flag_slug       VARCHAR(100),
    ADD COLUMN IF NOT EXISTS flag_submitted  VARCHAR(200),
    ADD COLUMN IF NOT EXISTS flag_verified   BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS verified_at     TIMESTAMP;

CREATE TABLE IF NOT EXISTS user_flags (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    flag_slug   VARCHAR(100) NOT NULL,
    report_id   INTEGER REFERENCES reports(id),
    found_at    TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, flag_slug)
);

-- ── v4.0 additions ────────────────────────────────────────────────

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS wallet_balance DECIMAL(10,2) DEFAULT 100.00,
    ADD COLUMN IF NOT EXISTS wallet_bonus   DECIMAL(10,2) DEFAULT 0.00;

CREATE TABLE IF NOT EXISTS chat_messages (
    id          SERIAL PRIMARY KEY,
    room_id     VARCHAR(50) NOT NULL DEFAULT '1',
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username    VARCHAR(100) NOT NULL DEFAULT 'Anonymous',
    content     TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chat_room ON chat_messages(room_id);

CREATE TABLE IF NOT EXISTS reward_claims (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    reward_type VARCHAR(50) DEFAULT 'daily_bonus',
    amount      DECIMAL(10,2) DEFAULT 0,
    claimed_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_apps (
    id           SERIAL PRIMARY KEY,
    client_id    VARCHAR(100) UNIQUE NOT NULL,
    client_secret VARCHAR(100) NOT NULL,
    name         VARCHAR(100),
    redirect_uris TEXT,
    created_at   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS graphql_logs (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    query       TEXT,
    variables   TEXT,
    ip_address  VARCHAR(50),
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Idempotent unique indexes (PostgreSQL-safe — no ADD CONSTRAINT IF NOT EXISTS)
CREATE UNIQUE INDEX IF NOT EXISTS uq_hof_handle   ON hall_of_fame(handle);
CREATE UNIQUE INDEX IF NOT EXISTS uq_flag_slug    ON vuln_flags(slug);
CREATE UNIQUE INDEX IF NOT EXISTS uq_completion   ON challenge_completions(user_id, challenge_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_hint_unlock  ON hint_unlocks(user_id, vuln_slug, level);
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_flag    ON user_flags(user_id, flag_slug);

-- Reset / lab data command support
CREATE TABLE IF NOT EXISTS lab_resets (
    id         SERIAL PRIMARY KEY,
    reset_at   TIMESTAMP DEFAULT NOW(),
    reset_by   INTEGER REFERENCES users(id)
);


-- ── v4.1 — Enhanced flag system & researcher stats ───────────────

-- Extend vuln_flags with severity, endpoint, difficulty
ALTER TABLE vuln_flags ADD COLUMN IF NOT EXISTS severity    VARCHAR(20) DEFAULT 'medium';
ALTER TABLE vuln_flags ADD COLUMN IF NOT EXISTS endpoint    TEXT;
ALTER TABLE vuln_flags ADD COLUMN IF NOT EXISTS difficulty  VARCHAR(20) DEFAULT 'medium';
ALTER TABLE vuln_flags ADD COLUMN IF NOT EXISTS is_active   BOOLEAN DEFAULT TRUE;

-- Extend reports with full flag validation fields
ALTER TABLE reports ADD COLUMN IF NOT EXISTS flag_valid         BOOLEAN  DEFAULT NULL;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS vuln_slug          VARCHAR(100);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS points_awarded     INTEGER  DEFAULT 0;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS first_blood        BOOLEAN  DEFAULT FALSE;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS validation_message TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS affected_asset     VARCHAR(200);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS screenshot_path    VARCHAR(500);

-- Researcher stats table (updated automatically on valid report)
CREATE TABLE IF NOT EXISTS researcher_stats (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    total_points     INTEGER DEFAULT 0,
    valid_reports    INTEGER DEFAULT 0,
    invalid_reports  INTEGER DEFAULT 0,
    duplicate_reports INTEGER DEFAULT 0,
    first_bloods     INTEGER DEFAULT 0,
    rank             INTEGER,
    updated_at       TIMESTAMP DEFAULT NOW()
);

-- First blood tracking (one per vuln_slug globally)
CREATE TABLE IF NOT EXISTS first_blood_claims (
    id         SERIAL PRIMARY KEY,
    vuln_slug  VARCHAR(100) UNIQUE NOT NULL,
    user_id    INTEGER REFERENCES users(id),
    report_id  INTEGER REFERENCES reports(id),
    claimed_at TIMESTAMP DEFAULT NOW()
);

-- One valid completion per user per vuln (for challenge tracking)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_vuln_complete
    ON user_flags(user_id, flag_slug);

CREATE TABLE IF NOT EXISTS employees (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, full_name VARCHAR(100), email VARCHAR(100), department VARCHAR(50), job_title VARCHAR(100), phone VARCHAR(30), location VARCHAR(80), salary INTEGER, ssn_last4 VARCHAR(4), access_level VARCHAR(20) DEFAULT 'standard', internal_notes TEXT, is_active BOOLEAN DEFAULT true, hire_date DATE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS invoices (id SERIAL PRIMARY KEY, invoice_number VARCHAR(30) UNIQUE, user_id INTEGER REFERENCES users(id), company_name VARCHAR(100), amount DECIMAL(10,2), tax_amount DECIMAL(10,2), status VARCHAR(20) DEFAULT 'paid', billing_email VARCHAR(100), card_last4 VARCHAR(4), notes TEXT, due_date DATE DEFAULT NOW()+30, created_at TIMESTAMP DEFAULT NOW());
CREATE TABLE IF NOT EXISTS api_tokens_v2 (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), token VARCHAR(80) UNIQUE NOT NULL, name VARCHAR(100), scope TEXT, expires_at TIMESTAMP, is_revoked BOOLEAN DEFAULT false, last_used TIMESTAMP, created_at TIMESTAMP DEFAULT NOW());
CREATE TABLE IF NOT EXISTS tenants (id SERIAL PRIMARY KEY, slug VARCHAR(50) UNIQUE, name VARCHAR(100), plan VARCHAR(30), owner_user_id INTEGER REFERENCES users(id), config JSONB DEFAULT '{}', secret_key VARCHAR(80), created_at TIMESTAMP DEFAULT NOW());
CREATE TABLE IF NOT EXISTS tenant_memberships (id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id), user_id INTEGER REFERENCES users(id), role VARCHAR(20) DEFAULT 'member', UNIQUE(tenant_id, user_id));
CREATE TABLE IF NOT EXISTS webhooks (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), url VARCHAR(500), secret VARCHAR(80), events TEXT[], is_active BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT NOW());
