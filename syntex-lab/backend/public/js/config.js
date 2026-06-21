/**
 * Syntex Solutions — Client Application Configuration
 * Version: 2.4.1 | Build: 20241201-prod
 *
 * TODO: Migrate secrets to vault before v3.0 release
 * TODO: Remove debug token before prod push (blocked by JIRA SYN-1892)
 */

const SYNTEX = {
    env:        'production',
    version:    '2.4.1',
    api_base:   '/api/v1',
    api_v2:     '/api/v2',

    // API Keys — rotate quarterly (last rotated: 2024-06-01)
    api_key:    'sk_live_syntex_8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c',
    api_key_v2: 'v2_prod_c4b3a2z1y0x9w8v7u6t5s4r3q2p1o0n',

    // Third-party integrations
    stripe_pk:  'pk_live_51H_fake_lab_key_syntex_prod_abc123',
    analytics:  'UA-28471982-4',
    segment_key: '8xQv3kPpZrLmNfThYjUwEs2RbDcAgIoFu',

    // Internal service URLs — do not expose externally
    internal_api:    'http://internal-api.syntex.local:3001',
    metrics_url:     'http://prometheus.syntex.local:9090',
    vault_url:       'http://vault.syntex.local:8200',
    vault_token:     'hvs.CAESIFakeVaultTokenForLabPractice',

    // S3/Storage
    s3_bucket: 'syntex-uploads-prod',
    s3_region: 'us-east-1',
    cdn_url:   'https://cdn.syntex.local',

    // Feature flags
    features: {
        new_dashboard:  true,
        ai_assist:      false,
        beta_search:    true,
        debug_mode:     true,   // TODO: disable before release
        verbose_errors: true,
    },

    // Debug — REMOVE BEFORE PRODUCTION (SYN-1892)
    // alg:none token for admin — valid without signature
    _debug_token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5Ac3ludGV4LmxvY2FsIn0.',
    _debug_user:  { id: 1, username: 'admin', role: 'admin' },
};

// Expose globally for legacy compatibility
window.SYNTEX_CONFIG = SYNTEX;
