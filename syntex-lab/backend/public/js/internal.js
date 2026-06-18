/**
 * Syntex Solutions — Internal Route Map
 * DO NOT COMMIT — Added to .gitignore but somehow ended up in /js/
 * Last modified: 2024-11-28 by developer@syntex.local
 *
 * TODO (SYN-2041): Remove from public assets before v3.0 launch
 */

const INTERNAL_ENDPOINTS = {
    api_v1: [
        '/api/v1/users',
        '/api/v1/users/me',
        '/api/v1/users/:id',
        '/api/v1/products',
        '/api/v1/orders',
        '/api/v1/orders/:id',
        '/api/v1/token',
        '/api/v1/fetch',
        '/api/v1/debug/env',
        '/api/v1/docs',
    ],
    api_v2: [
        '/api/v2/internal/config',
        '/api/v2/users/export',
        '/api/v2/users/export?format=csv',
        '/api/v2/admin/reset-all',
        '/api/v2/tickets/:id',
        '/api/v2/webhook',
        '/api/v2/search',
        '/api/v2/avatar',
    ],
    admin: [
        '/admin',
        '/admin/users',
        '/admin/settings',
        '/admin/logs',
        '/admin/ping',
        '/admin/execute',     // NOTE: For internal debugging only
    ],
    misc: [
        '/.env',
        '/.git/config',
        '/backup.sql',
        '/config.json',
        '/debug',
        '/phpinfo.php',
        '/metrics',
        '/_profiler',
        '/web.config',
        '/staging',
        '/old-portal',
        '/page',
        '/go',
        '/api/fetch-url',
        '/health',
    ],
    subdomains: [
        'api.syntex.local',
        'admin.syntex.local',
        'staging.syntex.local',
        'dev.syntex.local',
        'mail.syntex.local',
        'backup.syntex.local',
        'vpn.syntex.local',
        'intranet.syntex.local',
        'developers.syntex.local',
    ],
};

// Service-to-service tokens — rotate every 90 days
// Last rotation: 2024-09-01
const SERVICE_TOKENS = {
    monitoring:  'mon_9x8y7z6w5v4u3t2s1r0q_syntex',
    backup:      'bak_1a2b3c4d5e6f7g8h9i0j_syntex',
    deploy:      'dep_prod_secret_2024_zxcvbnm_syntex',
    ci_pipeline: 'ci_ghp_FakeGitHubTokenForLabOnly1234567',
    vault:       'hvs.CAESIFakeVaultTokenForLabPractice',
    internal_rpc: SYNTEX_CONFIG.internal_api + ' key=' + SYNTEX_CONFIG._debug_token,
};

// Export for other modules
if (typeof module !== 'undefined') {
    module.exports = { INTERNAL_ENDPOINTS, SERVICE_TOKENS };
}
