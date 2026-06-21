'use strict';

// ── Lab Reset Script ──────────────────────────────────────────────
// Clears all user-generated lab data and re-seeds to factory state.
// Preserves schema and flags but removes reports, hint unlocks,
// challenge completions, uploaded files, and chat messages.
//
// Usage:
//   docker exec syntex_app node database/reset.js
//   npm run reset

const { Pool } = require('pg');

const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME     || 'syntex_db',
    user:     process.env.DB_USER     || 'syntex_admin',
    password: process.env.DB_PASS     || 'Synx@2024!Prod',
});

async function reset() {
    const client = await pool.connect();
    try {
        console.log('[RESET] Starting lab data reset...');
        await client.query('BEGIN');

        // Truncate user-generated data (preserve flags and hall_of_fame)
        const tables = [
            'lab_resets',
            'first_blood_claims',
            'researcher_stats',
            'user_flags',
            'hint_unlocks',
            'challenge_completions',
            'graphql_logs',
            'reward_claims',
            'chat_messages',
            'ticket_replies',
            'comments',
            'audit_logs',
            'notifications',
            'files',
            'api_tokens',
            'sessions_custom',
            'password_resets',
            'coupon_uses',
            'reports',
        ];

        for (const table of tables) {
            await client.query(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
            console.log(`[RESET] Cleared: ${table}`);
        }

        // Reset orders to seed state (keep original 7, delete user-created)
        await client.query(`DELETE FROM orders WHERE id > 7`);

        // Reset ticket internal notes to seed values
        await client.query(`UPDATE tickets SET internal_notes='FLAG{idor_ticket3_internal_staff_notes_q7r8s9t0} | Issue: EU VAT calculation bug confirmed.' WHERE id=3`);

        // Reset user wallets
        await client.query(`UPDATE users SET wallet_balance=100.00, wallet_bonus=0.00`);

        // Reset coupon used_count
        await client.query(`UPDATE coupons SET used_count=0`);

        // Re-initialise researcher_stats for all current users
        await client.query(`
            INSERT INTO researcher_stats (user_id, total_points, valid_reports, first_bloods)
            SELECT id, 0, 0, 0 FROM users
            ON CONFLICT (user_id) DO NOTHING
        `);

        // Log the reset
        await client.query(`INSERT INTO lab_resets DEFAULT VALUES`);

        await client.query('COMMIT');
        console.log('[RESET] ✅ Lab data reset complete. Ready for fresh hunting.');
        console.log('[RESET] Re-seeding notifications and comments...');

        // Re-seed a few items
        await client.query(`
            INSERT INTO notifications (user_id, title, message, type, link) VALUES
            (2,'Welcome back','Lab has been reset. Start hunting fresh.','info','/dashboard'),
            (1,'Lab Reset','All user data cleared.','warning','/admin')
        `);

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[RESET] ❌ Reset failed:', err.message);
        process.exit(1);
    } finally {
        client.release();
        await pool.end();
    }
}

reset();
