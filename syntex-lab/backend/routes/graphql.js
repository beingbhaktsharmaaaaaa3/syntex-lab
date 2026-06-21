'use strict';

// ── GraphQL Vulnerable Module ─────────────────────────────────────
// Vulnerabilities: Introspection enabled, IDOR on user/order queries,
// sensitive field over-fetching (password_hash, api_key, secret_note),
// broken auth on mutations, mass data exposure
//
// Practice with:  graphql-cop, InQL, Burp Suite InQL extension

const { graphql, buildSchema } = require('graphql');
const db = require('../database/db');

// ── Schema definition ─────────────────────────────────────────────
// VULNERABILITY: Over-fetching — password_hash, api_key, secret_note exposed
const schema = buildSchema(`
  type User {
    id: Int
    username: String
    email: String
    role: String
    first_name: String
    last_name: String
    department: String
    job_title: String
    api_key: String
    secret_note: String
    password_hash: String
    bio: String
    created_at: String
    last_login: String
  }

  type Product {
    id: Int
    name: String
    slug: String
    price: Float
    category: String
    sku: String
    description: String
    version: String
    stock: Int
  }

  type Order {
    id: Int
    user_id: Int
    quantity: Int
    unit_price: Float
    total_price: Float
    status: String
    invoice_number: String
    license_key: String
    notes: String
    coupon_code: String
    discount: Float
    shipping_address: String
    created_at: String
    user: User
    product: Product
  }

  type SearchResult {
    type: String
    id: Int
    title: String
    url: String
  }

  type MutationResult {
    success: Boolean
    message: String
    user: User
  }

  type Query {
    # Returns currently authenticated user
    me: User

    # VULNERABILITY: IDOR — no ownership check, returns any user's data
    # including password_hash, api_key, secret_note
    user(id: Int!): User

    # VULNERABILITY: Mass data exposure — dumps all users with sensitive fields
    allUsers(limit: Int): [User]

    # Products (safe)
    product(id: Int!): Product
    products(category: String): [Product]

    # VULNERABILITY: IDOR — any authenticated user can read any order
    order(id: Int!): Order

    # VULNERABILITY: Returns ALL orders, not just current user's
    orders(limit: Int): [Order]

    # VULNERABILITY: SQLi via search query
    search(query: String!, type: String): [SearchResult]

    # Introspection (enabled by default — reveals full schema)
    _schema: String
  }

  type Mutation {
    # VULNERABILITY: No ownership check — can update any user's role
    # Payload: mutation { updateUser(id:2, role:"admin") { id role } }
    updateUser(id: Int!, role: String, email: String, bio: String): MutationResult

    # VULNERABILITY: No auth required — can delete any user
    deleteUser(id: Int!): MutationResult

    # VULNERABILITY: Client-supplied price (business logic)
    createOrder(productId: Int!, quantity: Int!, unitPrice: Float): MutationResult
  }
`);

// ── Resolvers ─────────────────────────────────────────────────────
function buildRoot(currentUser) {
    return {
        // ── Queries ──────────────────────────────────────────────
        me: async () => {
            if (!currentUser) return null;
            const r = await db.query(`SELECT * FROM users WHERE id=$1`, [currentUser.id]);
            return r.rows[0] || null;
        },

        // VULNERABILITY: IDOR — returns any user's full record
        user: async ({ id }) => {
            const r = await db.query(`SELECT * FROM users WHERE id=$1`, [id]);
            return r.rows[0] || null;
        },

        // VULNERABILITY: No auth — mass data exposure
        allUsers: async ({ limit = 50 }) => {
            const r = await db.query(
                `SELECT * FROM users ORDER BY id LIMIT $1`, [limit]
            );
            return r.rows;
        },

        product: async ({ id }) => {
            const r = await db.query(`SELECT * FROM products WHERE id=$1`, [id]);
            return r.rows[0] || null;
        },

        products: async ({ category }) => {
            let q = `SELECT * FROM products WHERE is_active=true`;
            // VULNERABILITY: SQLi via category
            if (category) q += ` AND category='${category}'`;
            const r = await db.query(q);
            return r.rows;
        },

        // VULNERABILITY: IDOR — any user reads any order
        order: async ({ id }) => {
            const r = await db.query(
                `SELECT o.*, p.name as product_name FROM orders o
                 LEFT JOIN products p ON p.id=o.product_id WHERE o.id=$1`, [id]
            );
            if (!r.rows.length) return null;
            const o = r.rows[0];
            // Resolve nested user
            const u = await db.query(`SELECT * FROM users WHERE id=$1`, [o.user_id]);
            o.user = u.rows[0];
            return o;
        },

        // VULNERABILITY: Returns ALL orders regardless of user
        orders: async ({ limit = 100 }) => {
            const r = await db.query(
                `SELECT o.*, p.name as product_name FROM orders o
                 LEFT JOIN products p ON p.id=o.product_id
                 ORDER BY o.created_at DESC LIMIT $1`, [limit]
            );
            return r.rows;
        },

        // VULNERABILITY: SQLi via query param
        search: async ({ query, type }) => {
            const r = await db.query(
                `SELECT 'product' as type, id, name as title,
                        '/products/'||id as url
                 FROM products WHERE name ILIKE '%${query}%'`
            );
            return r.rows;
        },

        // ── Mutations ─────────────────────────────────────────────

        // VULNERABILITY: Broken auth — privilege escalation
        // No check that currentUser owns this account or is admin
        updateUser: async ({ id, role, email, bio }) => {
            try {
                const fields = [];
                const vals   = [];
                let   i      = 1;
                if (role)  { fields.push(`role=$${i++}`);  vals.push(role);  }
                if (email) { fields.push(`email=$${i++}`); vals.push(email); }
                if (bio)   { fields.push(`bio=$${i++}`);   vals.push(bio);   }
                if (!fields.length) return { success: false, message: 'No fields to update' };
                vals.push(id);
                await db.query(`UPDATE users SET ${fields.join(',')} WHERE id=$${i}`, vals);
                const r = await db.query(`SELECT * FROM users WHERE id=$1`, [id]);
                return { success: true, message: `User ${id} updated`, user: r.rows[0] };
            } catch (err) {
                return { success: false, message: err.message };
            }
        },

        // VULNERABILITY: No auth — delete any user
        deleteUser: async ({ id }) => {
            try {
                await db.query(`DELETE FROM users WHERE id=$1`, [id]);
                return { success: true, message: `User ${id} deleted` };
            } catch (err) {
                return { success: false, message: err.message };
            }
        },

        // VULNERABILITY: Client-supplied price
        createOrder: async ({ productId, quantity, unitPrice }) => {
            if (!currentUser) return { success: false, message: 'Not authenticated' };
            const prod = await db.query(`SELECT * FROM products WHERE id=$1`, [productId]);
            if (!prod.rows.length) return { success: false, message: 'Product not found' };
            const price = unitPrice || prod.rows[0].price; // takes client price
            const total = price * quantity;
            const inv   = 'INV-GQL-' + Date.now();
            await db.query(
                `INSERT INTO orders (user_id,product_id,quantity,unit_price,total_price,invoice_number)
                 VALUES ($1,$2,$3,$4,$5,$6)`,
                [currentUser.id, productId, quantity, price, total, inv]
            );
            return { success: true, message: `Order created. Total: $${total}` };
        },
    };
}

// ── Express handler ───────────────────────────────────────────────
async function graphqlHandler(req, res) {
    const { query, variables, operationName } = req.method === 'POST'
        ? req.body
        : { query: req.query.query, variables: {} };

    if (!query) {
        // Serve GraphiQL playground
        return res.type('html').send(graphiqlHtml(req.baseUrl || '/graphql'));
    }

    try {
        const result = await graphql({
            schema,
            source:         query,
            rootValue:      buildRoot(req.session?.user || req.jwtUser || null),
            variableValues: variables || {},
            operationName,
        });
        res.json(result);
    } catch (err) {
        res.status(500).json({ errors: [{ message: err.message }] });
    }
}

// ── GraphiQL HTML ─────────────────────────────────────────────────
function graphiqlHtml(endpoint) {
    return `<!DOCTYPE html><html>
<head>
  <title>GraphiQL — Syntex API</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/graphiql/3.0.6/graphiql.min.css">
</head>
<body style="margin:0;">
  <div id="graphiql" style="height:100vh;"></div>
  <script crossorigin src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
  <script crossorigin src="https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js"></script>
  <script crossorigin src="https://cdnjs.cloudflare.com/ajax/libs/graphiql/3.0.6/graphiql.min.js"></script>
  <script>
    const fetcher = GraphiQL.createFetcher({ url: '${endpoint}' });
    ReactDOM.createRoot(document.getElementById('graphiql'))
      .render(React.createElement(GraphiQL, { fetcher,
        defaultQuery: \`# Syntex GraphQL API — Vulnerable by Design
# Try these attacks:
#
# 1. Introspection (schema discovery):
{ __schema { types { name fields { name } } } }
#
# 2. IDOR — read admin's secret_note and api_key:
# { user(id: 1) { username email secret_note api_key password_hash } }
#
# 3. Mass user dump with password hashes:
# { allUsers { id username email password_hash api_key secret_note role } }
#
# 4. Privilege escalation:
# mutation { updateUser(id: 2, role: "admin") { success message } }
#
# 5. IDOR on orders:
# { order(id: 6) { notes license_key user { email api_key } } }
\` }));
  </script>
</body></html>`;
}

module.exports = { graphqlHandler };
