interface Props { dark: boolean }

export default function Authentication({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Authentication</h1>

      <p className={p}>
        The web dashboard and API use JWT (JSON Web Tokens) for authentication. This page covers the
        authentication flow, password hashing, token management, and API authentication.
      </p>

      <h2 className={h2}>JWT Authentication Flow</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`1. Client sends POST /api/auth/login with username and password
2. Server verifies credentials against stored bcrypt hash
3. Server generates a signed JWT with user claims
4. Client stores the JWT and includes it in subsequent requests
5. Server validates the JWT signature and expiration on each request

Timeline:
┌──────────┐                           ┌──────────┐
│  Client  │                           │  Server  │
└────┬─────┘                           └────┬─────┘
     │  POST /api/auth/login                │
     │  { username, password }              │
     │─────────────────────────────────────▶│
     │                                      │ verify bcrypt hash
     │  200 OK                              │
     │  { token: "eyJhbG..." }              │
     │◀─────────────────────────────────────│
     │                                      │
     │  GET /api/stats                      │
     │  Authorization: Bearer eyJhbG...     │
     │─────────────────────────────────────▶│
     │                                      │ validate JWT
     │  200 OK { ... }                      │
     │◀─────────────────────────────────────│`}</code></pre>

      <h2 className={h2}>Password Hashing</h2>

      <p className={p}>
        Passwords are hashed using bcrypt (cost factor 10) via the <code className={ic}>labyrinth hash</code> CLI command.
        The plaintext password is never stored.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Hash a password
labyrinth hash --password "my-secure-password"
# Output: $2a$10$K7L/FqkZxJ2b...

# Verify a password against a hash
labyrinth hash --verify --password "my-secure-password" --hash '$2a$10$K7L/FqkZxJ2b...'
# Output: Password matches`}</code></pre>

      <h2 className={h2}>Token Lifetime</h2>

      <p className={p}>
        JWT tokens expire after the configured <code className={ic}>web.token_lifetime</code> (default: 24 hours).
        After expiration, the client must re-authenticate.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`web:
  token_lifetime: "24h"    # token valid for 24 hours
  jwt_secret: ""           # auto-generated if empty (changes on restart)`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Important:</strong> If <code className={ic}>jwt_secret</code> is left empty,
          Labyrinth generates a random secret on startup. This means all tokens are invalidated on restart.
          Set a fixed secret in production to persist sessions across restarts.
        </p>
      </div>

      <h2 className={h2}>API Authentication</h2>

      <p className={p}>
        All API endpoints (except <code className={ic}>/health</code>, <code className={ic}>/ready</code>, and
        {' '}<code className={ic}>/api/auth/login</code>) require a valid JWT token. Include it in the
        {' '}<code className={ic}>Authorization</code> header:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Authenticate
TOKEN=$(curl -s -X POST http://localhost:9153/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"your-password"}' | jq -r '.token')

# Use the token
curl -s http://localhost:9153/api/stats \\
  -H "Authorization: Bearer $TOKEN" | jq .

# Flush cache (requires auth)
curl -s -X POST http://localhost:9153/api/cache/flush \\
  -H "Authorization: Bearer $TOKEN"`}</code></pre>

      <h2 className={h2}>WebSocket Authentication</h2>

      <p className={p}>
        The WebSocket endpoint (<code className={ic}>/ws/queries</code>) accepts the JWT token as a query parameter
        since the WebSocket protocol does not support custom headers during the handshake:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`ws://localhost:9153/ws/queries?token=eyJhbGciOiJIUzI1NiIs...`}</code></pre>

      <h2 className={h2}>JWT Token Structure</h2>

      <p className={p}>
        The JWT payload contains:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`{
  "sub": "admin",           // username
  "iat": 1700000000,        // issued at (Unix timestamp)
  "exp": 1700086400,        // expires at (issued + token_lifetime)
  "iss": "labyrinth"        // issuer
}`}</code></pre>

      <h2 className={h2}>Security Recommendations</h2>

      <ul className={ul}>
        <li>Set a strong, fixed <code className={ic}>jwt_secret</code> in production (at least 32 characters)</li>
        <li>Use HTTPS (via reverse proxy) to protect tokens in transit</li>
        <li>Set <code className={ic}>token_lifetime</code> appropriately (shorter is more secure, longer is more convenient)</li>
        <li>The dashboard stores the JWT in <code className={ic}>localStorage</code>; use HTTPS to prevent XSS token theft</li>
        <li>Rotate the <code className={ic}>jwt_secret</code> periodically to invalidate all existing tokens</li>
      </ul>
    </div>
  )
}
