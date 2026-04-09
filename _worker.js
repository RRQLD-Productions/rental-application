// Routing + Basic Auth for the Renaissance Rentals Worker.
//
// This single Worker is bound to multiple custom domains:
//   - apply.renaissancerentalsqld.com  → public customer rental application
//                                        (no auth, root serves index.html)
//   - staff.renaissancerentalsqld.com  → internal staff hub
//                                        (Basic Auth required, root serves staff.html)
//
// Basic Auth credentials come from Worker environment variables:
//   BASIC_AUTH_USER  — the username
//   BASIC_AUTH_PASS  — the password
// Set these in: Workers & Pages → this Worker → Settings → Variables and Secrets.

const STAFF_HOST = 'staff.renaissancerentalsqld.com';
const STAFF_ROOT_FILE = '/staff.html';
const REALM = 'Renaissance Rentals — Staff';

// Files that exist in the assets directory but should ONLY be reachable
// via the staff host. On any other host (apply., etc.) they 404.
// Both with-extension and extensionless variants are blocked because
// Cloudflare static assets serves /foo.html at both /foo.html and /foo.
const STAFF_ONLY_PATHS = new Set([
  '/staff.html',
  '/staff',
  '/inspection.html',
  '/inspection',
  '/link-generator.html',
  '/link-generator',
  '/contract-generator.html',
  '/contract-generator',
]);

function unauthorized() {
  return new Response('Authentication required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Cache-Control': 'no-store',
    },
  });
}

// Constant-time string compare to avoid timing attacks.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function checkBasicAuth(request, env) {
  const expectedUser = env.BASIC_AUTH_USER;
  const expectedPass = env.BASIC_AUTH_PASS;

  // Fail closed if env vars aren't set yet — never serve the staff site unprotected.
  if (!expectedUser || !expectedPass) {
    return new Response(
      'Staff auth is not configured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS in Worker → Settings → Variables and Secrets, then redeploy.',
      { status: 503 }
    );
  }

  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Basic ')) {
    return unauthorized();
  }

  let decoded;
  try {
    decoded = atob(header.slice(6).trim());
  } catch {
    return unauthorized();
  }

  const sep = decoded.indexOf(':');
  if (sep === -1) return unauthorized();

  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);

  if (!(safeEqual(user, expectedUser) && safeEqual(pass, expectedPass))) {
    return unauthorized();
  }

  return null; // null means "auth passed, continue"
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isStaffHost = url.hostname === STAFF_HOST;

    if (isStaffHost) {
      // Lock down the entire staff host with Basic Auth.
      const authResponse = checkBasicAuth(request, env);
      if (authResponse) return authResponse;

      // Serve the hub at the bare URL.
      if (url.pathname === '/' || url.pathname === '') {
        const rewritten = new URL(request.url);
        rewritten.pathname = STAFF_ROOT_FILE;
        return env.ASSETS.fetch(new Request(rewritten.toString(), request));
      }

      // All other authenticated requests on the staff host: serve normally.
      return env.ASSETS.fetch(request);
    }

    // Public customer host (and any other host).
    // Block direct access to staff-only files so they can't be reached
    // unauthenticated by guessing the path.
    if (STAFF_ONLY_PATHS.has(url.pathname)) {
      return new Response('Not found', { status: 404 });
    }

    return env.ASSETS.fetch(request);
  },
};
