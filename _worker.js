// HTTP Basic Auth for the entire site (Workers Static Assets).
//
// Credentials come from Worker environment variables:
//   BASIC_AUTH_USER  — the username
//   BASIC_AUTH_PASS  — the password
// Set these in: Workers & Pages → this Worker → Settings → Variables and Secrets.
// (The "cannot add variables" warning disappears once this file is deployed,
//  because the Worker now has code, not just static assets.)

const REALM = 'Renaissance Rentals — Staff';

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

export default {
  async fetch(request, env) {
    const expectedUser = env.BASIC_AUTH_USER;
    const expectedPass = env.BASIC_AUTH_PASS;

    // Fail closed if env vars aren't set yet — never serve the site unprotected.
    if (!expectedUser || !expectedPass) {
      return new Response(
        'Site auth is not configured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS in Worker → Settings → Variables and Secrets, then redeploy.',
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

    // Authenticated — serve the requested static asset.
    return env.ASSETS.fetch(request);
  },
};
