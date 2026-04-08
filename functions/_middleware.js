// HTTP Basic Auth for the entire Pages project.
// Credentials come from Cloudflare Pages environment variables:
//   BASIC_AUTH_USER  — the username
//   BASIC_AUTH_PASS  — the password
// Set these in: Pages project → Settings → Environment variables.

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

export const onRequest = async ({ request, next, env }) => {
  const expectedUser = env.BASIC_AUTH_USER;
  const expectedPass = env.BASIC_AUTH_PASS;

  // If env vars aren't set, fail closed rather than serving the site unprotected.
  if (!expectedUser || !expectedPass) {
    return new Response(
      'Site auth is not configured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS in Pages → Settings → Environment variables.',
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

  const userOk = safeEqual(user, expectedUser);
  const passOk = safeEqual(pass, expectedPass);
  if (!(userOk && passOk)) {
    return unauthorized();
  }

  // Authenticated — serve the requested asset.
  return next();
};
