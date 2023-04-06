export const config = {
  runtime: 'edge',
}

export default async (req: Request) => {
  let pathname = new URL(req.url).pathname;

  // Fetch from the backend.
  const r = await fetch(
    process.env.UPSTREAM + pathname,
  )

  const nonce = crypto.randomUUID();

  let csp = r.headers.get('content-security-policy-report-only') || '';
  csp = csp.replace(/script-src /, "script-src 'strict-dynamic' 'nonce-MAGICNONCE' ");
  csp = csp.replace(/MAGICNONCE/g, nonce);
  csp = csp.replace(/'unsafe-inline' 'unsafe-eval'/g, "'unsafe-eval'");

  let body = await r.text();
  body = body.replace(/<script/g, "<script nonce=\"MAGICNONCE\"");
  body = body.replace(/MAGICNONCE/g, nonce);

  return new Response(body, {
    status: r.status,
    headers: {
      // Allow list of backend headers.
      'content-security-policy-report-only': csp,
      'content-type': r.headers.get('content-type') || '',
    },
  })
}
