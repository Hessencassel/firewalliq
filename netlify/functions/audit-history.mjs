// FirewallIQ — Audit History
// Returns the authenticated user's saved audit summaries, most recent first.
// Never returns raw config or full finding evidence — only score, severity
// counts, and generic finding titles.

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
    },
  });
}

function sbHeaders() {
  return {
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "apikey": SUPABASE_SERVICE_KEY,
  };
}

export default async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-headers": "authorization",
      },
    });
  }

  if (req.method !== "GET") return json({ error: "Method not allowed." }, 405);

  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return json({ error: "Not authenticated." }, 401);
  const token = authHeader.slice(7);

  let sbUser;
  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { ...sbHeaders(), "Authorization": `Bearer ${token}` },
    });
    if (!res.ok) return json({ error: "Session expired. Please log in again." }, 401);
    sbUser = await res.json();
  } catch {
    return json({ error: "Could not validate session." }, 502);
  }

  try {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/audit_history?user_id=eq.${sbUser.id}&select=id,vendor,framework,score,critical_count,high_count,medium_count,low_count,finding_titles,created_at&order=created_at.desc&limit=50`,
      { headers: sbHeaders() }
    );
    if (!res.ok) {
      const err = await res.text();
      console.error("FIREWALLIQ: audit-history fetch failed:", err);
      return json({ error: "Could not fetch history." }, 502);
    }
    const rows = await res.json();
    return json({ history: rows });

  } catch (e) {
    console.error("FIREWALLIQ: audit-history error:", e.message);
    return json({ error: "Could not fetch history." }, 502);
  }
};
