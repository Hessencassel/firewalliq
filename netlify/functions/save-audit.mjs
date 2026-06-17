// FirewallIQ — Save Audit to History
// Stores a summary of a completed audit (score, severity counts, finding titles)
// Never stores the raw config or full finding evidence.

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
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "authorization, content-type",
      },
    });
  }

  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

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

  let body;
  try { body = await req.json(); }
  catch { return json({ error: "Invalid request body." }, 400); }

  const { vendor, framework, score, criticalCount, highCount, mediumCount, lowCount, findingTitles } = body || {};

  if (!vendor || typeof vendor !== "string") return json({ error: "Missing vendor." }, 400);
  if (!framework || typeof framework !== "string") return json({ error: "Missing framework." }, 400);
  if (typeof score !== "number" || score < 0 || score > 100) return json({ error: "Invalid score." }, 400);
  if (!Array.isArray(findingTitles)) return json({ error: "Invalid finding titles." }, 400);

  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/audit_history`, {
      method: "POST",
      headers: { ...sbHeaders(), "Content-Type": "application/json", "Prefer": "return=representation" },
      body: JSON.stringify({
        user_id: sbUser.id,
        vendor,
        framework,
        score,
        critical_count: criticalCount || 0,
        high_count:     highCount     || 0,
        medium_count:   mediumCount   || 0,
        low_count:      lowCount      || 0,
        finding_titles: findingTitles.slice(0, 50),
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error("FIREWALLIQ: save-audit insert failed:", err);
      return json({ error: "Could not save audit." }, 502);
    }

    const rows = await res.json();
    return json({ success: true, id: rows?.[0]?.id });

  } catch (e) {
    console.error("FIREWALLIQ: save-audit error:", e.message);
    return json({ error: "Could not save audit." }, 502);
  }
};
