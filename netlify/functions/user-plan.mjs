// FirewallIQ — User Plan Function
// Returns the current user's plan info from Netlify Identity

const SITE_URL = "https://firewalliq.io";

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
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return json({ error: "Not authenticated." }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const res = await fetch(`${SITE_URL}/.netlify/identity/user`, {
      headers: { "Authorization": `Bearer ${token}` },
    });

    if (!res.ok) {
      return json({ error: "Session expired. Please log in again." }, 401);
    }

    const user = await res.json();
    const plan = user.user_metadata?.plan || user.app_metadata?.plan || null;
    const planLabel = plan === "pro" ? "FirewallIQ Pro" : plan === "team" ? "FirewallIQ Team" : null;
    const auditsPerMonth = plan === "pro" ? 30 : plan === "team" ? -1 : 0;

    return json({
      email: user.email,
      plan,
      planLabel,
      auditsPerMonth,
      hasActivePlan: !!plan,
    });

  } catch (e) {
    console.error("FIREWALLIQ: user-plan error:", e.message);
    return json({ error: "Could not fetch plan info." }, 502);
  }
};
