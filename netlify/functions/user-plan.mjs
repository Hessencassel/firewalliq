// FirewallIQ — User Plan Function
// Returns plan info for the logged-in user.
// Checks team_subscriptions (domain) first — skips consumer domains — then public.users (Pro).

import { isConsumerDomain } from "./consumer-domains.mjs";

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const PRO_AUDIT_LIMIT      = 30;

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

  // Validate JWT
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

  const email  = sbUser.email;
  const domain = email?.split("@")[1];

  // 1. Team check — domain lookup (skip consumer domains)
  if (domain && !isConsumerDomain(domain)) {
    try {
      const res = await fetch(
        `${SUPABASE_URL}/rest/v1/team_subscriptions?domain=eq.${encodeURIComponent(domain)}&active=eq.true&select=domain,owner_email,created_at`,
        { headers: sbHeaders() }
      );
      const rows = await res.json();
      const team = rows?.[0];
      if (team) {
        return json({
          email,
          plan: "team",
          planLabel: "FirewallIQ Team",
          hasActivePlan: true,
          isTeam: true,
          teamDomain: team.domain,
          auditsUsed: null,
          auditsPerMonth: -1,
          auditsRemaining: -1,
        });
      }
    } catch (e) {
      console.error("FIREWALLIQ: team lookup error:", e.message);
    }
  }

  // 2. Pro check
  try {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/users?id=eq.${sbUser.id}&select=plan,audits_used,billing_period_start`,
      { headers: sbHeaders() }
    );
    const rows = await res.json();
    const record = rows?.[0];

    if (!record?.plan) {
      return json({ email, plan: null, planLabel: null, hasActivePlan: false,
                    auditsUsed: 0, auditsPerMonth: 0, auditsRemaining: 0 });
    }

    const used      = record.audits_used ?? 0;
    const remaining = Math.max(0, PRO_AUDIT_LIMIT - used);

    return json({
      email,
      plan: "pro",
      planLabel: "FirewallIQ Pro",
      hasActivePlan: true,
      isTeam: false,
      auditsUsed: used,
      auditsPerMonth: PRO_AUDIT_LIMIT,
      auditsRemaining: remaining,
      billingPeriodStart: record.billing_period_start,
    });

  } catch (e) {
    console.error("FIREWALLIQ: user-plan error:", e.message);
    return json({ error: "Could not fetch plan info." }, 502);
  }
};
