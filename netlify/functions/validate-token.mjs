// FirewallIQ — Token Validation Function
// Validates an audit token against Stripe to confirm active subscription

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

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

function decodeToken(token) {
  try {
    const padded = token.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(padded);
    const parts = decoded.split(":");
    if (parts.length !== 3 || parts[2] !== "firewalliq") return null;
    return { sessionId: parts[0], plan: parts[1] };
  } catch {
    return null;
  }
}

export default async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type",
      },
    });
  }

  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  const { token } = body || {};
  if (!token || !token.trim()) return json({ valid: false, error: "No token provided." });

  const decoded = decodeToken(token.trim());
  if (!decoded) return json({ valid: false, error: "Invalid token format." });

  try {
    // Verify the session exists in Stripe and is paid
    const response = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${decoded.sessionId}`,
      {
        headers: { "Authorization": `Bearer ${STRIPE_SECRET_KEY}` },
      }
    );

    const session = await response.json();

    if (!response.ok) {
      console.error("FIREWALLIQ: Stripe session lookup error:", session);
      return json({ valid: false, error: "Could not verify token." });
    }

    if (session.payment_status !== "paid") {
      return json({ valid: false, error: "Payment not completed." });
    }

    // Check subscription is still active
    if (session.subscription) {
      const subResponse = await fetch(
        `https://api.stripe.com/v1/subscriptions/${session.subscription}`,
        {
          headers: { "Authorization": `Bearer ${STRIPE_SECRET_KEY}` },
        }
      );
      const subscription = await subResponse.json();

      if (!["active", "trialing"].includes(subscription.status)) {
        return json({ valid: false, error: "Subscription is not active." });
      }
    }

    console.log(`FIREWALLIQ: token valid — plan=${decoded.plan} session=${decoded.sessionId}`);
    return json({
      valid: true,
      plan: decoded.plan,
      planLabel: decoded.plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team",
      auditsPerMonth: decoded.plan === "pro" ? 30 : -1,
    });

  } catch (e) {
    console.error("FIREWALLIQ: token validation error:", e.message);
    return json({ valid: false, error: "Validation error. Try again." });
  }
};
