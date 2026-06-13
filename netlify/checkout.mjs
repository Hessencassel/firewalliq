// FirewallIQ — Stripe Checkout Function
// Creates a Stripe Checkout session and returns the URL

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const PRO_PRICE_ID = process.env.STRIPE_PRO_PRICE_ID;
const TEAM_PRICE_ID = process.env.STRIPE_TEAM_PRICE_ID;
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
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type",
      },
    });
  }

  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  if (!STRIPE_SECRET_KEY) return json({ error: "Stripe not configured." }, 500);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  const { plan } = body || {};
  if (!plan || !["pro", "team"].includes(plan)) {
    return json({ error: "Invalid plan. Choose pro or team." }, 400);
  }

  const priceId = plan === "pro" ? PRO_PRICE_ID : TEAM_PRICE_ID;
  const planLabel = plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team";

  try {
    const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        "mode": "subscription",
        "line_items[0][price]": priceId,
        "line_items[0][quantity]": "1",
        "success_url": `${SITE_URL}/success?session_id={CHECKOUT_SESSION_ID}&plan=${plan}`,
        "cancel_url": `${SITE_URL}/#pricing`,
        "allow_promotion_codes": "true",
        "billing_address_collection": "auto",
        "metadata[plan]": plan,
        "metadata[plan_label]": planLabel,
        "subscription_data[metadata][plan]": plan,
        ...(body.email ? { "customer_email": body.email } : {}),
      }),
    });

    const session = await response.json();

    if (!response.ok) {
      console.error("Stripe error:", session);
      return json({ error: session.error?.message || "Stripe error." }, 502);
    }

    console.log(`FIREWALLIQ: checkout session created — plan=${plan} session=${session.id}`);
    return json({ url: session.url });

  } catch (e) {
    console.error("FIREWALLIQ: checkout error:", e.message);
    return json({ error: "Could not create checkout session." }, 502);
  }
};
