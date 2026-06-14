// FirewallIQ — Stripe Webhook Function
// Handles checkout.session.completed
// Creates Netlify Identity user and sends invite email

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET = process.env.FIREWALLIQ_WEBHOOK_SECRET;
const NETLIFY_ACCESS_TOKEN = process.env.NETLIFY_ACCESS_TOKEN;
const NETLIFY_SITE_ID = process.env.NETLIFY_SITE_ID;
const SITE_URL = "https://firewalliq.io";

// Verify Stripe webhook signature
async function verifyStripeSignature(payload, sigHeader, secret) {
  const parts = sigHeader.split(",");
  let timestamp = "";
  let signature = "";
  for (const part of parts) {
    const [key, value] = part.split("=");
    if (key === "t") timestamp = value;
    if (key === "v1") signature = value;
  }
  if (!timestamp || !signature) return false;
  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(signedPayload));
  const expected = Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  return expected === signature;
}

// Create or invite user in Netlify Identity
async function inviteIdentityUser(email, plan) {
  const identityUrl = `https://api.netlify.com/api/v1/sites/${NETLIFY_SITE_ID}/identity/users`;

  const response = await fetch(identityUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${NETLIFY_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      send_invite: true,
      data: {
        plan,
        plan_label: plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team",
        audits_used: 0,
        period_start: new Date().toISOString(),
      },
    }),
  });

  const result = await response.json();

  if (!response.ok) {
    if (response.status === 422 || result.msg?.includes("already")) {
      console.log(`FIREWALLIQ: user already exists, updating plan — ${email}`);
      await updateUserPlan(email, plan);
      return { updated: true };
    }
    throw new Error(`Identity API error: ${JSON.stringify(result)}`);
  }

  console.log(`FIREWALLIQ: identity user invited — ${email} plan=${plan}`);
  return result;
}

// Update plan for existing user
async function updateUserPlan(email, plan) {
  const listUrl = `https://api.netlify.com/api/v1/sites/${NETLIFY_SITE_ID}/identity/users?search=${encodeURIComponent(email)}`;
  const listRes = await fetch(listUrl, {
    headers: { "Authorization": `Bearer ${NETLIFY_ACCESS_TOKEN}` },
  });
  const list = await listRes.json();
  const user = list.users?.find(u => u.email === email);
  if (!user) return;

  const updateUrl = `https://api.netlify.com/api/v1/sites/${NETLIFY_SITE_ID}/identity/users/${user.id}`;
  await fetch(updateUrl, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${NETLIFY_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      data: {
        plan,
        plan_label: plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team",
        audits_used: 0,
        period_start: new Date().toISOString(),
      },
    }),
  });
}

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const sigHeader = req.headers.get("stripe-signature");
  if (!sigHeader) return new Response("Missing signature", { status: 400 });

  const payload = await req.text();

  if (WEBHOOK_SECRET) {
    const valid = await verifyStripeSignature(payload, sigHeader, WEBHOOK_SECRET);
    if (!valid) {
      console.error("FIREWALLIQ: invalid webhook signature");
      return new Response("Invalid signature", { status: 400 });
    }
  }

  let event;
  try {
    event = JSON.parse(payload);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  console.log(`FIREWALLIQ: webhook received — type=${event.type}`);

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email;
    const plan = session.metadata?.plan || "pro";

    console.log(`FIREWALLIQ: payment complete — plan=${plan} email=${email}`);

    if (email && NETLIFY_ACCESS_TOKEN && NETLIFY_SITE_ID) {
      try {
        await inviteIdentityUser(email, plan);
        console.log(`FIREWALLIQ: identity user created/invited — ${email}`);
      } catch (e) {
        console.error("FIREWALLIQ: identity user creation failed:", e.message);
      }
    } else {
      console.warn("FIREWALLIQ: missing email or Netlify credentials");
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const subscription = event.data.object;
    console.log(`FIREWALLIQ: subscription cancelled — ${subscription.id}`);
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
