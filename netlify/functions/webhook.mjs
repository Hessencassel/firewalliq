// FirewallIQ — Stripe Webhook Function
// Handles checkout.session.completed
// Creates Netlify Identity user and sends invite email

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET = process.env.FIREWALLIQ_WEBHOOK_SECRET;
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

async function inviteIdentityUser(email, plan, context) {
  const identity = context?.identity;
  if (!identity?.url || !identity?.token) {
    throw new Error("Identity context not available in this function");
  }

  const response = await fetch(`${identity.url}/invite`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${identity.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      data: {
        plan,
        plan_label: plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team",
      },
    }),
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(`Invite failed: ${JSON.stringify(result)}`);
  }
  return result;
}

export default async (req, context) => {
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

    if (email) {
      try {
        await inviteIdentityUser(email, plan, context);
        console.log(`FIREWALLIQ: identity user created/invited — ${email}`);
      } catch (e) {
        console.error("FIREWALLIQ: identity user creation failed:", e.message);
      }
    } else {
      console.warn("FIREWALLIQ: missing email");
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
