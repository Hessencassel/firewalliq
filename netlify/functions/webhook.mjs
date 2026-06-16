// FirewallIQ — Stripe Webhook Function
//
// Pro plan:  upserts individual user record in public.users
// Team plan: upserts domain record in public.team_subscriptions
//            domain is extracted from the purchaser's email automatically
//
// Events handled:
//   checkout.session.completed      — new subscription, link plan
//   invoice.paid                    — billing renewal, reset Pro usage counter
//   customer.subscription.updated   — plan change / upgrade / downgrade
//   customer.subscription.deleted   — cancellation, deactivate plan

const STRIPE_SECRET_KEY    = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET       = process.env.FIREWALLIQ_WEBHOOK_SECRET;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// ── Stripe signature verification ─────────────────────────────────────────

async function verifyStripeSignature(payload, sigHeader, secret) {
  const parts = sigHeader.split(",");
  let timestamp = "", signature = "";
  for (const part of parts) {
    const [key, value] = part.split("=");
    if (key === "t")  timestamp = value;
    if (key === "v1") signature = value;
  }
  if (!timestamp || !signature) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const encoder  = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(signedPayload));
  const expected  = Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  return expected === signature;
}

// ── Supabase helpers ───────────────────────────────────────────────────────

function sbHeaders() {
  return {
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "apikey": SUPABASE_SERVICE_KEY,
    "Content-Type": "application/json",
    "Prefer": "resolution=merge-duplicates,return=minimal",
  };
}

async function findSupabaseUserByEmail(email) {
  const res = await fetch(
    `${SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
    { headers: { "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`, "apikey": SUPABASE_SERVICE_KEY } }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return data?.users?.[0] || null;
}

// ── Pro: upsert individual user record ────────────────────────────────────

async function upsertProUser({ email, stripeCustomerId, stripeSubscriptionId }) {
  const sbUser = await findSupabaseUserByEmail(email);

  if (!sbUser) {
    console.log(`FIREWALLIQ [pro]: Supabase user not found for ${email} — will link on signup`);
    return { linked: false, email };
  }

  const res = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
    method: "POST",
    headers: sbHeaders(),
    body: JSON.stringify({
      id: sbUser.id,
      email,
      plan: "pro",
      audits_used: 0,
      billing_period_start: new Date().toISOString(),
      stripe_customer_id: stripeCustomerId || null,
      stripe_subscription_id: stripeSubscriptionId || null,
    }),
  });

  if (!res.ok) throw new Error(`Pro upsert failed: ${await res.text()}`);
  return { linked: true, userId: sbUser.id, email };
}

// ── Team: upsert domain record ────────────────────────────────────────────

async function upsertTeamSubscription({ email, stripeCustomerId, stripeSubscriptionId }) {
  const domain = email.split("@")[1];
  if (!domain) throw new Error(`Could not extract domain from email: ${email}`);

  const res = await fetch(`${SUPABASE_URL}/rest/v1/team_subscriptions`, {
    method: "POST",
    headers: sbHeaders(),
    body: JSON.stringify({
      domain,
      owner_email: email,
      stripe_customer_id: stripeCustomerId || null,
      stripe_subscription_id: stripeSubscriptionId || null,
      active: true,
    }),
  });

  if (!res.ok) throw new Error(`Team upsert failed: ${await res.text()}`);
  console.log(`FIREWALLIQ [team]: domain ${domain} activated — owner=${email}`);
  return { domain, email };
}

// ── Cancellation helpers ──────────────────────────────────────────────────

async function deactivateProByCustomerId(stripeCustomerId) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/users?stripe_customer_id=eq.${encodeURIComponent(stripeCustomerId)}`,
    { method: "PATCH", headers: sbHeaders(), body: JSON.stringify({ plan: null, stripe_subscription_id: null }) }
  );
  if (!res.ok) throw new Error(`Pro deactivate failed: ${await res.text()}`);
}

async function deactivateTeamBySubscriptionId(stripeSubscriptionId) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/team_subscriptions?stripe_subscription_id=eq.${encodeURIComponent(stripeSubscriptionId)}`,
    { method: "PATCH", headers: sbHeaders(), body: JSON.stringify({ active: false }) }
  );
  if (!res.ok) throw new Error(`Team deactivate failed: ${await res.text()}`);
}

// ── Usage reset on billing renewal (Pro only) ─────────────────────────────

async function resetProUsageBySubscriptionId(stripeSubscriptionId) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/users?stripe_subscription_id=eq.${encodeURIComponent(stripeSubscriptionId)}`,
    {
      method: "PATCH",
      headers: sbHeaders(),
      body: JSON.stringify({ audits_used: 0, billing_period_start: new Date().toISOString() }),
    }
  );
  if (!res.ok) throw new Error(`Pro usage reset failed: ${await res.text()}`);
}

// ── Main handler ──────────────────────────────────────────────────────────

export default async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

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
  try { event = JSON.parse(payload); }
  catch { return new Response("Invalid JSON", { status: 400 }); }

  console.log(`FIREWALLIQ: webhook — type=${event.type}`);

  // ── checkout.session.completed ────────────────────────────────
  if (event.type === "checkout.session.completed") {
    const session        = event.data.object;
    const email          = session.customer_details?.email || session.customer_email;
    const plan           = session.metadata?.plan || "pro";
    const customerId     = session.customer;
    const subscriptionId = session.subscription;

    console.log(`FIREWALLIQ: payment complete — plan=${plan} email=${email}`);

    if (!email) {
      console.warn("FIREWALLIQ: no email on session — cannot link plan");
    } else {
      try {
        if (plan === "team") {
          await upsertTeamSubscription({ email, stripeCustomerId: customerId, stripeSubscriptionId: subscriptionId });
        } else {
          const result = await upsertProUser({ email, stripeCustomerId: customerId, stripeSubscriptionId: subscriptionId });
          if (!result.linked) {
            console.log(`FIREWALLIQ [pro]: ${email} not yet signed up — plan will link on first login`);
          }
        }
      } catch (e) {
        console.error(`FIREWALLIQ: plan link failed [${plan}]:`, e.message);
      }
    }
  }

  // ── invoice.paid — reset Pro usage counter on renewal ─────────
  if (event.type === "invoice.paid") {
    const invoice        = event.data.object;
    const subscriptionId = invoice.subscription;
    // Only reset Pro; Team has no counter
    if (subscriptionId) {
      try {
        await resetProUsageBySubscriptionId(subscriptionId);
        console.log(`FIREWALLIQ: Pro usage reset — subscription=${subscriptionId}`);
      } catch (e) {
        // May be a Team subscription — not an error
        console.log(`FIREWALLIQ: usage reset skipped (likely Team) — ${e.message}`);
      }
    }
  }

  // ── customer.subscription.deleted — cancellation ──────────────
  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object;
    const plan = sub.metadata?.plan || "pro";

    try {
      if (plan === "team") {
        await deactivateTeamBySubscriptionId(sub.id);
        console.log(`FIREWALLIQ: Team domain deactivated — subscription=${sub.id}`);
      } else {
        await deactivateProByCustomerId(sub.customer);
        console.log(`FIREWALLIQ: Pro plan deactivated — customer=${sub.customer}`);
      }
    } catch (e) {
      console.error("FIREWALLIQ: deactivation failed:", e.message);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
