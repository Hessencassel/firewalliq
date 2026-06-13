// FirewallIQ — Stripe Webhook Function
// Handles checkout.session.completed and sends token email via Resend

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET = process.env.FIREWALLIQ_WEBHOOK_SECRET;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FIREWALLIQ_FROM_EMAIL || "noreply@firewalliq.io";

// Generate a token from session ID and plan
function generateToken(sessionId, plan) {
  const payload = `${sessionId}:${plan}:firewalliq`;
  return btoa(payload).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// Simple Stripe webhook signature verification
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
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(signedPayload);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
  const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return expectedSignature === signature;
}

async function sendTokenEmail(email, token, plan, planLabel) {
  const auditsText = plan === "pro" ? "30 audits per month" : "unlimited audits";

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0a101c;font-family:'IBM Plex Sans',system-ui,sans-serif;">
  <div style="max-width:560px;margin:40px auto;background:#111a2c;border:1px solid #1f2c44;border-radius:16px;overflow:hidden;">
    
    <!-- Header -->
    <div style="padding:28px 32px;border-bottom:1px solid #1f2c44;">
      <div style="display:flex;align-items:center;gap:10px;">
        <div style="width:32px;height:32px;background:linear-gradient(180deg,#14213a,#0d1424);border:1px solid #1f2c44;border-radius:8px;display:flex;align-items:center;justify-content:center;">
          <span style="color:#38bdf8;font-size:18px;">🛡</span>
        </div>
        <span style="color:#e8eef8;font-size:18px;font-weight:700;">Firewall<span style="color:#38bdf8;">IQ</span></span>
      </div>
    </div>

    <!-- Body -->
    <div style="padding:32px;">
      <h1 style="color:#e8eef8;font-size:22px;font-weight:700;margin:0 0 8px;letter-spacing:-0.02em;">
        Your ${planLabel} access is ready.
      </h1>
      <p style="color:#93a1bd;font-size:15px;margin:0 0 28px;line-height:1.6;">
        Thank you for subscribing to FirewallIQ ${planLabel}. Here is your audit token. 
        Keep it safe — you will need it to run audits.
      </p>

      <!-- Token box -->
      <div style="background:#0e1626;border:1px solid #1f2c44;border-radius:10px;padding:20px;margin-bottom:28px;">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:#64759a;margin-bottom:8px;">
          Your audit token
        </div>
        <div style="font-family:'IBM Plex Mono',monospace;font-size:14px;color:#38bdf8;word-break:break-all;line-height:1.5;">
          ${token}
        </div>
      </div>

      <!-- Plan details -->
      <div style="background:#0e1626;border:1px solid #1f2c44;border-radius:10px;padding:20px;margin-bottom:28px;">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:#64759a;margin-bottom:12px;">
          Your plan
        </div>
        <div style="color:#e8eef8;font-size:15px;font-weight:600;margin-bottom:4px;">${planLabel}</div>
        <div style="color:#93a1bd;font-size:14px;">${auditsText} · All 10 vendors · All 4 frameworks</div>
      </div>

      <!-- How to use -->
      <div style="margin-bottom:28px;">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:#64759a;margin-bottom:12px;">
          How to use
        </div>
        <ol style="color:#93a1bd;font-size:14px;line-height:1.8;margin:0;padding-left:20px;">
          <li>Go to <a href="https://firewalliq.io" style="color:#38bdf8;">firewalliq.io</a></li>
          <li>Paste your firewall configuration</li>
          <li>Enter your token when prompted</li>
          <li>Select your vendor and framework</li>
          <li>Click Run audit</li>
        </ol>
      </div>

      <!-- CTA -->
      <a href="https://firewalliq.io/#audit" style="display:block;background:#38bdf8;color:#04121e;text-align:center;padding:14px 24px;border-radius:10px;font-weight:600;font-size:15px;text-decoration:none;margin-bottom:28px;">
        Run your first audit →
      </a>

      <p style="color:#64759a;font-size:13px;line-height:1.6;margin:0;">
        Questions? Reply to this email or contact us at 
        <a href="mailto:support@firewalliq.io" style="color:#38bdf8;">support@firewalliq.io</a>.<br>
        Your subscription renews monthly. Manage billing at 
        <a href="https://billing.stripe.com" style="color:#38bdf8;">billing.stripe.com</a>.
      </p>
    </div>

    <!-- Footer -->
    <div style="padding:20px 32px;border-top:1px solid #1f2c44;">
      <p style="color:#64759a;font-size:12px;font-family:'IBM Plex Mono',monospace;margin:0;">
        FirewallIQ · Treesh Tech LLC · Fort Wayne, Indiana<br>
        Your configs are never stored. Zero storage architecture.
      </p>
    </div>

  </div>
</body>
</html>`;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: [email],
      subject: `Your FirewallIQ ${planLabel} token`,
      html,
    }),
  });

  const result = await response.json();
  if (!response.ok) {
    console.error("FIREWALLIQ: Resend error:", result);
    throw new Error(`Email failed: ${result.message || "unknown error"}`);
  }

  console.log(`FIREWALLIQ: token email sent to ${email}`);
  return result;
}

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const sigHeader = req.headers.get("stripe-signature");
  if (!sigHeader) {
    return new Response("Missing signature", { status: 400 });
  }

  const payload = await req.text();

  // Verify webhook signature
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
    const planLabel = plan === "pro" ? "FirewallIQ Pro" : "FirewallIQ Team";
    const token = generateToken(session.id, plan);

    console.log(`FIREWALLIQ: payment complete — plan=${plan} email=${email} session=${session.id}`);

    if (email && RESEND_API_KEY) {
      try {
        await sendTokenEmail(email, token, plan, planLabel);
      } catch (e) {
        console.error("FIREWALLIQ: email error:", e.message);
        // Do not return error — log it but acknowledge the webhook
      }
    } else {
      console.warn("FIREWALLIQ: no email or Resend key — token not sent:", token);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
