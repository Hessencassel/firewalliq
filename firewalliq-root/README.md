# FirewallIQ — core audit engine (MVP)

Paste a single device's running configuration, pick a compliance framework, and get a scored, control-mapped audit report with vendor-specific CLI remediation. Configurations are processed in memory and never stored.

This is the **engine layer** only — no login or billing yet. Its purpose is to let you validate audit quality against real configs before the accounts/Stripe layer is added.

**Launch coverage:** Cisco ASA / FTD, FortiGate (FortiOS), Palo Alto (PAN-OS) · PCI DSS v4.0, CIS Benchmarks.

---

## Deploy to Netlify

### Option A — GitHub → Netlify (recommended, matches your usual flow)
1. Create a new GitHub repo and push these files to it.
2. In Netlify: **Add new site → Import an existing project**, pick the repo.
3. Leave build settings as detected (the `netlify.toml` here sets everything). Deploy.

### Option B — drag and drop
1. Drag this whole folder into the Netlify dashboard (**Sites → Add new site → Deploy manually**).

### Required: set your API key
In Netlify: **Site configuration → Environment variables → Add a variable**

| Key | Value |
|---|---|
| `ANTHROPIC_API_KEY` | your Anthropic API key |

Then **redeploy** so the function picks it up. The key lives only in Netlify's server-side environment — never in the code or the browser.

### Optional: change the model
| Key | Value | Default |
|---|---|---|
| `FIREWALLIQ_MODEL` | any Claude model string | `claude-sonnet-4-6` |

---

## Test it
1. Open the deployed site.
2. Paste a real config (or upload a file). The appliance type is auto-detected; override the dropdown if needed.
3. Pick a framework and **Run audit**.
4. Read the score and findings, check the evidence and remediation against what you'd expect, and **Export report** to PDF.

The thing to validate: are the findings accurate, are the control references right, and is the CLI remediation correct for the platform? That sign-off is the gate before we build accounts and billing.

---

## What's here
```
index.html                     the tool (UI, streaming client, PDF export)
netlify/functions/audit.mjs    the audit engine (composes prompts, scrubs secrets, streams Claude)
netlify.toml                   Netlify config
package.json                   ESM, no dependencies
```

## What's next (not in this build)
- Accounts and login (Supabase)
- Subscriptions and usage limits (Stripe)
- Saved audit history
- More vendors (Check Point, SonicWall, Juniper, pfSense/OPNsense…) and frameworks (HIPAA, NIST 800-53)

## Notes
- The audit function **streams** its response so it doesn't hit Netlify's synchronous function timeout on larger configs.
- Obvious secrets (passwords, pre-shared keys, SNMP communities, key material) are redacted before anything leaves your function.
- The vendor and framework prompt blocks in `audit.mjs` are a first pass — refine them against configs you trust; that content is the real moat.
