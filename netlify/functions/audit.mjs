// FirewallIQ — core audit engine (Netlify Function v2, streaming)
//
// Auth flow:
//   1. Validate Supabase JWT
//   2. Extract email domain — skip team check if consumer domain (gmail etc.)
//      Otherwise check team_subscriptions for active domain match
//      → Team match: unlimited audits, no counter
//   3. If no team match, check public.users for active Pro plan
//      → Pro: enforce 30 audit/month limit, increment counter
//
// Configs processed in memory only — nothing stored.

import { isConsumerDomain } from "./consumer-domains.mjs";

const MODEL                = process.env.FIREWALLIQ_MODEL || "claude-sonnet-4-6";
const ANTHROPIC_VERSION    = "2023-06-01";
const MAX_TOKENS           = 8000;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const PRO_AUDIT_LIMIT      = 30;

const VENDORS = {
  cisco_asa:   "Cisco ASA / FTD (Firepower Threat Defense)",
  fortigate:   "Fortinet FortiGate (FortiOS)",
  palo_alto:   "Palo Alto Networks (PAN-OS)",
  checkpoint:  "Check Point Gaia (R80/R81)",
  sonicwall:   "SonicWall (SonicOS)",
  sophos:      "Sophos Firewall (SFOS)",
  watchguard:  "WatchGuard Firebox (Fireware)",
  juniper_srx: "Juniper SRX (Junos)",
  pfsense:     "pfSense / OPNsense",
};

const FRAMEWORKS = {
  pci_dss_4:   "PCI DSS v4.0",
  cis:         "CIS Benchmarks (vendor-specific)",
  hipaa:       "HIPAA Security Rule (45 CFR Part 164)",
  nist_800_53: "NIST SP 800-53 Rev 5",
};

// --- Vendor knowledge blocks ---
const VENDOR_BLOCKS = {
  cisco_asa: `PLATFORM: Cisco ASA / FTD (Firepower Threat Defense).
A "running-config" from an ASA is flat CLI. FTD is ASA-like but managed by FMC; assess only what is present.
Audit these areas and cite the exact line as evidence:
- Access policy: any-any permits, overly broad rules, "permit ip any any", missing explicit deny with logging.
- NAT: overly broad or identity NAT exposing internal hosts.
- Management plane: telnet enabled (must be SSH only), "http server enable" scope, SSH version 2 only, login/exec timeouts, "service password-encryption", banner present.
- AAA & accounts: local-only auth vs TACACS+/RADIUS, default or weak usernames, "enable password" strength.
- Logging: logging enabled, logging host/buffered, trap severity, logging of denied traffic.
- SNMP: v2c community strings vs SNMPv3 with auth/priv.
- NTP: configured and authenticated.
- VPN/crypto: IKEv1 vs IKEv2, weak DH groups (1/2/5), weak transforms (DES/3DES/MD5), missing PFS.
Remediation must use real ASA/FTD CLI.`,

  fortigate: `PLATFORM: Fortinet FortiGate (FortiOS). Config is block-structured: "config ... / edit ... / set ... / next / end".
Audit these areas and cite the exact line as evidence:
- Firewall policy: any-any or overly broad policies, missing security profiles (av, ips, webfilter), "set logtraffic all" missing.
- Interfaces/zones: untrusted interfaces with admin access enabled (http/telnet/ping).
- Admin access: trusted hosts not set, HTTP/Telnet admin enabled, "set admintimeout" too high, password-policy, two-factor missing.
- SNMP: v1/v2c communities vs SNMPv3.
- Logging: syslogd / FortiAnalyzer forwarding, event logging on.
- VPN/crypto: weak DH groups (1/2/5), DES/3DES, IKEv1 aggressive mode.
Remediation must use real FortiOS CLI.`,

  palo_alto: `PLATFORM: Palo Alto Networks (PAN-OS). Config may be set-format CLI or XML; interpret either.
Audit these areas and cite the exact element as evidence:
- Security policy: any-any rules, rules without Security Profile Groups, "action allow" with "log-end no", port-based rules.
- Management profile: mgmt profiles permitting HTTP/Telnet, permitted-IP not restricted.
- Admin & auth: superuser sprawl, local-only admins, no MFA, weak password complexity.
- Logging: log forwarding profiles attached, traffic logged at session end.
- Threat prevention: missing AV, Anti-Spyware, Vulnerability, URL filtering profiles.
- IKE/IPsec crypto: weak DH groups, 3DES/DES, MD5, missing PFS.
Remediation must use real PAN-OS set-CLI.`,

  checkpoint: `PLATFORM: Check Point Gaia (R80/R81). Config may be Gaia CLI or policy exports.
Audit these areas and cite the exact element as evidence:
- Security policy: any-any rules, permissive rulebase, missing cleanup rule with logging, stealth rule absent.
- Management access: Gaia portal exposed broadly, SSH restricted to management hosts only, idle timeout set.
- Admin accounts: default admin account renamed, strong password policy, role-based access.
- Logging: logs sent to Smart Log / Log Server, track set on all rules, implied rules logged.
- SNMP: v1/v2c communities vs SNMPv3.
- NTP: configured and synced.
Remediation must use real Gaia CLI or SmartConsole policy guidance.`,

  sonicwall: `PLATFORM: SonicWall (SonicOS). Config is typically exported XML or CLI.
Audit these areas and cite the exact element as evidence:
- Access rules: any-to-any rules, rules missing application control, logging disabled on rules.
- Management: HTTP management enabled, management restricted to specific hosts, inactivity timeout.
- Admin accounts: default "admin" password, additional admin accounts.
- Logging: syslog server configured, logging on deny rules.
- SNMP: community strings, SNMPv3 preferred.
- VPN: IKEv1 aggressive mode, weak DH groups, DES/3DES.
Remediation must use real SonicOS guidance.`,

  sophos: `PLATFORM: Sophos Firewall (SFOS). Config is typically XML export or CLI.
Audit these areas and cite the exact element as evidence:
- Firewall rules: any-any rules, rules missing IPS/web/app control policies, logging disabled.
- Management: HTTP admin access, admin allowed from untrusted zones, inactivity timeout.
- Admin accounts: default credentials, unused accounts, super admin sprawl.
- Logging: syslog forwarding configured, log all denied traffic.
- VPN: IPsec using weak ciphers (DES, MD5, DH group 1/2/5).
Remediation must use real SFOS CLI or admin console guidance.`,

  watchguard: `PLATFORM: WatchGuard Firebox (Fireware). Config is typically XML export.
Audit these areas and cite the exact element as evidence:
- Firewall policies: any-any policies, policies missing Application Control or IPS, logging disabled.
- Management: management access allowed from any IP, HTTP admin enabled.
- Admin accounts: default admin/status accounts, password strength.
- Logging: WatchGuard Log Server or syslog configured, denied packets logged.
- SNMP: v2c community strings, SNMPv3 with auth/priv.
- VPN: weak phase1/2 proposals, aggressive mode IKEv1, missing PFS.
Remediation must use real Fireware CLI or Policy Manager guidance.`,

  juniper_srx: `PLATFORM: Juniper SRX (Junos). Config is Junos hierarchical CLI.
Audit these areas and cite the exact element as evidence:
- Security policies: permit-all rules, policies missing application inspection or IDP, logging disabled.
- Zones: management zone not restricted, fxp0 accessible from untrusted zones.
- Management: Telnet enabled, management restricted to specific hosts.
- Authentication: local-only auth vs RADIUS/TACACS+, root login permitted from network.
- Logging: syslog to remote server, log on deny policies.
- SNMP: v2c communities vs SNMPv3.
- VPN/IKE: weak DH groups, DES/3DES/MD5, IKEv1 aggressive mode.
Remediation must use real Junos set-CLI.`,

  pfsense: `PLATFORM: pfSense / OPNsense. Config is XML export or CLI.
Audit these areas and cite the exact element as evidence:
- Firewall rules: pass-any rules on WAN, missing block rules, no logging on rules.
- Management: WebGUI accessible from WAN, HTTP instead of HTTPS, SSH with root login.
- Admin accounts: default admin account, password strength.
- Logging: remote syslog configured, firewall logging enabled.
- SNMP: community strings if installed, SNMPv3 preferred.
- VPN: weak cipher suites (DES, BF-CBC, MD5), TLS auth missing on OpenVPN.
Remediation must use real pfSense/OPNsense GUI or CLI guidance.`,
};

// --- Framework blocks ---
const FRAMEWORK_BLOCKS = {
  pci_dss_4: `FRAMEWORK: PCI DSS v4.0. Map each finding to a real requirement number:
- 1.2.1 Configuration standards for NSCs defined and applied.
- 1.2.5 Only necessary services, protocols, and ports are allowed.
- 1.3.1 / 1.3.2 Inbound and outbound traffic to/from the CDE restricted.
- 1.4.1 NSCs implemented between trusted and untrusted networks.
- 2.2.1 / 2.2.2 Configuration standards; no vendor default accounts/passwords.
- 2.2.7 Non-console administrative access is encrypted (no Telnet/HTTP).
- 8.3 / 8.4 Strong authentication and MFA for administrative access.
- 10.2.x / 10.4 Audit logs capture access and security events.
Where a control cannot be confirmed from the provided config, state that explicitly.`,

  cis: `FRAMEWORK: CIS Benchmarks (vendor-specific). Map each finding to the relevant CIS control area.
Core CIS control areas for firewalls:
- Management plane hardening: disable Telnet/HTTP, SSHv2 only, restrict management, idle timeouts, login banner.
- Authentication & accounts: centralized AAA, no default/shared accounts, strong password policy, MFA.
- Logging & monitoring: NTP with auth, syslog to central server, log denied traffic.
- Data plane: deny-by-default, anti-spoofing, no any-any rules.
- SNMP: SNMPv3 with auth/priv; no v2c communities.
- Secure VPN: strong DH groups, AES, SHA, PFS enabled.`,

  hipaa: `FRAMEWORK: HIPAA Security Rule (45 CFR Part 164). Map each finding to the relevant safeguard:
- 164.312(a)(1) Access Control: unique user IDs, automatic logoff, encryption.
- 164.312(b) Audit Controls: activity logs on systems containing ePHI.
- 164.312(d) Person Authentication: verify identity before granting access.
- 164.312(e)(1) Transmission Security: encrypt ePHI in transit (TLS 1.2+, no weak ciphers).
- 164.308(a)(3) Workforce Access Management: least privilege, no shared accounts.
Where a control cannot be confirmed from the provided config, state that explicitly.`,

  nist_800_53: `FRAMEWORK: NIST SP 800-53 Rev 5. Map each finding to the relevant control:
- AC-2 Account Management: no default/shared accounts, inactive accounts disabled.
- AC-3 Access Enforcement: deny-by-default, least privilege on rules.
- AC-17 Remote Access: encrypted remote access, MFA, session timeouts.
- AU-2 / AU-3 Audit Events: log success/failure with sufficient detail.
- CM-6 Configuration Settings: hardened configuration baselines applied.
- CM-7 Least Functionality: disable unnecessary services/ports/protocols.
- IA-2 Identification and Authentication: MFA for privileged accounts.
- SC-8 Transmission Confidentiality: encrypt management and VPN traffic.
Where a control cannot be confirmed from the provided config, state that explicitly.`,
};

function scrubSecrets(text) {
  return text
    .replace(/(\bpre-shared-key\s+)(\S+)/gi,           "$1[REDACTED]")
    .replace(/(\bpassword\s+)(\S+)/gi,                 "$1[REDACTED]")
    .replace(/(\bsecret\s+[05]\s+)(\S+)/gi,            "$1[REDACTED]")
    .replace(/(\benable\s+(?:password|secret)\s+)(\S+)/gi, "$1[REDACTED]")
    .replace(/(\bsnmp-server\s+community\s+)(\S+)/gi,  "$1[REDACTED]")
    .replace(/(\bset\s+vpn\s+ipsec\s+.*pre-shared-secret\s+)(\S+)/gi, "$1[REDACTED]");
}

function buildSystem(vendor, framework) {
  return `You are FirewallIQ, an expert network security auditor specialising in firewall compliance.
${VENDOR_BLOCKS[vendor] || ""}
${FRAMEWORK_BLOCKS[framework] || ""}

OUTPUT FORMAT — strict Markdown, no deviations:

# Compliance Audit Report

## Executive Summary
2-3 sentences: overall risk posture, compliance readiness, most critical issue.

## Compliance Score
**Score: XX / 100**
Scoring: start at 100; deduct 15-20 for each Critical, 8-12 for each High, 3-6 for each Medium, 1-2 for each Low. Floor at 0.

## Findings

For EACH finding use this exact structure:

### [SEVERITY] Finding Title
**Severity:** Critical | High | Medium | Low
**Framework Control:** [exact requirement number or control name]
**Evidence:** \`exact config line or element that triggered this finding\`
**Risk:** One sentence explaining the specific risk.
**Remediation:**
\`\`\`
exact CLI commands to fix the issue
\`\`\`

## Passed Controls
List 3-6 things the config does correctly, with brief explanation.

## Summary Table
| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| **Total** | **N** |

Rules:
- Never invent config lines. Only cite what is literally present in the config.
- If you cannot confirm a control, say "Cannot confirm from provided config."
- Remediation commands must be real, working CLI for the specified platform.
- Do not add commentary outside the defined structure.`;
}

function buildUser(vendor, framework, config) {
  return `Audit the following ${VENDORS[vendor]} configuration against ${FRAMEWORKS[framework]}.

--- BEGIN CONFIGURATION ---
${config}
--- END CONFIGURATION ---`;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

// ── Auth helpers ───────────────────────────────────────────────────────────

function sbHeaders() {
  return {
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "apikey": SUPABASE_SERVICE_KEY,
  };
}

// Step 1: validate JWT, return Supabase user
async function getSupabaseUser(token) {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { ...sbHeaders() , "Authorization": `Bearer ${token}` },
  });
  if (!res.ok) return null;
  return res.json();
}

// Step 2a: check team_subscriptions by domain
async function getTeamSubscription(domain) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/team_subscriptions?domain=eq.${encodeURIComponent(domain)}&active=eq.true&select=domain,owner_email`,
    { headers: sbHeaders() }
  );
  if (!res.ok) return null;
  const rows = await res.json();
  return rows?.[0] || null;
}

// Step 2b: check public.users for Pro plan + usage
async function getProUser(userId) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/users?id=eq.${userId}&select=plan,audits_used,billing_period_start`,
    { headers: sbHeaders() }
  );
  if (!res.ok) return null;
  const rows = await res.json();
  return rows?.[0] || null;
}

async function resetProUsage(userId) {
  await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${userId}`, {
    method: "PATCH",
    headers: { ...sbHeaders(), "Content-Type": "application/json", "Prefer": "return=minimal" },
    body: JSON.stringify({ audits_used: 0, billing_period_start: new Date().toISOString() }),
  });
}

async function incrementProUsage(userId) {
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/increment_audits_used?schema=internal`, {
    method: "POST",
    headers: { ...sbHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId }),
  });
}

// ── Main auth + plan validation ────────────────────────────────────────────

async function validateUser(authHeader) {
  if (!authHeader?.startsWith("Bearer ")) {
    return { valid: false, error: "Please log in to run an audit." };
  }
  const token = authHeader.slice(7);

  // 1. Validate JWT
  const sbUser = await getSupabaseUser(token).catch(() => null);
  if (!sbUser?.id) {
    return { valid: false, error: "Session expired. Please log in again." };
  }

  const email  = sbUser.email;
  const domain = email?.split("@")[1];

  // 2. Team check — domain match beats everything, unless it's a consumer domain
  if (domain && !isConsumerDomain(domain)) {
    const team = await getTeamSubscription(domain).catch(() => null);
    if (team) {
      console.log(`FIREWALLIQ: team auth — email=${email} domain=${domain}`);
      return { valid: true, userId: sbUser.id, email, plan: "team", isTeam: true };
    }
  }

  // 3. Pro check — individual plan + usage limit
  const proRecord = await getProUser(sbUser.id).catch(() => null);
  if (!proRecord?.plan) {
    return { valid: false, error: "No active plan found. Please purchase a subscription." };
  }

  // Reset counter if billing period has rolled over (fallback to 30-day window)
  const periodStart      = new Date(proRecord.billing_period_start);
  const daysSincePeriod  = (Date.now() - periodStart) / 86400000;
  let auditsUsed         = proRecord.audits_used;

  if (daysSincePeriod >= 30) {
    await resetProUsage(sbUser.id).catch(() => {});
    auditsUsed = 0;
  }

  if (auditsUsed >= PRO_AUDIT_LIMIT) {
    return {
      valid: false,
      error: `Monthly audit limit reached (${PRO_AUDIT_LIMIT}/month on Pro). Upgrade to Team for unlimited audits.`,
    };
  }

  console.log(`FIREWALLIQ: pro auth — email=${email} used=${auditsUsed}/${PRO_AUDIT_LIMIT}`);
  return { valid: true, userId: sbUser.id, email, plan: "pro", isTeam: false, auditsUsed };
}

// ── Main handler ───────────────────────────────────────────────────────────

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey)              return json({ error: "The audit engine is not configured." }, 500);
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY)
                            return json({ error: "Auth backend is not configured." }, 500);

  const auth = await validateUser(req.headers.get("authorization"));
  if (!auth.valid) return json({ error: auth.error }, 401);

  let body;
  try   { body = await req.json(); }
  catch { return json({ error: "Invalid request body." }, 400); }

  const { config, vendor, framework } = body || {};
  if (!config?.trim())        return json({ error: "Paste a configuration to audit." }, 400);
  if (!VENDORS[vendor])       return json({ error: `Unsupported vendor: ${vendor}` }, 400);
  if (!FRAMEWORKS[framework]) return json({ error: `Unsupported framework: ${framework}` }, 400);

  const scrubbed = scrubSecrets(config);
  console.log(`FIREWALLIQ: audit — vendor=${vendor} framework=${framework} plan=${auth.plan} chars=${scrubbed.length}`);

  // Increment Pro usage counter (Team has no counter)
  if (!auth.isTeam) {
    await incrementProUsage(auth.userId).catch(e =>
      console.error("FIREWALLIQ: usage increment failed:", e.message)
    );
  }

  let upstream;
  try {
    upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: MAX_TOKENS,
        system: buildSystem(vendor, framework),
        stream: true,
        messages: [{ role: "user", content: buildUser(vendor, framework, scrubbed) }],
      }),
    });
  } catch (e) {
    console.error("FIREWALLIQ: Anthropic fetch failed:", e.message);
    return json({ error: "Could not reach the audit engine. Try again." }, 502);
  }

  if (!upstream.ok || !upstream.body) {
    const detail = await upstream.text().catch(() => "");
    console.error(`FIREWALLIQ: Anthropic error ${upstream.status}:`, detail.slice(0, 400));
    return json({ error: "The audit engine returned an error.", detail: detail.slice(0, 600) }, 502);
  }

  const stream = new ReadableStream({
    async start(controller) {
      const reader  = upstream.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      let buffer = "", charCount = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith("data:")) continue;
            const data = trimmed.slice(5).trim();
            if (!data || data === "[DONE]") continue;
            try {
              const evt = JSON.parse(data);
              if (evt.type === "content_block_delta" && evt.delta?.type === "text_delta") {
                charCount += evt.delta.text.length;
                controller.enqueue(encoder.encode(evt.delta.text));
              }
            } catch { /* ignore */ }
          }
        }
        console.log(`FIREWALLIQ: stream complete — chars=${charCount}`);
      } catch (e) {
        console.error("FIREWALLIQ: stream error:", e.message);
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
};
