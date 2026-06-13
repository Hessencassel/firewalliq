// FirewallIQ — core audit engine (Netlify Function v2, streaming)
//
// Reads ANTHROPIC_API_KEY from the environment. Optionally FIREWALLIQ_MODEL.
// Configs are processed in memory only. Nothing is written to disk or stored.

const MODEL = process.env.FIREWALLIQ_MODEL || "claude-sonnet-4-6";
const ANTHROPIC_VERSION = "2023-06-01";
const MAX_TOKENS = 4000;

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
  pci_dss_4: "PCI DSS v4.0",
  cis:       "CIS Benchmarks (vendor-specific)",
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
Remediation must use real ASA/FTD CLI (e.g., "ssh version 2", "no telnet 0.0.0.0 0.0.0.0 outside", "snmp-server group ... v3 priv").`,

  fortigate: `PLATFORM: Fortinet FortiGate (FortiOS). Config is block-structured: "config ... / edit ... / set ... / next / end".
Audit these areas and cite the exact line as evidence:
- Firewall policy: any-any or overly broad policies, missing security profiles (av, ips, webfilter), "set logtraffic all" missing.
- Interfaces/zones: untrusted interfaces with admin access enabled (http/telnet/ping).
- Admin access: trusted hosts not set, HTTP/Telnet admin enabled, "set admintimeout" too high, password-policy, two-factor missing.
- SNMP: v1/v2c communities vs SNMPv3.
- Logging: syslogd / FortiAnalyzer forwarding, event logging on.
- VPN/crypto: weak DH groups (1/2/5), DES/3DES, IKEv1 aggressive mode.
Remediation must use real FortiOS CLI (config/edit/set/next/end).`,

  palo_alto: `PLATFORM: Palo Alto Networks (PAN-OS). Config may be set-format CLI or XML; interpret either.
Audit these areas and cite the exact element as evidence:
- Security policy: any-any rules, rules without Security Profile Groups, "action allow" with "log-end no", port-based rules.
- Management profile: mgmt profiles permitting HTTP/Telnet, permitted-IP not restricted.
- Admin & auth: superuser sprawl, local-only admins, no MFA, weak password complexity.
- Logging: log forwarding profiles attached, traffic logged at session end.
- Threat prevention: missing AV, Anti-Spyware, Vulnerability, URL filtering profiles.
- IKE/IPsec crypto: weak DH groups, 3DES/DES, MD5, missing PFS.
Remediation must use real PAN-OS set-CLI.`,

  checkpoint: `PLATFORM: Check Point Gaia (R80/R81). Config may be Gaia CLI ("set", "show") or policy exports.
Audit these areas and cite the exact element as evidence:
- Security policy: any-any rules, permissive rulebase, missing cleanup rule with logging, stealth rule absent (protecting firewall itself).
- Management access: Gaia portal exposed broadly, SSH restricted to management hosts only, idle timeout set.
- Admin accounts: default admin account renamed, strong password policy, role-based access.
- Logging: logs sent to Smart Log / Log Server, track set on all rules, implied rules logged.
- SNMP: v1/v2c communities vs SNMPv3.
- NTP: configured and synced.
- Backup and SIC: SIC certificate health, scheduled backups configured.
Remediation must use real Gaia CLI or SmartConsole policy guidance.`,

  sonicwall: `PLATFORM: SonicWall (SonicOS). Config is typically exported XML or CLI.
Audit these areas and cite the exact element as evidence:
- Access rules: any-to-any rules, rules missing application control or content filtering, logging disabled on rules.
- Management: HTTP management enabled (should be HTTPS only), management restricted to specific hosts, SSH enabled, inactivity timeout.
- Admin accounts: default "admin" account password, additional admin accounts, guest management accounts.
- Logging: syslog server configured, logging on deny rules, log redundancy filter.
- SNMP: community strings, SNMPv3 preferred.
- VPN: IKEv1 aggressive mode, weak DH groups, DES/3DES, pre-shared keys vs certificates.
- Geo-IP and botnet filtering enabled.
Remediation must use real SonicOS guidance.`,

  sophos: `PLATFORM: Sophos Firewall (SFOS). Config is typically XML export or CLI.
Audit these areas and cite the exact element as evidence:
- Firewall rules: any-any rules, rules missing IPS/web/app control policies, logging disabled.
- Management: HTTP admin access, admin allowed from untrusted zones, inactivity timeout, two-factor auth for admin.
- Admin accounts: default credentials, unused accounts, super admin sprawl.
- Logging: syslog forwarding configured, log all denied traffic, local logging retention.
- IPS and WAF policies: IPS policy applied to internet-facing rules, WAF enabled where applicable.
- VPN: IPsec phase1/2 using weak ciphers (DES, MD5, DH group 1/2/5), SSL VPN certificate validity.
- Email and web protection active.
Remediation must use real SFOS CLI or admin console guidance.`,

  watchguard: `PLATFORM: WatchGuard Firebox (Fireware). Config is typically XML export.
Audit these areas and cite the exact element as evidence:
- Firewall policies: any-any policies, policies missing Application Control or IPS, logging disabled on policies.
- Management: management access allowed from any IP, HTTP admin enabled, Firebox management restricted to trusted hosts.
- Admin accounts: default admin/status accounts, password strength, role-based access.
- Logging: WatchGuard Log Server or syslog configured, denied packets logged.
- SNMP: v2c community strings, SNMPv3 with auth/priv.
- VPN: weak phase1/2 proposals, aggressive mode IKEv1, missing PFS, pre-shared key length.
- Branch Office VPN certificate vs PSK usage.
Remediation must use real Fireware CLI or Policy Manager guidance.`,

  juniper_srx: `PLATFORM: Juniper SRX (Junos). Config is Junos hierarchical CLI ("set" format or bracketed).
Audit these areas and cite the exact element as evidence:
- Security policies: permit-all rules, policies missing application inspection or IDP, logging disabled ("log { session-close; }").
- Zones: management zone not restricted, fxp0 management interface accessible from untrusted zones.
- Management: Telnet enabled (should be SSH only), management restricted to specific hosts, login class permissions.
- Authentication: local-only auth vs RADIUS/TACACS+, root login permitted from network, idle-timeout on login classes.
- Logging: syslog to remote server, security log mode (stream vs event), log on deny policies.
- SNMP: v2c communities vs SNMPv3, restrict SNMP to management hosts.
- VPN/IKE: weak DH groups (group 1/2/5), DES/3DES/MD5, IKEv1 aggressive mode, missing PFS.
Remediation must use real Junos set-CLI.`,

  pfsense: `PLATFORM: pfSense / OPNsense. Config is XML export (config.xml) or CLI.
Audit these areas and cite the exact element as evidence:
- Firewall rules: pass-any rules on WAN, missing block rules, no logging on rules, anti-lockout rule scope.
- Management: WebGUI accessible from WAN, HTTP instead of HTTPS, management not restricted to LAN/VPN, SSH enabled with root login or password auth.
- Admin accounts: default admin account, password strength, additional accounts with unnecessary privileges.
- Logging: remote syslog configured, firewall logging enabled, auth logging enabled.
- SNMP: community strings if SNMP package installed, SNMPv3 preferred.
- VPN (OpenVPN/IPsec): weak cipher suites (DES, BF-CBC, MD5), TLS auth missing on OpenVPN, weak DH params.
- Packages: unneeded packages installed, outdated versions.
- DNS Resolver: DNS over TLS enabled, DNSSEC validation active.
Remediation must use real pfSense/OPNsense GUI or CLI guidance.`,
};

// --- Framework blocks ---
const FRAMEWORK_BLOCKS = {
  pci_dss_4: `FRAMEWORK: PCI DSS v4.0. Map each finding to a real requirement number:
- 1.2.1 Configuration standards for NSCs defined and applied.
- 1.2.5 Only necessary services, protocols, and ports are allowed.
- 1.2.6 Security features defined for any insecure services in use.
- 1.3.1 / 1.3.2 Inbound and outbound traffic to/from the CDE restricted to only what is necessary.
- 1.4.1 NSCs implemented between trusted and untrusted networks.
- 1.4.3 Anti-spoofing measures detect and block forged source IPs.
- 1.4.4 System components storing cardholder data not directly accessible from untrusted networks.
- 2.2.1 / 2.2.2 Configuration standards; no vendor default accounts/passwords.
- 2.2.7 Non-console administrative access is encrypted (no Telnet/HTTP).
- 8.3 / 8.4 Strong authentication and MFA for administrative access.
- 10.2.x / 10.4 Audit logs capture access and security events; logs reviewed.
Where a control cannot be confirmed from the provided config, state that explicitly.`,

  cis: `FRAMEWORK: CIS Benchmarks (vendor-specific). Map each finding to the relevant CIS control area. If unsure of an exact number, cite the control area precisely (e.g., "CIS Cisco ASA — Management Plane: disable Telnet").
Core CIS control areas for firewalls:
- Management plane hardening: disable Telnet/HTTP, SSHv2 only, restrict management to specific hosts, idle timeouts, login banner.
- Authentication & accounts: centralized AAA, no default/shared accounts, strong password policy, MFA for admins.
- Logging & monitoring: NTP with authentication, syslog to central server, appropriate severity, log denied traffic.
- Data plane: deny-by-default, anti-spoofing, no any-any rules, segment trusted/untrusted.
- SNMP: SNMPv3 with auth/priv; no public/private or v2c communities.
- Secure VPN: strong DH groups, AES (not DES/3DES), SHA (not MD5), PFS enabled.`,
};

function scrubSecrets(text) {
  let out = String(text);
  out = out.replace(
    /\b(password|passwd|secret|pre-shared-key|key-string|psksecret|passphrase|ppk|psk)\b(\s+(?:\d+|ENC|7|5))?\s+\S+/gi,
    (_m, kw, enc) => `${kw}${enc || ""} [REDACTED]`
  );
  out = out.replace(/\bsnmp-server\s+community\s+\S+/gi, "snmp-server community [REDACTED]");
  out = out.replace(/\bset\s+(psksecret|passwd|password|passphrase|private-key)\b.*$/gim, "set $1 [REDACTED]");
  out = out.replace(/<phash>[\s\S]*?<\/phash>/gi, "<phash>[REDACTED]</phash>");
  out = out.replace(/<key>[\s\S]*?<\/key>/gi, "<key>[REDACTED]</key>");
  return out;
}

function buildSystem(vendor, framework) {
  return `You are FirewallIQ, a senior firewall and network-security configuration auditor. You audit a single device's running configuration against a compliance framework and produce an evidence-based report.

${VENDOR_BLOCKS[vendor]}

${FRAMEWORK_BLOCKS[framework]}

RULES
- Be precise and evidence-based. For every finding, quote the exact configuration element as "evidence". If a control cannot be assessed, set evidence to "Not present in the provided configuration" and treat it as a gap.
- Remediation must be concrete, copy-pasteable CLI wherever possible.
- Include a few notable "pass" findings for controls that are correctly configured.

SEVERITY
- critical: directly exploitable or major compliance failure (permit any-any, plaintext management, default credentials, no logging).
- high: significant weakness or gap likely to fail an audit.
- medium: hardening gap or partial compliance.
- low: minor or best-practice.
- pass: control is satisfied.

SCORE
Start at 100. Subtract: critical -20 to -25, high -10 to -12, medium -4, low -2. Do not subtract for pass. Floor at 0.
Labels: 0-49 "At risk", 50-69 "Needs work", 70-84 "Fair", 85-94 "Strong", 95-100 "Hardened".

OUTPUT
Respond with ONLY a single valid JSON object. No markdown, no code fences, no preamble, no text before or after the JSON. Start your response with { and end with }.

{
  "score": <integer 0-100>,
  "score_label": "<label>",
  "summary": "<2-3 sentence executive summary>",
  "findings": [
    {
      "id": "F1",
      "severity": "critical|high|medium|low|pass",
      "title": "<short finding title>",
      "control": "<framework control reference>",
      "evidence": "<exact config line(s) or 'Not present in the provided configuration'>",
      "remediation": "<concrete CLI or steps to fix>"
    }
  ]
}`;
}

function buildUser(vendor, framework, config) {
  return `Audit the following ${VENDORS[vendor]} configuration against ${FRAMEWORKS[framework]}. Return only the JSON object. Start with { and end with }.

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

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error("FIREWALLIQ: ANTHROPIC_API_KEY is not set.");
    return json(
      { error: "The audit engine is not configured. Set ANTHROPIC_API_KEY in Netlify environment variables." },
      500
    );
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  const { config, vendor, framework } = body || {};
  if (!config || !String(config).trim()) return json({ error: "Paste a configuration to audit." }, 400);
  if (!VENDORS[vendor])    return json({ error: `Unsupported vendor: ${vendor}` }, 400);
  if (!FRAMEWORKS[framework]) return json({ error: `Unsupported framework: ${framework}` }, 400);

  const scrubbed = scrubSecrets(config);
  console.log(`FIREWALLIQ: audit started — vendor=${vendor} framework=${framework} config_chars=${scrubbed.length}`);

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
        messages: [
          { role: "user", content: buildUser(vendor, framework, scrubbed) },
        ],
      }),
    });
  } catch (e) {
    console.error("FIREWALLIQ: fetch to Anthropic failed:", e.message);
    return json({ error: "Could not reach the audit engine. Try again." }, 502);
  }

  if (!upstream.ok || !upstream.body) {
    const detail = await upstream.text().catch(() => "");
    console.error(`FIREWALLIQ: Anthropic API error ${upstream.status}:`, detail.slice(0, 400));
    return json({ error: "The audit engine returned an error. Check your API key and credits.", detail: detail.slice(0, 600) }, 502);
  }

  console.log("FIREWALLIQ: Anthropic stream started, forwarding to client...");

  const stream = new ReadableStream({
    async start(controller) {
      const reader = upstream.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      let buffer = "";
      let charCount = 0;
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
                const text = evt.delta.text;
                charCount += text.length;
                controller.enqueue(encoder.encode(text));
              }
            } catch {
              // partial or non-JSON keep-alive line — ignore
            }
          }
        }
        console.log(`FIREWALLIQ: stream complete, total chars forwarded: ${charCount}`);
      } catch (e) {
        console.error("FIREWALLIQ: stream error:", e.message);
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
};
