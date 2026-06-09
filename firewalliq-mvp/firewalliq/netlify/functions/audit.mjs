// FirewallIQ — core audit engine (Netlify Function v2, streaming)
//
// Reads ANTHROPIC_API_KEY from the environment. Optionally FIREWALLIQ_MODEL.
// Configs are processed in memory only. Nothing is written to disk or stored.

const MODEL = process.env.FIREWALLIQ_MODEL || "claude-sonnet-4-6";
const ANTHROPIC_VERSION = "2023-06-01";
const MAX_TOKENS = 8000;

const VENDORS = {
  cisco_asa: "Cisco ASA / FTD (Firepower Threat Defense)",
  fortigate: "Fortinet FortiGate (FortiOS)",
  palo_alto: "Palo Alto Networks (PAN-OS)",
};

const FRAMEWORKS = {
  pci_dss_4: "PCI DSS v4.0",
  cis: "CIS Benchmarks (vendor-specific)",
};

// --- Vendor knowledge blocks (v1 — validate and refine against trusted configs) ---
const VENDOR_BLOCKS = {
  cisco_asa: `PLATFORM: Cisco ASA / FTD (Firepower Threat Defense).
A "running-config" from an ASA is flat CLI. FTD running-config is ASA-like but FTD is typically managed by FMC, so some policy lives off-box; assess only what is present and note what cannot be evaluated.
Audit these areas and cite the exact line as evidence:
- Access policy: any-any permits, overly broad source/destination/service, "permit ip any any", unused or shadowed access-list entries, missing explicit deny with logging.
- NAT: overly broad or identity NAT exposing internal hosts.
- Management plane: telnet enabled (should be SSH only), "http server enable" and ASDM access scoped to specific hosts, SSH version 2 only, login/exec timeouts, "service password-encryption", banner present.
- AAA & accounts: local-only auth vs TACACS+/RADIUS, default or weak usernames, "enable password" strength, password policy.
- Logging: logging enabled, logging host/buffered, trap severity, logging of denied traffic.
- SNMP: v2c community strings (weak) vs SNMPv3 with auth/priv.
- NTP: configured and authenticated.
- VPN/crypto: IKEv1 vs IKEv2, weak DH groups (1/2/5), weak transforms (DES/3DES/MD5), missing PFS.
Remediation must use real ASA/FTD CLI (e.g., "ssh version 2", "no telnet 0.0.0.0 0.0.0.0 inside", "logging enable", "snmp-server group ... v3 priv").`,

  fortigate: `PLATFORM: Fortinet FortiGate (FortiOS). Config is block-structured: "config ... / edit ... / set ... / next / end".
Audit these areas and cite the exact line as evidence:
- Firewall policy: any-any or overly broad policies, policies missing security profiles (av, ips, webfilter, app, ssl-ssh-profile), "set logtraffic all" missing, disabled implicit-deny logging.
- Interfaces/zones: untrusted interfaces with admin access enabled (set allowaccess including http/telnet/ping).
- Admin access: trusted hosts (trusthost) not set, HTTP/Telnet admin enabled (should be HTTPS/SSH only), "set admintimeout" too high, password-policy, two-factor for admins.
- SNMP: v1/v2c communities vs SNMPv3.
- Logging: logging enabled and forwarded (syslogd / FortiAnalyzer), event logging on.
- VPN/crypto: IPsec phase1/phase2 proposals using weak DH (group 1/2/5) or weak encryption (des/3des), IKEv1 aggressive mode.
- DoS policy presence, default-profile usage, NTP configured.
Remediation must use real FortiOS CLI (config/edit/set/next/end), e.g., "config system global / set admin-https-redirect enable", "set allowaccess ssh https", "set logtraffic all".`,

  palo_alto: `PLATFORM: Palo Alto Networks (PAN-OS). Config may be "set"-format CLI or XML export; interpret either.
Audit these areas and cite the exact element as evidence:
- Security policy: any-any rules, rules without a Security Profile Group (AV/AS/Vuln/URL/File/WildFire), "action allow" with "log-end no", port-based rules that should be App-ID based, permissive intrazone/interzone defaults.
- Management profile: interface mgmt profiles permitting HTTP/Telnet, permitted-IP not restricted, GUI/SSH exposed broadly.
- Admin & auth: superuser sprawl, local-only admins, no MFA, weak password complexity.
- Logging: log forwarding profiles attached, traffic logged at session end.
- Threat prevention: missing/!default AV, Anti-Spyware, Vulnerability, URL filtering profiles; decryption policy absence where expected.
- Zone protection / DoS profiles.
- IKE/IPsec crypto profiles: weak DH groups, 3DES/DES, MD5, missing PFS.
Remediation must use real PAN-OS set-CLI (e.g., "set deviceconfig system permitted-ip ...", "set rulebase security rules <name> profile-setting group <grp>", "set ... log-end yes").`,
};

// --- Framework blocks (v1) ---
const FRAMEWORK_BLOCKS = {
  pci_dss_4: `FRAMEWORK: PCI DSS v4.0. Assess only firewall/network-security-control-relevant requirements and map each finding to a real requirement number:
- 1.2.1 Configuration standards for network security controls (NSCs) are defined and applied.
- 1.2.5 Only necessary services, protocols, and ports are allowed; all in use are identified and approved.
- 1.2.6 Security features are defined for any insecure services/protocols in use.
- 1.2.7 NSC configurations are reviewed at least every six months (note if no evidence of change control/review).
- 1.3.1 / 1.3.2 Inbound and outbound traffic to/from the CDE is restricted to only what is necessary.
- 1.4.1 NSCs are implemented between trusted and untrusted networks.
- 1.4.3 Anti-spoofing measures detect and block forged source IPs.
- 1.4.4 System components storing cardholder data are not directly accessible from untrusted networks.
- 1.5.1 Controls protect against threats from computing devices that connect to both untrusted networks and the CDE.
- 2.2.1 / 2.2.2 Configuration standards; no vendor default accounts/passwords (remove or change defaults).
- 2.2.7 Non-console administrative access is encrypted (no Telnet/HTTP for management).
- 8.3 / 8.4 Strong authentication and MFA for administrative access.
- 10.2.x / 10.4 Audit logs capture access and security events; logs are reviewed.
Where a control cannot be confirmed from the provided config, state that explicitly rather than assuming compliance.`,

  cis: `FRAMEWORK: CIS Benchmarks. CIS publishes vendor-specific benchmarks (CIS Cisco ASA, CIS Palo Alto Networks, CIS Fortinet FortiGate). Map each finding to the relevant CIS recommendation. Reference real recommendation areas; if you are not certain of an exact recommendation number, cite the control area/topic precisely (e.g., "CIS Cisco ASA — Management Plane: disable Telnet") rather than inventing a number.
Core CIS control areas for firewalls:
- Management plane hardening: disable Telnet/HTTP, SSHv2 only, restrict management to specific hosts, idle/exec timeouts, login banner.
- Authentication & accounts: centralized AAA, no default/shared accounts, strong password policy, MFA for admins.
- Logging & monitoring: NTP configured with authentication, syslog to a central server, appropriate logging severity, log denied traffic.
- Control plane: routing protocol authentication, ICMP hardening.
- Data plane: deny-by-default policy, anti-spoofing, no any-any rules, segment trusted/untrusted.
- SNMP: SNMPv3 with auth/priv; no public/private or v2c communities.
- Secure VPN: strong DH groups, AES (not DES/3DES), SHA (not MD5), PFS enabled.`,
};

function scrubSecrets(text) {
  let out = String(text);
  // Redact secret values while keeping the directive so context is preserved.
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
  return `You are FirewallIQ, a senior firewall and network-security configuration auditor. You audit a single device's running configuration against a compliance framework and produce an evidence-based report a consultant can hand to a client.

${VENDOR_BLOCKS[vendor]}

${FRAMEWORK_BLOCKS[framework]}

RULES
- Be precise and evidence-based. For every finding, quote the exact configuration element it is based on as "evidence". If a control cannot be assessed from the provided configuration, set evidence to "Not present in the provided configuration" and treat it as a gap, not a pass.
- Reference real control identifiers. If unsure of an exact number, cite the control area/topic precisely rather than inventing one.
- Remediation must be concrete, copy-pasteable ${VENDORS[vendor]} CLI or steps wherever possible.
- Include a few notable "pass" findings for controls that are correctly configured, so the report is balanced.

SEVERITY
- critical: directly exploitable or a major compliance failure (e.g., permit any-any to sensitive zones, plaintext management like Telnet/HTTP, default credentials, no logging where required).
- high: a significant weakness or gap likely to fail an audit.
- medium: a hardening gap or partial compliance.
- low: minor or best-practice.
- pass: control is satisfied.

SCORE
Start at 100 and subtract by severity: critical -20 to -30, high -10 to -15, medium -5, low -2. Do not subtract for "pass". Floor at 0. Map the number to a label: 0-49 "At risk", 50-69 "Needs work", 70-84 "Fair", 85-94 "Strong", 95-100 "Hardened".

OUTPUT
Respond with ONLY a single JSON object and nothing else. No markdown, no code fences, no text before or after. Shape:
{
  "score": <integer 0-100>,
  "score_label": "<label>",
  "summary": "<2-4 sentence executive summary>",
  "findings": [
    {
      "id": "F1",
      "severity": "critical|high|medium|low|pass",
      "title": "<short finding title>",
      "control": "<framework control reference, e.g. 'PCI DSS 4.0 Req 1.4.3' or 'CIS Fortinet — Management Plane'>",
      "evidence": "<exact config line(s) or 'Not present in the provided configuration'>",
      "remediation": "<concrete CLI or steps to fix>"
    }
  ]
}
Order findings by severity: critical, high, medium, low, then pass.`;
}

function buildUser(vendor, framework, config) {
  return `Audit the following ${VENDORS[vendor]} configuration against ${FRAMEWORKS[framework]}. Return only the JSON object.

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
    return json(
      { error: "The audit engine isn't configured. Set ANTHROPIC_API_KEY in your Netlify environment variables." },
      500
    );
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  const { config, vendor, framework } = body || {};
  if (!config || !String(config).trim()) return json({ error: "Paste a configuration to audit." }, 400);
  if (!VENDORS[vendor]) return json({ error: "Choose a supported vendor." }, 400);
  if (!FRAMEWORKS[framework]) return json({ error: "Choose a supported framework." }, 400);

  const scrubbed = scrubSecrets(config);

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
    return json({ error: "Couldn't reach the audit engine. Try again." }, 502);
  }

  if (!upstream.ok || !upstream.body) {
    const detail = await upstream.text().catch(() => "");
    return json({ error: "The audit engine returned an error.", detail: detail.slice(0, 600) }, 502);
  }

  // Parse the Anthropic SSE stream and forward text deltas to the client.
  const stream = new ReadableStream({
    async start(controller) {
      const reader = upstream.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      let buffer = "";
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
                controller.enqueue(encoder.encode(evt.delta.text));
              }
            } catch {
              // partial / non-JSON keep-alive line — ignore
            }
          }
        }
      } catch {
        // upstream interrupted — close gracefully with whatever we have
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
};
