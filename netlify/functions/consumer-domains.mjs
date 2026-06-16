// FirewallIQ — Consumer email domain blocklist
// Used to prevent Team plan domain-matching on personal email providers.
// Team plans require a work/business email domain.

export const CONSUMER_DOMAINS = new Set([
  // Google
  "gmail.com", "googlemail.com",

  // Microsoft
  "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
  "hotmail.it", "hotmail.es", "live.com", "live.co.uk", "live.fr", "live.de",
  "live.it", "live.com.au", "msn.com", "passport.com",

  // Yahoo
  "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.com.au", "yahoo.ca",
  "yahoo.fr", "yahoo.de", "yahoo.it", "yahoo.es", "yahoo.com.br",
  "yahoo.com.mx", "yahoo.com.ar", "yahoo.com.ph", "yahoo.com.sg",
  "ymail.com", "rocketmail.com",

  // Apple
  "icloud.com", "me.com", "mac.com",

  // AOL / Verizon Media
  "aol.com", "aol.co.uk", "aol.fr", "aol.de", "aim.com",
  "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
  "pacbell.net", "ameritech.net",

  // Privacy / Secure email
  "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
  "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io",
  "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "sharklasers.com", "spam4.me", "mailnull.com",

  // European providers
  "gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch",
  "web.de", "freenet.de", "t-online.de", "arcor.de",
  "orange.fr", "laposte.net", "sfr.fr", "free.fr", "wanadoo.fr",
  "libero.it", "virgilio.it", "tin.it", "alice.it",
  "terra.es", "telefonica.net",

  // US ISP / regional
  "comcast.net", "xfinity.com", "charter.net", "cox.net",
  "roadrunner.com", "rr.com", "twc.com", "spectrum.net",
  "earthlink.net", "mindspring.com", "netzero.net", "juno.com",
  "optonline.net", "optimum.net",

  // Other major global providers
  "mail.com", "email.com", "myself.com", "hailmail.net",
  "inbox.com", "usa.com", "post.com",
  "zoho.com",          // consumer tier (business tier uses custom domain)
  "yandex.com", "yandex.ru", "yandex.ua", "ya.ru",
  "mail.ru", "bk.ru", "list.ru", "inbox.ru",
  "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
  "naver.com", "daum.net", "hanmail.net",
  "rediffmail.com",

  // Disposable / temp mail services
  "mailinator.com", "trashmail.com", "throwam.com",
  "getairmail.com", "fakeinbox.com", "tempr.email",
  "dispostable.com", "maildrop.cc", "yopmail.com",
  "tempmail.com", "temp-mail.org", "throwaway.email",
]);

/**
 * Returns true if the domain is a known consumer/personal email provider.
 * @param {string} domain — e.g. "gmail.com"
 */
export function isConsumerDomain(domain) {
  return CONSUMER_DOMAINS.has(domain?.toLowerCase().trim());
}
