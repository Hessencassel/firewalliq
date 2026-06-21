-- FirewallIQ — Supabase Security Fixes
-- Run this in the Supabase SQL Editor after the initial schema.
--
-- Fixes:
--   1. Set fixed search_path on both functions (prevents search path injection)
--   2. Revoke EXECUTE on increment_audits_used from anon + authenticated roles
--      (only the service role key used by Netlify functions should call this)

-- ── Fix handle_updated_at ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- ── Fix increment_audits_used ─────────────────────────────────────
CREATE OR REPLACE FUNCTION public.increment_audits_used(user_id UUID)
RETURNS VOID LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE public.users
  SET audits_used = audits_used + 1
  WHERE id = user_id;
END;
$$;

-- ── Revoke public execute access on increment_audits_used ─────────
-- anon (unauthenticated) and authenticated (logged-in) users must NOT
-- be able to call this directly via the REST API.
-- Only the service role key (used by Netlify functions) can call it.
REVOKE EXECUTE ON FUNCTION public.increment_audits_used(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.increment_audits_used(uuid) FROM authenticated;
