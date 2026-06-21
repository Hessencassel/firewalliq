-- FirewallIQ — Supabase Schema
-- Run this in the Supabase SQL Editor.
--
-- Two separate concerns:
--   public.users              — individual Pro subscribers (usage tracked)
--   public.team_subscriptions — domain-based Team subscriptions (unlimited)
--
-- On audit: check team_subscriptions first (domain match = unlimited).
-- If no team match, fall back to users table (pro plan + usage count).

-- ── Pro users table ───────────────────────────────────────────────
CREATE TABLE public.users (
  id                     UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email                  TEXT NOT NULL,
  plan                   TEXT CHECK (plan IN ('pro')),
  audits_used            INTEGER NOT NULL DEFAULT 0,
  billing_period_start   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  stripe_customer_id     TEXT,
  stripe_subscription_id TEXT,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Team subscriptions table (domain-based) ───────────────────────
-- One row per paying team. Everyone whose email domain matches
-- `domain` gets unlimited audits while `active` is true.
CREATE TABLE public.team_subscriptions (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain                 TEXT NOT NULL UNIQUE,   -- e.g. "acmemsp.com"
  owner_email            TEXT NOT NULL,          -- who purchased
  stripe_customer_id     TEXT,
  stripe_subscription_id TEXT UNIQUE,
  active                 BOOLEAN NOT NULL DEFAULT TRUE,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────────
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_subscriptions ENABLE ROW LEVEL SECURITY;

-- Pro users can read their own row
CREATE POLICY "Users can read own record"
  ON public.users FOR SELECT
  USING (auth.uid() = id);

-- Any authenticated user can check team_subscriptions (domain lookup)
CREATE POLICY "Authenticated users can read team subscriptions"
  ON public.team_subscriptions FOR SELECT
  TO authenticated
  USING (true);

-- ── Auto-update updated_at ────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_users_updated
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

CREATE TRIGGER on_team_subscriptions_updated
  BEFORE UPDATE ON public.team_subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- ── Indexes ───────────────────────────────────────────────────────
CREATE INDEX idx_users_email           ON public.users (email);
CREATE INDEX idx_users_stripe_customer ON public.users (stripe_customer_id);
CREATE INDEX idx_users_stripe_sub      ON public.users (stripe_subscription_id);
CREATE INDEX idx_team_domain           ON public.team_subscriptions (domain);
CREATE INDEX idx_team_stripe_customer  ON public.team_subscriptions (stripe_customer_id);
CREATE INDEX idx_team_stripe_sub       ON public.team_subscriptions (stripe_subscription_id);

-- ── RPC: atomic audit usage increment (Pro only) ─────────────────
CREATE OR REPLACE FUNCTION public.increment_audits_used(user_id UUID)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE public.users
  SET audits_used = audits_used + 1
  WHERE id = user_id;
END;
$$;
