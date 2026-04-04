-- Create user_credits table to track scan limits
CREATE TABLE IF NOT EXISTS public.user_credits (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    scans_remaining INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Creating a payments table to track successful Razorpay orders (optional but good for history)
CREATE TABLE IF NOT EXISTS public.payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    razorpay_order_id TEXT NOT NULL,
    razorpay_payment_id TEXT,
    amount INTEGER NOT NULL, -- in paise
    status TEXT DEFAULT 'created',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE public.user_credits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;

-- Allow users to read their own credits
CREATE POLICY "Users can view their own credits" 
ON public.user_credits FOR SELECT 
USING (auth.uid() = user_id);

-- Allow users to view their own payments
CREATE POLICY "Users can view their own payments" 
ON public.payments FOR SELECT 
USING (auth.uid() = user_id);

-- (The backend Python service bypasses RLS since it uses the Service Role Key)

-- ─────────────────────────────────────────────
-- PROMO CODES SCHEMA
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.promo_codes (
    code TEXT PRIMARY KEY,
    credits_offered INTEGER NOT NULL,
    uses_left INTEGER DEFAULT 999999, -- essentially infinite unless bounded
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.user_promo_usages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    promo_code TEXT REFERENCES public.promo_codes(code) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, promo_code) -- ensure one-time use per user
);

-- Basic row level security
ALTER TABLE public.promo_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_promo_usages ENABLE ROW LEVEL SECURITY;

-- Users can select active promo codes (to verify if they exist)
CREATE POLICY "Users can view active promo codes" 
ON public.promo_codes FOR SELECT 
USING (active = true);

-- Users can view their own usages
CREATE POLICY "Users can view their own promo usages" 
ON public.user_promo_usages FOR SELECT 
USING (auth.uid() = user_id);

-- Insert initial promo codes
INSERT INTO public.promo_codes (code, credits_offered)
VALUES 
    ('SHIELD10', 10),
    ('WELCOME5', 5),
    ('EARLYBIRD', 8),
    ('HACKER26', 15)
ON CONFLICT (code) DO NOTHING;

-- ─────────────────────────────────────────────
-- AUTH TRIGGER: 3 Free Credits on Signup
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user() 
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.user_credits (user_id, scans_remaining)
  VALUES (new.id, 3);
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger the function every time a user is created
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();
