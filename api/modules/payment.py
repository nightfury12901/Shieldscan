import os
import hmac
import hashlib
from fastapi import HTTPException
from pydantic import BaseModel
import razorpay
from modules.db import get_supabase

# Initialize Razorpay Client lazily
def get_razorpay_client():
    key_id = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    
    if not key_id or not key_secret:
        raise HTTPException(500, "Razorpay credentials not configured")
        
    return razorpay.Client(auth=(key_id, key_secret))

class CreateOrderRequest(BaseModel):
    user_id: str

class VerifyPaymentRequest(BaseModel):
    user_id: str
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class ApplyPromoRequest(BaseModel):
    user_id: str
    promo_code: str

# Price configuration
AMOUNT_PAISE = 19900  # ₹199.00
CREDITS_PER_PURCHASE = 10

def create_order(req: CreateOrderRequest):
    client = get_razorpay_client()
    
    try:
        order = client.order.create({
            "amount": AMOUNT_PAISE,
            "currency": "INR",
            "receipt": f"receipt_{req.user_id[:8]}",
            "notes": {
                "user_id": req.user_id
            }
        })
        
        return {
            "order_id": order["id"],
            "amount": AMOUNT_PAISE,
            "currency": "INR"
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to create order: {str(e)}")

def verify_payment(req: VerifyPaymentRequest):
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    if not key_secret:
        raise HTTPException(500, "Razorpay credentials not configured")

    # Verify signature
    msg = f"{req.razorpay_order_id}|{req.razorpay_payment_id}"
    generated_signature = hmac.new(
        key_secret.encode('utf-8'),
        msg.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if generated_signature != req.razorpay_signature:
        raise HTTPException(400, "Invalid payment signature")

    # Signature is valid. Add transaction to DB and increment user credits.
    supabase = get_supabase()
    
    # 1. Insert into payments
    try:
        supabase.table("payments").insert({
            "user_id": req.user_id,
            "razorpay_order_id": req.razorpay_order_id,
            "razorpay_payment_id": req.razorpay_payment_id,
            "amount": AMOUNT_PAISE,
            "status": "success"
        }).execute()
    except Exception as e:
        # If payments table does not exist or fails, we continue so the user still gets their credits!
        print(f"Warning: Failed to log payment transaction. Error: {e}")

    # 2. Increment credits
    try:
        increment_credits(req.user_id, CREDITS_PER_PURCHASE, supabase)
    except Exception as e:
        error_msg = str(e)
        if "relation" in error_msg and "does not exist" in error_msg:
             error_msg = f"Table missing. Please ensure 'user_credits' table exists in Supabase. DB Error: {error_msg}"
        raise HTTPException(400, f"Payment verified, but failed to add credits: {error_msg}")

    return {"status": "success", "credits_added": CREDITS_PER_PURCHASE}


def apply_promo(req: ApplyPromoRequest):
    supabase = get_supabase()
    code = req.promo_code.strip().upper()
    
    try:
        # 1. Verify promo code exists and is active and has uses left
        promo_res = supabase.table("promo_codes").select("*").eq("code", code).eq("active", True).execute()
        
        if not promo_res.data:
            raise HTTPException(400, "Invalid or inactive promo code")
            
        promo = promo_res.data[0]
        if promo.get("uses_left", 0) <= 0:
            raise HTTPException(400, "Promo code usage limit reached")
            
        # 2. Check if user already used this promo
        usage_res = supabase.table("user_promo_usages").select("*").eq("user_id", req.user_id).eq("promo_code", code).execute()
        
        if usage_res.data:
            raise HTTPException(400, "You have already used this promo code")
            
        # 3. Mark as used
        try:
            supabase.table("user_promo_usages").insert({
                "user_id": req.user_id,
                "promo_code": code
            }).execute()
        except Exception:
            raise HTTPException(400, "Unable to apply promo code. Already used?")
            
        # 4. Decrease uses_left
        new_uses_left = promo["uses_left"] - 1
        supabase.table("promo_codes").update({"uses_left": new_uses_left}).eq("code", code).execute()
        
        # 5. Increment user credits
        credits_offered = promo["credits_offered"]
        increment_credits(req.user_id, credits_offered, supabase)
        
        return {"status": "success", "credits_added": credits_offered, "message": f"Promo code applied successfully!"}
    
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        error_msg = str(e)
        # Catch typical Supabase postgrest missing table errors nicely
        if "relation" in error_msg and "does not exist" in error_msg:
             error_msg = f"Database setup incomplete. Please ensure 'promo_codes', 'user_promo_usages', and 'user_credits' tables exist in Supabase. Details: {error_msg}"
        raise HTTPException(400, f"Promo code processing failed: {error_msg}")

def increment_credits(user_id: str, amount: int, supabase=None):
    if supabase is None:
        supabase = get_supabase()
        
    credit_res = supabase.table("user_credits").select("scans_remaining").eq("user_id", user_id).execute()
    
    if not credit_res.data:
        supabase.table("user_credits").insert({
            "user_id": user_id,
            "scans_remaining": amount
        }).execute()
        return amount
    else:
        current_credits = credit_res.data[0]["scans_remaining"]
        new_credits = current_credits + amount
        supabase.table("user_credits").update({
            "scans_remaining": new_credits
        }).eq("user_id", user_id).execute()
        return new_credits

def decrement_credits(user_id: str, supabase=None):
    if supabase is None:
        supabase = get_supabase()
        
    try:
        credit_res = supabase.table("user_credits").select("scans_remaining").eq("user_id", user_id).execute()
        
        if not credit_res.data or credit_res.data[0]["scans_remaining"] <= 0:
            raise HTTPException(402, "Insufficient credits. Please upgrade to scan.")
            
        current_credits = credit_res.data[0]["scans_remaining"]
        supabase.table("user_credits").update({
            "scans_remaining": current_credits - 1
        }).eq("user_id", user_id).execute()
        return current_credits - 1
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        # If DB error like table doesn't exist, we fallback
        raise HTTPException(500, f"Database error verifying credits: {str(e)}")
