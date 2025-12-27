# Stripe Setup (Live Payments)

This project uses Stripe Payment Intents + Connect Express payouts.
Use this guide to accept real card payments in production.

## 1) Prepare Stripe
1. Create a Stripe account and complete business verification.
2. In the Stripe dashboard, enable **Stripe Connect**.
3. Keep **Connect type** as Express (this project forces Express even if Standard is selected).

## 2) Get Live Keys
1. In Stripe, toggle **Live mode** on.
2. Go to **Developers → API keys**.
3. Copy:
   - **Publishable key** (starts with `pk_live_...`)
   - **Secret key** (starts with `sk_live_...`)

## 3) Configure the Server
Edit `Server/config/integrations.env` and set:
```
APP_BASE_URL=https://your-domain.com
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_DEV_BYPASS=false
HELPER_FEE_PERCENT=25
CUSTOMER_SERVICE_FEE_PERCENT=5
SALES_TAX_PERCENT=0
```

Notes:
- `APP_BASE_URL` must be your public HTTPS URL so Stripe redirects and webhooks work.
- `STRIPE_DEV_BYPASS` must be `false` for real payouts.
- Update `SALES_TAX_PERCENT` to your required rate.

Restart the server after editing the file.

## 4) Add the Stripe Webhook
1. Go to **Developers → Webhooks → Add endpoint**.
2. Endpoint URL:
   ```
   https://your-domain.com/webhooks/stripe
   ```
3. **Events to send**:
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
4. Copy the **Signing secret** and set it in `Server/config/integrations.env`:
   ```
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```
5. Restart the server.

## 5) Helper Payouts
Helpers must connect payouts before you can pay them:
1. Log in as the helper.
2. Go to the helper profile.
3. Click **Connect Payouts** (Stripe Express onboarding).

Once connected:
- Customers can pay.
- Funds are held on the platform.
- After **both sides** mark the job completed, the server transfers payout to the helper.

## 6) Production Requirements
- Use HTTPS for all Stripe pages and API calls.
- Confirm that your domain resolves publicly.
- Keep your Stripe secret key private.

## Troubleshooting
- If payment status does not update, check the webhook configuration and logs.
- If you see "Helper payouts are not connected", the helper needs to finish onboarding.
- If you change your domain, update `APP_BASE_URL` and the webhook URL.
