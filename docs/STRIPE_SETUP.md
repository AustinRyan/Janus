# Stripe + Resend Setup

Step-by-step guide to configure billing and license key delivery for Sentinel Pro.

## 1. Stripe Account

1. Create a [Stripe account](https://dashboard.stripe.com/register) (or use an existing one).
2. Toggle **Test mode** while developing.

## 2. Create Product & Price

1. Go to **Products** > **Add product**.
2. Name: `Sentinel Pro — Team`
3. Add a **Recurring** price: `$499.00 / month`
4. Save. Copy the **Price ID** (starts with `price_`).

```
STRIPE_PRICE_ID=price_xxxxxxxxxxxxx
```

## 3. API Secret Key

1. Go to **Developers** > **API keys**.
2. Copy the **Secret key** (starts with `sk_test_` in test mode).

```
STRIPE_SECRET_KEY=sk_test_xxxxxxxxxxxxx
```

## 4. Webhook Endpoint

1. Go to **Developers** > **Webhooks** > **Add endpoint**.
2. Endpoint URL: `https://your-domain.com/api/webhooks/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.deleted`
4. Save. Copy the **Signing secret** (starts with `whsec_`).

```
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxx
```

### Local Development

Use the [Stripe CLI](https://stripe.com/docs/stripe-cli) to forward webhooks locally:

```bash
stripe listen --forward-to localhost:8000/api/webhooks/stripe
```

The CLI will print a webhook signing secret — use that as `STRIPE_WEBHOOK_SECRET`.

## 5. Resend (Email Delivery)

1. Create a [Resend account](https://resend.com/signup).
2. Go to **API Keys** > **Create API Key**.
3. Copy the key.

```
RESEND_API_KEY=re_xxxxxxxxxxxxx
```

Resend is used to email the license key after purchase. If `RESEND_API_KEY` is not set, the checkout flow still works — the license key is shown on the success page, just not emailed.

## 6. Environment Variables Summary

Add all variables to your `.env` file:

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRICE_ID=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
RESEND_API_KEY=re_...
```

## 7. Install Billing Dependencies

```bash
pip install 'sentinel-security[billing]'
```

This installs `stripe` and `resend` packages.

## 8. Verify

1. Start the server: `sentinel serve`
2. Visit the landing page and click **Start Free Trial**.
3. Complete checkout with a [Stripe test card](https://stripe.com/docs/testing#cards) (`4242 4242 4242 4242`).
4. You should be redirected to `/checkout/success` with your license key.
5. The license key email should arrive (if Resend is configured).
6. Activate: `POST /api/license/activate` with the key — tier should become `pro`.
