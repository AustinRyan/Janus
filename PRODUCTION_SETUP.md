# Janus Production Setup Checklist

## 1. Stripe Billing

- [ ] Create a Stripe account at https://stripe.com
- [ ] Create a Product + recurring Price in Stripe Dashboard > Products
- [ ] Copy your **Secret Key** from Dashboard > Developers > API Keys
- [ ] Copy the **Price ID** (starts with `price_`)
- [ ] Add a webhook endpoint: `https://your-domain.com/api/webhooks/stripe`
  - Events to listen for: `checkout.session.completed`, `customer.subscription.deleted`
- [ ] Copy the **Webhook Signing Secret** (starts with `whsec_`)
- [ ] Set environment variables:
  ```
  STRIPE_SECRET_KEY=sk_live_...
  STRIPE_PRICE_ID=price_...
  STRIPE_WEBHOOK_SECRET=whsec_...
  JANUS_BASE_URL=https://your-domain.com
  ```
- [ ] Install billing dependencies: `pip install 'janus-security[billing]'`

## 2. Resend Email (License Delivery)

- [ ] Create a Resend account at https://resend.com
- [ ] Generate an API key from the Resend dashboard
- [ ] Add and verify your sending domain (e.g. `janus-security.dev`) in Resend > Domains
  - Requires adding DNS records (DKIM, SPF, DMARC)
- [ ] Update the `from` address in `janus/email.py` if using a different domain
- [ ] Set environment variable:
  ```
  RESEND_API_KEY=re_...
  ```

## 3. Dashboard API Authentication

- [ ] Choose a strong API key string (or generate one: `python -c "import secrets; print(secrets.token_urlsafe(32))"`)
- [ ] Set on backend:
  ```
  JANUS_API_KEY=your-secret-key
  ```
- [ ] Set on frontend (`frontend/.env.local`):
  ```
  NEXT_PUBLIC_JANUS_API_KEY=your-secret-key
  NEXT_PUBLIC_API_URL=https://your-api-domain.com
  ```

## 4. Notification Channels (janus.toml)

### Slack
- [ ] Create a Slack app at https://api.slack.com/apps
- [ ] Enable Incoming Webhooks and create one for your channel
- [ ] Add to `janus.toml`:
  ```toml
  [exporters.notifications.slack]
  webhook_url = "https://hooks.slack.com/services/T.../B.../..."
  min_verdict = "block"
  ```

### Email Alerts
- [ ] Get SMTP credentials (Gmail app password, SendGrid, AWS SES, etc.)
- [ ] Add to `janus.toml`:
  ```toml
  [exporters.notifications.email]
  smtp_host = "smtp.gmail.com"
  smtp_port = 587
  smtp_user = "you@gmail.com"
  smtp_password = "your-app-password"
  from_addr = "alerts@yourdomain.com"
  to_addrs = ["team@yourdomain.com"]
  min_verdict = "block"
  ```

### Telegram
- [ ] Create a bot via @BotFather on Telegram, get the bot token
- [ ] Get your chat/group ID (send a message to the bot, then check `https://api.telegram.org/bot<TOKEN>/getUpdates`)
- [ ] Add to `janus.toml`:
  ```toml
  [exporters.notifications.telegram]
  bot_token = "123456:ABC-DEF..."
  chat_id = "-1001234567890"
  min_verdict = "block"
  ```

## 5. Webhook/SIEM Export (Optional)

- [ ] Set up your SIEM or webhook receiver endpoint
- [ ] Choose an HMAC signing secret for payload verification
- [ ] Add to `janus.toml`:
  ```toml
  [exporters]
  webhook_url = "https://your-siem.com/api/ingest"
  webhook_signing_secret = "your-hmac-secret"
  ```

## 6. Domain & Deployment

- [ ] Set up your production domain
- [ ] Configure HTTPS/TLS (Let's Encrypt, Cloudflare, etc.)
- [ ] Deploy backend (Docker, Railway, Fly.io, VPS, etc.)
- [ ] Deploy frontend (Vercel, Netlify, or self-hosted)
- [ ] Point `JANUS_BASE_URL` to your frontend URL
- [ ] Point `NEXT_PUBLIC_API_URL` to your backend URL
- [ ] Set `JANUS_CONFIG_PATH` to your production `janus.toml` path

## 7. Database

- [ ] Decide on DB location (default: `~/.janus/janus.db`)
- [ ] Set `JANUS_DB_PATH` if using a custom path
- [ ] Set up backups for the SQLite file

## Quick Reference: All Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `ANTHROPIC_API_KEY` | Yes | Security classifier + chat |
| `JANUS_API_KEY` | Production | Protects API endpoints |
| `JANUS_CONFIG_PATH` | Optional | Path to janus.toml |
| `JANUS_DB_PATH` | Optional | Custom SQLite path |
| `JANUS_BASE_URL` | For Stripe | Frontend URL for redirects |
| `STRIPE_SECRET_KEY` | For billing | Stripe API key |
| `STRIPE_PRICE_ID` | For billing | Subscription price ID |
| `STRIPE_WEBHOOK_SECRET` | For billing | Webhook signature verification |
| `RESEND_API_KEY` | For emails | License email delivery |
| `NEXT_PUBLIC_API_URL` | Frontend | Backend API base URL |
| `NEXT_PUBLIC_JANUS_API_KEY` | Frontend | Must match JANUS_API_KEY |
