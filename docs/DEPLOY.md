# Deploying the cloud (Cloudflare Workers Free)

The Worker, D1 database, dashboard and daily cron deploy from GitHub Actions (`cloud-ci.yml`, job
`deploy`) on every push to `main` that touches `cloud/` — once the steps below are done. Until then
the job is skipped and only the tests run.

## 1. Cloudflare

1. **Zone.** `supertechguy.net` must use Cloudflare DNS (the Worker is attached as the custom domain
   `netcaliper.supertechguy.net`; Cloudflare creates the DNS record and certificate on first deploy).
2. **API token** (My Profile → API Tokens → Create): start from the *Edit Cloudflare Workers*
   template and add **Account → D1 → Edit**. Limit it to your account and the `supertechguy.net`
   zone. Note the **Account ID** (Workers overview, right column).
3. **Zero Trust → Access → Applications → Add → Self-hosted**:
   - *netcaliper dashboard*: domain `netcaliper.supertechguy.net` (whole host). Policy **Allow**,
     include your email(s) (or an IdP group). Copy the **Application Audience (AUD) tag**.
   - *netcaliper devices*: same domain, paths `api/v1/enroll`, `api/v1/sync`, `api/v1/config`,
     `api/v1/health`. Policy **Bypass**, include **Everyone**. (Devices authenticate with their
     token; the Worker still rejects anything else on these paths without one.)
   - Your **team domain** is shown under Settings → Custom Pages: `<team>.cloudflareaccess.com`.

## 2. GitHub (repository → Settings)

- Environment **`production`** (optionally require your approval for deploys).
- Secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.
- Variables: `ACCESS_TEAM_DOMAIN` (`<team>.cloudflareaccess.com`), `ACCESS_AUD` (the AUD tag),
  `CLOUDFLARE_DEPLOY` = `true`.

Then re-run the latest `cloud-ci` workflow (or push). The job creates the `netcaliper` D1 database on
first run, applies migrations, deploys, and smoke-tests that `/api/v1/health` answers and the admin
API refuses a request without an Access identity.

`scripts/deploy-config.mjs` refuses to build a deploy config without the Access settings, with
`workers_dev`/`preview_urls` on, or with any entry point other than `src/index.ts`.

## 3. Enroll a device

1. Dashboard → **Enroll** → device name (and site) → a code like `7K2QX-M9D4A`, valid 15 minutes.
2. On the device: **Settings → Cloud sync** → server `https://netcaliper.supertechguy.net`, code →
   **Enroll**. The status bar shows `sync: ok` once the first batch is stored.
3. To retire a device: **Overview → revoke** (and *Unenroll* on the device).

## Local development

```sh
cd cloud && npm ci
npm test            # Workers-runtime tests with a local D1
npm run dev         # http://127.0.0.1:8787 — dev entry signs a localhost-only Access identity
```

A device (or `make serve`) can sync to it with server `http://127.0.0.1:8787` (plain HTTP is only
accepted for loopback; for a real device use an SSH reverse tunnel: `ssh -R 8787:127.0.0.1:8787 <device>`).
