# Deploying the cloud (Cloudflare Workers Free)

The Worker, D1 database, dashboard and daily cron deploy from GitHub Actions (`cloud-ci.yml`, job
`deploy`) on every push to `main` that touches `cloud/` — once the steps below are done. Until then
the job is skipped and only the tests run.

## 1. Cloudflare

1. **Zone.** `supertechguy.net` must use Cloudflare DNS (the Worker is attached as the custom domain
   `netcaliper.supertechguy.net`; Cloudflare creates the DNS record and certificate on first deploy).
2. **API token** (checked against Cloudflare's docs 2026-11-28). My Profile → **API Tokens** →
   **Create Token** → **Create Custom Token** (bottom of the template list) → name `netcaliper-deploy`.
   Add these permission rows (each row: scope ▸ permission ▸ level):

   | Scope   | Permission       | Level |
   |---------|------------------|-------|
   | Account | Workers Scripts  | Edit  |
   | Account | D1               | Edit  |
   | Account | Account Settings | Read  |
   | Zone    | Workers Routes   | Edit  |
   | Zone    | Zone             | Read  |

   Account Resources: *Include → your account*. Zone Resources: *Include → Specific zone →
   supertechguy.net*. → **Continue to summary** → **Create Token**; copy it (shown once).
   Pre-filled form (permissions only; still set the resources):
   `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_routes%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=netcaliper-deploy`
   **Account ID**: Ctrl+K in the dashboard → "Copy account ID" (or Workers & Pages → Account details).
3. **Access** (Zero Trust → Access controls → Applications; checked against the docs 2026-11-28):
   - *netcaliper dashboard*: self-hosted, public hostname `netcaliper.supertechguy.net`, path empty
     (whole host). Policy **Allow**, include your email. Edit → *Additional settings* → copy the
     **Application Audience (AUD) Tag**.
   - *netcaliper devices*: a second self-hosted app on the same hostname with four public hostnames
     whose paths are `api/v1/enroll`, `api/v1/sync`, `api/v1/config`, `api/v1/health` (if the form
     takes only one, make one app per path). Policy: Action **Bypass**, Include **Everyone**. The
     more specific path wins, so only these four skip the login; devices authenticate with their
     token. Do **not** bypass `api/v1/*` — the dashboard's admin API needs the Access header.
   - **Team domain**: Zero Trust → **Settings** → team domain `<team>.cloudflareaccess.com`.

## 2. GitHub (repository → Settings)

- Environment **`production`** (optionally require your approval for deploys).
- Secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.
- Secrets → Actions (repository secrets are fine; they don't need to sit in the environment).
- `ACCESS_TEAM_DOMAIN` (`<team>.cloudflareaccess.com`) and `ACCESS_AUD` (the AUD tag), as variables
  or secrets; variable `CLOUDFLARE_DEPLOY` = `true`.

Then run `cloud-ci` (Actions → cloud-ci → Run workflow, or push to `cloud/`). The job creates the `netcaliper` D1 database on
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
