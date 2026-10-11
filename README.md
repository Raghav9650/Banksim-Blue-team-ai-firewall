# BankSim · Blue-Team AI Firewall

A personal defensive-fintech simulator with a custom request firewall, Supabase email/password authentication, owner-isolated audit history, client-side encryption for memo/transaction details, and a persistent double-entry simulated account ledger. Users can add explicitly simulated test funds and transfer them to another BankSim account; atomic database functions update both test balances and record both sides of each transfer. There are no payment rails, external bank links, card charges, or real funds.

## 1. Create and prepare your Supabase project

1. Open [supabase.com/dashboard](https://supabase.com/dashboard), create a project, and save the database password somewhere private.
2. Wait for the project database to finish provisioning.
3. In the project dashboard, open **SQL Editor** → **New query**.
4. Open [`sql/supabase.sql`](./sql/supabase.sql), copy the **entire file**, paste it into the SQL editor, and select **Run**. This creates the user profile table, private firewall ledger, simulated double-entry transaction ledger, atomic deposit/transfer functions, owner-only row-level security policies, per-account encryption salts, and the automatic Supabase Auth profile trigger.
5. In **Project Settings** → **API** (sometimes labelled **API Keys**), record:
   - The Project URL.
   - The public `anon` / `publishable` key.
   - The private `service_role` / `secret` key. This key is server-only. Never use it as a `VITE_` variable, commit it, paste it into source, or expose it in browser code.
6. In **Authentication** → **Providers** → **Email**, enable email/password sign-in.
7. In **Authentication** → **URL Configuration**, set your local site URL to `http://localhost:5173`; add that URL and the final Vercel production URL to the allowed redirect URLs. Do not add wildcard production redirects.
8. For quick local testing, email confirmation may be disabled in **Authentication** → **Providers** → **Email**. For an internet-facing deployment, leave confirmation enabled and configure Supabase's production email/SMTP provider.

### SQL notes

- Run the SQL once in a **new/empty Supabase project**. If you already installed the authenticated BankSim schema, rerun the complete updated file to add the simulated transaction ledger and its atomic RPC functions. The script is safe to re-run after its tables and trigger have been created, but it is not a migration for the previous unowned demo ledger.
- If you previously ran the original pre-auth `sql/supabase.sql` in this same project, stop before replacing/dropping anything: those old log rows have no provable owner and the old tables have no encryption fields. Use a new Supabase project for this version, or have a database administrator create an explicit migration that quarantines those legacy rows. Do not assign old events to an arbitrary user.
- You do not need to hand-write any additional SQL queries after running the file. The profile trigger automatically creates an individual profile and a random encryption salt for every confirmed or unconfirmed Supabase Auth signup.
- To make and receive a simulated transfer, create two BankSim test users, sign in to each one, and share the receiver's `BS-…` account number from the Live sandbox. A new test account starts at `$0.00`; use **Add test funds** to post an explicitly simulated deposit (up to `$5,000.00` per deposit). Transfers are limited to `$5,000.00`, require sufficient available test funds, and must target another BankSim account. There is no real-money funding source.
- Deposits and transfers use PostgreSQL functions that lock affected profiles and commit balance changes and ledger entries atomically. A transfer creates a debit for the sender and a matching credit for the recipient. Unique request keys make network retries safe from double-posting. Simulated transactions are private and readable only through the owner-authenticated server API.
- A sender's transfer memo is encrypted with that sender's private audit key before it is stored. The receiver sees an incoming-transfer entry without the sender's memo; BankSim does not share one user's private decryption key with another account.
- The API persists the authenticated Supabase user ID as `user_id`, never a client-supplied owner ID. Supabase RLS applies `auth.uid() = user_id`; the trusted server also filters every admin-key query by that same verified owner ID.

## 2. Configure and run locally on Windows

From the project folder in PowerShell:

```powershell
npm.cmd install
Copy-Item .env.example .env
```

Open `.env` and set all four values to the same Supabase project:

```dotenv
PORT=4174
VITE_SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_ANON_KEY=YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY
SUPABASE_SERVICE_ROLE_KEY=YOUR_PRIVATE_SERVICE_ROLE_OR_SECRET_KEY
```

Only `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are bundled into the public browser application. `SUPABASE_SERVICE_ROLE_KEY` is read by the API process only and must remain private.

Then run:

```powershell
npm.cmd run dev
```

Open the Vite URL printed in the terminal (normally `http://localhost:5173`). Create an account in the app, confirm your email if requested, and sign in. The first successful sign-in binds an encrypted key-verification value to your account. After subsequent page reloads you sign in/unlock your account again before any private log or metric is fetched.

If authentication fails, first check **Supabase Authentication → Users** for the new account, confirm the local redirect URL, and compare all URL/key values in `.env` with the same Supabase project. Restart Vite after every `.env` change.

## 3. Deploy the complete application to Vercel

1. Push the project to a Git repository that you control. `.env` is intentionally ignored; never commit it.
2. In [Vercel](https://vercel.com/), select **Add New → Project**, import that repository, and keep the detected Vite framework. [`vercel.json`](./vercel.json) configures the Vite build and authenticated Express API function. Vercel discovers the API function from `api/[...path].ts`; do not add a rewrite for `/api/*` or a catch-all rewrite to `/index.html`, as either can bypass the function.
3. In the Vercel project's **Settings → Environment Variables**, add these variables to **Production** and to any Preview environments you intend to test:
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
4. Set the same environment variables under **Development** if you want to run `vercel dev`. Local Vite also reads your `.env` file.
5. Deploy. After Vercel displays your production domain, add its exact `https://…vercel.app` URL under **Supabase → Authentication → URL Configuration → Redirect URLs**, set it as the production **Site URL**, and redeploy if you changed build variables.
6. Open the deployed app, create a test account, sign in, inspect one clean test memo and one attack fixture, and verify that each event appears in the signed-in account's own ledger.
7. In Vercel **Deployments → Functions → Logs**, inspect server errors if Supabase logging fails. Audit writes fail closed: if a verified, owner-tagged log cannot be persisted, the banking simulator does not return a successful action.

The build bundles the Express API into a JavaScript module before deployment, and Vercel includes that module with each handler. `api/banking/*` and `api/firewall/evaluate` have explicit function entry points so nested routes do not depend on catch-all matching. The client bundle contains only the Supabase public/anonymous key. The service key never enters a browser response.

After deploying, open `https://YOUR_DOMAIN/api/health` directly. It must return JSON with `authentication_configured` and `audit_persistence`, not the BankSim HTML page. If it returns HTML, check the deployment's **Functions** list/logs for the `api/[...path].ts` function, confirm the Vercel project is deploying this repository root with the included `vercel.json`, then redeploy the latest commit. Recheck `/api/health` before signing in; changing Supabase redirect URLs alone does not deploy or repair an API function.

## 4. Authentication, privacy, and encryption model

- **Identity and isolation:** Supabase Auth email/password sessions are verified by the API using `SUPABASE_ANON_KEY`. The verified `auth.users.id` is attached server-side to every log. Queries filter on that ID. The database additionally has owner-scoped row-level-security policies. Users cannot provide, override, or select another user's `user_id`.
- **Profile access:** Signup creates one `bank_users` row using an `auth.users` trigger. Users may read their own profile and update only the key-check value; browser roles cannot change a simulated balance, clearance, or account number. The API uses a server-only service key and database functions for controlled simulated balance updates.
- **Audit encryption:** The browser derives a 256-bit AES-GCM key using PBKDF2/SHA-256 (600,000 iterations), the Supabase user ID, the account's random per-user salt, and the account password. A fresh random AES-GCM nonce encrypts a copy of each audit request before it is sent to the API. To inspect the memo, the firewall API also receives the request fields over TLS in plaintext; the Vercel application can therefore read the request briefly while processing it. The API writes only the encrypted copy of the memo/amount/recipient to Supabase. This protects stored audit content from database readers, but is **not end-to-end encryption against the application server**. The ledger decrypts the signed-in user's records in the browser.
- **Key handling:** The derived key exists in browser memory only, is not sent to Supabase or the API, and is cleared at sign-out/page reload. Supabase stores a ciphertext proof, not the key or account password. Do not weaken this flow by storing the password or derived key in local storage, server environment variables, SQL, or source control.
- **Password recovery warning:** Historical encrypted audit entries cannot be recovered from a Supabase password reset because the password participates in the local encryption key. If you know the old password, decrypt/export needed records before changing/resetting it. A production release that needs recoverable encryption should add a separately backed-up, user-controlled recovery key and a tested key-rotation workflow before enabling password resets.
- **Visible audit metadata:** Verdict, risk score, threat category, target-tool type, timing, feature counts, and the encrypted-record integrity hash remain available to the trusted audit server for the dashboard. Request content remains encrypted in Supabase. This is app-level encryption in addition to Supabase's managed storage encryption; it does not hide access patterns or verdict metadata.
- **Simulated banking scope:** Account balances and transfer activity are persistent rows in the BankSim demo database, but represent test-only units; they are not real customer balances and cannot move money outside BankSim. Adding test funds is a mock ledger credit, not a card charge or bank deposit.
- **Security scope:** This is an educational/demo simulator, not a bank-grade or externally certified service. It has no payment rails, external banking access, authentication MFA, production abuse-monitoring, or recovery-key workflow. The deterministic heuristic is not a guarantee against prompt injection; never wire this demo endpoint to live banking tools.

## Useful commands

```powershell
npm.cmd run dev
npm.cmd run build
npm.cmd test
npm.cmd audit
```

The tests cover attack categories, fail-closed transaction structure, encrypted audit ownership keys, fresh encryption nonces, decryption, and ciphertext tampering.

## API surface

- `GET /api/health`: non-sensitive configuration status.
- `POST /api/firewall/evaluate`: bearer-authenticated exact four-field verdict; owner-tagged encrypted audit write must succeed first.
- `GET /api/banking/account`: returns the verified user's simulated balance, account number, and recent simulated activity.
- `POST /api/banking/deposit`: posts a capped simulated credit through an atomic, idempotent database function.
- `POST /api/banking/simulate`: re-evaluates and persists an audit event; an approved transfer is atomically debited from its sender and credited to the named BankSim recipient, and a balance inquiry reads the user's simulated balance.
- `GET /api/logs?limit=50`: returns only the current user's encrypted audit events.
- `GET /api/metrics`: derives dashboard values only from the current user's audit rows.
