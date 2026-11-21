# SnapFind AI — Multi-Tenant Event Photography & Super Admin Platform

A self-hostable event photography delivery platform with multi-tenant studio isolation, studio staff RBAC, opt-in AI face discovery, and an enterprise Super Admin Control System.

## Account Types & Access Control
1. **Super Admin (`/super-admin.html`)**
   - Central platform governance account with mandatory TOTP Multi-Factor Authentication (MFA).
   - **Never accessible via public registration** and ships with **no hardcoded password**.
   - Created only via:
     - CLI bootstrap: `npm run setup:super-admin`
     - Or controlled initial web setup at `/super-admin.html` using `SUPER_ADMIN_SETUP_TOKEN` (16+ chars in `.env`) while zero Super Admin accounts exist.
   - Additional Super Admin accounts are disabled by default (`ALLOW_MULTIPLE_SUPER_ADMINS=false`).
2. **Studio Owner (`studio_owner`)**
   - Registers publicly via `/` (`POST /api/auth/register`), automatically receiving an isolated studio tenant (`studios.id`).
   - Manages their own studio's events, uploads, QR/PIN galleries, AI indexing, guest selections, optional TOTP MFA, and **Studio Staff**.
3. **Studio Staff (`studio_staff`)**
   - Created by a Studio Owner (or Super Admin) under a specific studio tenant with granular permissions (`events:read`, `events:write`, `photos:upload`, `photos:delete`, `selections:read`, `ai:index`).
   - Strictly isolated on the backend/database to their assigned `studio_id`.

## Security & Privacy Monitoring
- **Strict Tenant Isolation:** Studio Owners and Staff can only query/modify events, photos, and selections belonging to their own `studio_id`. Suspending a studio blocks both its team members and its public/private guest galleries & media URLs.
- **Session & Security Auditing:** Login successes/failures, MFA verification, suspicious login indicators (new IP after prior logins, repeated failures), password resets, session revocations, and all Super Admin actions are recorded in `security_events` and `audit_logs`.
- **Transparency Disclosure:** Security activity logs record login timestamps, IP addresses, and device/browser strings solely for account protection and session management, disclosed clearly in the Studio Dashboard and Super Admin Console.

## Production deployment requirements

- On Vercel production, configure `DATABASE_URL` to a durable managed PostgreSQL database and configure Vercel Blob credentials. The application now fails startup if either is missing rather than silently using ephemeral SQLite/filesystem storage.
- Uploads are batched by the browser (at most 3 files and roughly 3 MB per batch). The server defaults to 3 files per request and rejects requests with a known `Content-Length` above `MAX_UPLOAD_BATCH_MB`; file-count and per-file limits also apply. Defaults are 4 MB on Vercel and 60 MB for local/self-hosted environments.
- Keep `SESSION_SECRET` strong and unique, and configure `BASE_URL` to the canonical HTTPS origin.
- Protected galleries are intentionally excluded from the public event directory; share their access code/QR directly with guests.
- AI face discovery uses a conservative server-controlled matching threshold. Match scores are approximate similarity indicators, not verified identity or calibrated probabilities.

## Backup, recovery & operational safeguards

### Backup policy
- **PostgreSQL:** schedule managed-provider backups and point-in-time recovery where available. For an additional portable backup, use `pg_dump -Fc` with a restricted backup identity and encrypt the resulting file before moving it off-site.
- **Vercel Blob:** the database backup does not contain image files. Maintain a separate export/mirror of the `events/<event-id>/originals`, `previews`, and `thumbs` objects, using a private storage identity. Confirm object counts and checksums during backup; do not assume a database backup covers Blob content.
- **Local/self-hosted:** stop writes before copying the SQLite database and media directory, or use SQLite's online backup facility. Never copy an actively-written SQLite file without a consistent backup procedure.
- Store backups separately from the application and protect them with encryption, access controls, and retention limits. Do not put backup archives, production database URLs, API keys, or media tokens in Git.

### Recovery checklist
1. Provision the same supported database and media storage, then restore the database backup.
2. Restore the corresponding media objects/files so photo rows and referenced variants are available.
3. Reconfigure the original `SESSION_SECRET`, `MEDIA_SIGNING_SECRET`, `BASE_URL`, database URL, and Blob credentials. Changing signing secrets invalidates existing signed media links.
4. Confirm the restored database schema migrations are current, verify restored event/photo counts against backup records, and check that a small set of original/preview/thumb objects can be retrieved privately.
5. Record the recovery outcome and any data-loss window. Schedule periodic restore drills; a backup that has never been restored is not proven recoverable.

### Monitoring and deployment operations
- Alert on application 5xx spikes, database connection/timeout errors, Blob upload/delete failures, repeated authentication/MFA failures, password-reset delivery failures, and quota rejection trends.
- Review Super Admin and studio security/audit events for unusual sign-in patterns; restrict log access because events contain IP/device metadata.
- Keep production dependencies patched, deploy only reviewed commits, require HTTPS, and ensure the production environment has durable database and media storage before enabling traffic.
- Every HTTP request carries an `X-Request-ID` response header. Use it to correlate a client error with server logs; unexpected failures are logged with the ID and error class, without dumping the full error/request body.
- Avoid logging reset tokens, reset links, face descriptor vectors, guest selfies, or full request bodies. Do not share error logs containing personal data publicly.

### Face-discovery data lifecycle
- The uploaded guest selfie is processed in the browser; the image is not sent to SnapFind. When matching is requested, descriptor vectors are sent securely to the server for comparison and are not persisted as query data.
- Match results (photo IDs) are held in the server-side session until the guest clears the scan or the session expires.
- Event photo descriptors are stored while AI face discovery is enabled. Disable AI face discovery or clear indexing to delete descriptors; photo deletion cascades to associated descriptors. Retain event photos and guest selections only for the studio's stated purpose and delete them when no longer needed.

## Run
1. Install Node.js 22.5+ (tested on Node 24)
2. Copy `.env.example` to `.env` and set a strong `SESSION_SECRET` (32+ characters; required in `NODE_ENV=production`), plus optional `MEDIA_SIGNING_SECRET`, `REGISTRATION_INVITE_CODE`, and `SUPER_ADMIN_SETUP_TOKEN`.
3. `npm install`
4. Initialize Super Admin: `npm run setup:super-admin` (or configure `SUPER_ADMIN_SETUP_TOKEN` and visit `/super-admin.html`)
5. `npm start`
6. Open http://localhost:4100 (or http://localhost:4100/super-admin.html)

Run automated tests:
```bash
npm test
```

## AI matching and privacy
Face matching is opt-in per event and per guest session. Guest selfies are analysed locally on the guest's device (`@vladmandic/face-api` self-hosted under `/vendor/face-api/`) and only the ephemeral 128D matching vector is sent over TLS to `/api/gallery/:code/match`. Disabling AI discovery on an event automatically purges stored face descriptors.

## Self-service password recovery email

Configure Resend:
- `RESET_EMAIL_PROVIDER=resend`
- `RESEND_API_KEY` (restricted API key)
- `RESET_EMAIL_FROM` (verified sender, e.g. `SnapFind <no-reply@your-domain.example>`)
- Set `BASE_URL` to the public HTTPS origin.

Reset links expire in 30 minutes; token values are stored hashed. Requests return a generic response to avoid account enumeration. Without email configuration no self-service token is created; Super Admin resets remain available. Delivery failures never log reset URLs or token values.
