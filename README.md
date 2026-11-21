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
- Keep `SESSION_SECRET` strong and unique, and configure `BASE_URL` to the canonical HTTPS origin.
- Protected galleries are intentionally excluded from the public event directory; share their access code/QR directly with guests.
- AI face discovery uses a conservative server-controlled matching threshold. Match scores are approximate similarity indicators, not verified identity or calibrated probabilities.

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
