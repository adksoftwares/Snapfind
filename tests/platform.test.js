const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const sharp = require("sharp");

const { createApp } = require("../src/app");
const { loadConfig } = require("../src/config");

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  capture(res) {
    const setCookies =
      typeof res.headers.getSetCookie === "function"
        ? res.headers.getSetCookie()
        : [];
    for (const raw of setCookies) {
      const pair = raw.split(";")[0];
      const idx = pair.indexOf("=");
      if (idx > 0) {
        this.cookies.set(pair.slice(0, idx), pair.slice(idx + 1));
      }
    }
  }

  header() {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }
}

async function reqJson(baseUrl, jar, urlPath, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const cookie = jar?.header();
  if (cookie) headers.Cookie = cookie;

  const res = await fetch(`${baseUrl}${urlPath}`, { ...options, headers });
  jar?.capture(res);
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

async function getCsrf(baseUrl, jar) {
  const { data } = await reqJson(baseUrl, jar, "/api/auth/csrf");
  return data.csrfToken;
}

async function makeSampleJpegWithExif() {
  return sharp({
    create: {
      width: 64,
      height: 48,
      channels: 3,
      background: { r: 120, g: 165, b: 90 },
    },
  })
    .withMetadata({
      exif: {
        IFD0: {
          Make: "TestCamera",
          Copyright: "SecretLocationEXIF",
        },
      },
    })
    .jpeg()
    .toBuffer();
}

describe("SnapFind AI Platform", () => {
  let tmpDir;
  let instance;
  let baseUrl;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snapfind-test-"));
    instance = createApp({
      port: 0,
      uploadDir: path.join(tmpDir, "uploads"),
      dbPath: path.join(tmpDir, "test.sqlite"),
      maxStorageMbPerUser: 10,
      disableRateLimit: true,
      sessionSecret: "test-secret-with-more-than-thirty-two-characters-1234",
    });

    await new Promise((resolve) => {
      instance.server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = instance.server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await instance.close();
    fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("enforces strong SESSION_SECRET in production config", () => {
    assert.throws(
      () =>
        loadConfig({
          env: { NODE_ENV: "production", SESSION_SECRET: "short" },
        }),
      /SESSION_SECRET/
    );
  });

  it("exposes health endpoint with strict CSP headers and self-hosted face-api assets", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);

    const csp = res.headers.get("content-security-policy") || "";
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self'/);

    const faceRes = await fetch(`${baseUrl}/vendor/face-api/face-api.js`);
    assert.equal(faceRes.status, 200);

    const ssdBinRes = await fetch(`${baseUrl}/vendor/face-api/model/ssd_mobilenetv1_model.bin`);
    assert.equal(ssdBinRes.status, 200);
    assert.ok((await ssdBinRes.arrayBuffer()).byteLength > 1_000_000);

    const tinyBinRes = await fetch(`${baseUrl}/vendor/face-api/model/tiny_face_detector_model.bin`);
    assert.equal(tinyBinRes.status, 200);
    assert.ok((await tinyBinRes.arrayBuffer()).byteLength > 100_000);
  });

  it("handles full auth + CSRF (including login/register), disk-streamed uploads, EXIF stripping, signed media URLs, PIN galleries, LIKE escaping, server-side match, password change, and admin moderation", async () => {
    const studioJar = new CookieJar();
    const guestJar = new CookieJar();

    // 1. Register CSRF protection (missing token -> 403)
    const noRegCsrf = await reqJson(baseUrl, studioJar, "/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        name: "Maya",
        email: "maya@example.com",
        password: "StrongPassword123!",
      }),
    });
    assert.equal(noRegCsrf.res.status, 403);

    const initCsrf = await getCsrf(baseUrl, studioJar);

    // 2. Reject weak registration
    const badReg = await reqJson(baseUrl, studioJar, "/api/auth/register", {
      method: "POST",
      headers: { "X-CSRF-Token": initCsrf },
      body: JSON.stringify({ name: "A", email: "not-an-email", password: "short" }),
    });
    assert.equal(badReg.res.status, 400);

    // 3. Register photographer
    const reg = await reqJson(baseUrl, studioJar, "/api/auth/register", {
      method: "POST",
      headers: { "X-CSRF-Token": initCsrf },
      body: JSON.stringify({
        name: "Maya Studio",
        email: "maya@example.com",
        password: "StrongPassword123!",
        studio: "Maya Photography",
      }),
    });
    assert.equal(reg.res.status, 201);
    assert.ok(reg.data.csrfToken);
    let csrf = reg.data.csrfToken;
    const userId = reg.data.user.id;

    // 4. Reject authenticated mutation without CSRF token
    const noCsrf = await reqJson(baseUrl, studioJar, "/api/events", {
      method: "POST",
      body: JSON.stringify({ title: "Blocked Event" }),
    });
    assert.equal(noCsrf.res.status, 403);

    // 5. Create private PIN-protected event + public event
    const privEv = await reqJson(baseUrl, studioJar, "/api/events", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        title: "Private Wedding",
        venue: "Colombo",
        pin: "4321",
        is_public: false,
        ai_enabled: true,
      }),
    });
    assert.equal(privEv.res.status, 201);
    const eventId = privEv.data.event.id;
    const accessCode = privEv.data.event.access_code;
    assert.equal(accessCode.length, 12);
    assert.equal(privEv.data.event.has_pin, true);
    assert.equal(privEv.data.event.pin_hash, undefined);

    const pubEv = await reqJson(baseUrl, studioJar, "/api/events", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        title: "Public Charity Run",
        is_public: true,
      }),
    });
    assert.equal(pubEv.res.status, 201);

    // 6. Public directory lists ONLY public active events
    const pubList = await reqJson(baseUrl, guestJar, "/api/public/events");
    assert.equal(pubList.res.status, 200);
    assert.equal(pubList.data.events.length, 1);
    assert.equal(pubList.data.events[0].title, "Public Charity Run");

    // 7. Reject spoofed HTML upload & ensure _tmp directory is cleaned up
    const spoofForm = new FormData();
    spoofForm.append(
      "photos",
      new Blob(["<script>alert(1)</script>"], { type: "image/jpeg" }),
      "evil.html"
    );
    const spoofUpload = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/photos`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: spoofForm,
    });
    assert.equal(spoofUpload.res.status, 400);
    assert.equal(fs.readdirSync(path.join(tmpDir, "uploads", "_tmp")).length, 0);

    // 8. Upload real JPEG with EXIF metadata and Unicode filename
    const sampleJpeg = await makeSampleJpegWithExif();
    const validForm = new FormData();
    validForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "விழா_bride.jpg");
    const validUpload = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/photos`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: validForm,
    });
    assert.equal(validUpload.res.status, 201);
    assert.equal(validUpload.data.photos.length, 1);
    assert.equal(fs.readdirSync(path.join(tmpDir, "uploads", "_tmp")).length, 0);
    const uploadedPhoto = validUpload.data.photos[0];

    // 9. Private PIN gallery blocks guest gallery & unsigned media until unlocked
    const lockedRes = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}`);
    assert.equal(lockedRes.res.status, 200);
    assert.equal(lockedRes.data.locked, true);
    assert.equal(lockedRes.data.photos.length, 0);
    const guestCsrf = lockedRes.data.csrfToken;
    assert.ok(guestCsrf);

    const unsignedThumbPath = uploadedPhoto.thumb_url.split("?")[0];
    const blockedMedia = await fetch(`${baseUrl}${unsignedThumbPath}`);
    assert.equal(blockedMedia.status, 403);

    const wrongPin = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/unlock`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ pin: "9999" }),
    });
    assert.equal(wrongPin.res.status, 401);

    const rightPin = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/unlock`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ pin: "4321" }),
    });
    assert.equal(rightPin.res.status, 200);

    // 10. Unlocked guest gets HMAC-signed URLs; verify signed download works, tampered sig fails, EXIF stripped, UTF-8 Content-Disposition works
    const unlockedGallery = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}`);
    assert.equal(unlockedGallery.data.locked, false);
    assert.equal(unlockedGallery.data.photos.length, 1);
    const signedUrl = unlockedGallery.data.photos[0].url;
    assert.match(signedUrl, /sig=/);

    const tamperedUrl = signedUrl.replace(/sig=[a-f0-9]+/, "sig=0000000000000000");
    const tamperedRes = await fetch(`${baseUrl}${tamperedUrl}`);
    assert.equal(tamperedRes.status, 403);

    const dlRes = await fetch(`${baseUrl}${signedUrl}&download=1`);
    assert.equal(dlRes.status, 200);
    assert.equal(dlRes.headers.get("x-content-type-options"), "nosniff");
    assert.match(dlRes.headers.get("content-disposition") || "", /filename\*=UTF-8''/);
    const dlBuf = Buffer.from(await dlRes.arrayBuffer());
    const dlMeta = await sharp(dlBuf).metadata();
    assert.equal(dlMeta.exif, undefined, "EXIF metadata must be stripped");

    // 11. Caption update & escaped LIKE wildcard search
    const capRes = await reqJson(baseUrl, studioJar, `/api/photos/${uploadedPhoto.id}`, {
      method: "PATCH",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({ caption: "First dance" }),
    });
    assert.equal(capRes.res.status, 200);
    assert.equal(capRes.data.photo.caption, "First dance");

    const wildcardSearch = await reqJson(
      baseUrl,
      guestJar,
      `/api/gallery/${accessCode}?q=${encodeURIComponent("%")}`
    );
    assert.equal(wildcardSearch.res.status, 200);
    assert.equal(wildcardSearch.data.photos.length, 0);

    // 12. Guest favourite toggle & selection
    const guestKey = "guest-uuid-12345678";
    const favOn = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/favourite`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ photo_id: uploadedPhoto.id, guest_key: guestKey }),
    });
    assert.equal(favOn.data.favourited, true);

    const favOff = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/favourite`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ photo_id: uploadedPhoto.id, guest_key: guestKey }),
    });
    assert.equal(favOff.data.favourited, false);

    const sel = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/select`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({
        photo_id: uploadedPhoto.id,
        guest_name: "Nimali",
        guest_email: "nimali@example.com",
        guest_key: guestKey,
      }),
    });
    assert.equal(sel.res.status, 200);

    const selList = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/selections`);
    assert.equal(selList.res.status, 200);
    assert.equal(selList.data.selections.length, 1);
    assert.equal(selList.data.selections[0].original_name, "விழா_bride.jpg");
    assert.ok(selList.data.selections[0].thumb_url);

    // 13. Server-side ephemeral AI face matching (raw descriptors never exposed to guests)
    const oldFacesEndpoint = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/faces`);
    assert.equal(oldFacesEndpoint.res.status, 404);

    const descriptor = Array.from({ length: 128 }, (_, i) => Number((i * 0.001).toFixed(4)));
    const idxRes = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/faces`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        entries: [{ photo_id: uploadedPhoto.id, descriptors: [descriptor] }],
      }),
    });
    assert.equal(idxRes.res.status, 200);
    assert.equal(idxRes.data.saved_descriptors, 1);

    const matchHit = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ descriptor }),
    });
    assert.equal(matchHit.res.status, 200);
    assert.equal(matchHit.data.indexed_count, 1);
    assert.equal(matchHit.data.matches.length, 1);
    assert.equal(matchHit.data.matches[0].photo_id, uploadedPhoto.id);

    const farDescriptor = Array.from({ length: 128 }, () => 1.0);
    const matchMiss = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ descriptor: farDescriptor }),
    });
    assert.equal(matchMiss.res.status, 200);
    assert.equal(matchMiss.data.matches.length, 0);

    const multiMatch = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ descriptors: [farDescriptor, descriptor] }),
    });
    assert.equal(multiMatch.res.status, 200);
    assert.equal(multiMatch.data.matches.length, 1);
    assert.ok(multiMatch.data.matches[0].confidence >= 95);

    // Slightly shifted hair/beard/angle descriptor (~0.65 Euclidean distance) should match in adaptive threshold mode
    const shiftedDescriptor = descriptor.map((v, idx) =>
      idx < 100 ? Number((v + 0.065).toFixed(4)) : v
    );
    const adaptiveMatch = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ descriptors: [shiftedDescriptor], threshold: 0.67 }),
    });
    assert.equal(adaptiveMatch.res.status, 200);
    assert.equal(adaptiveMatch.data.matches.length, 1);

    // Turn off ai_enabled -> purges descriptors
    await reqJson(baseUrl, studioJar, `/api/events/${eventId}`, {
      method: "PATCH",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({ ai_enabled: false }),
    });
    const matchDisabled = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": guestCsrf },
      body: JSON.stringify({ descriptor }),
    });
    assert.equal(matchDisabled.res.status, 403);

    // 14. Super Admin route isolation & event pause invalidates fast media cache
    const nonSuperAdmin = await reqJson(baseUrl, studioJar, "/api/super-admin/overview");
    assert.equal(nonSuperAdmin.res.status, 403);

    const modRes = await reqJson(
      baseUrl,
      studioJar,
      `/api/events/${eventId}`,
      {
        method: "PATCH",
        headers: { "X-CSRF-Token": csrf },
        body: JSON.stringify({ status: "paused" }),
      }
    );
    assert.equal(modRes.res.status, 200);

    // Even valid unexpired HMAC URL stops serving immediately when event is paused
    const pausedSignedMedia = await fetch(`${baseUrl}${signedUrl}`);
    assert.equal(pausedSignedMedia.status, 403);

    const pausedGallery = await reqJson(baseUrl, guestJar, `/api/gallery/${accessCode}`);
    assert.equal(pausedGallery.res.status, 404);

    // 15. Password rotation & login CSRF check
    const pwChange = await reqJson(baseUrl, studioJar, "/api/auth/password", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        current_password: "StrongPassword123!",
        new_password: "RotatedPassword456!",
      }),
    });
    assert.equal(pwChange.res.status, 200);
    csrf = pwChange.data.csrfToken;

    // 16. QR generation, photo deletion & event deletion cleanup
    const qrRes = await reqJson(baseUrl, studioJar, `/api/events/${pubEv.data.event.id}/qr`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    });
    assert.equal(qrRes.res.status, 200);
    assert.match(qrRes.data.qr, /^data:image\/png;base64,/);

    await reqJson(baseUrl, studioJar, `/api/events/${eventId}`, {
      method: "PATCH",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({ status: "active" }),
    });
    const delPhoto = await reqJson(baseUrl, studioJar, `/api/photos/${uploadedPhoto.id}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    });
    assert.equal(delPhoto.res.status, 200);
    assert.equal((await reqJson(baseUrl, studioJar, "/api/dashboard")).data.storage.used_bytes, 0);

    // 16b. Bulk photo upload & bulk delete
    const bulkForm = new FormData();
    bulkForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "bulk-one.jpg");
    bulkForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "bulk-two.jpg");
    const bulkUp = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/photos`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: bulkForm,
    });
    assert.equal(bulkUp.res.status, 201);
    assert.equal(bulkUp.data.photos.length, 2);

    const bulkDel = await reqJson(baseUrl, studioJar, `/api/events/${eventId}/photos/bulk-delete`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({ photo_ids: bulkUp.data.photos.map((p) => p.id) }),
    });
    assert.equal(bulkDel.res.status, 200);
    assert.equal(bulkDel.data.deleted_count, 2);
    assert.equal((await reqJson(baseUrl, studioJar, "/api/dashboard")).data.storage.used_bytes, 0);

    const delEv = await reqJson(baseUrl, studioJar, `/api/events/${eventId}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    });
    assert.equal(delEv.res.status, 200);
    assert.equal(fs.existsSync(path.join(tmpDir, "uploads", eventId)), false);

    // 17. Private selfie-only gallery hides all un-matched photos until face scan
    const selfieOnlyEv = await reqJson(baseUrl, studioJar, "/api/events", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        title: "Selfie Only Event",
        is_public: true,
        ai_enabled: true,
        selfie_only: true,
      }),
    });
    assert.equal(selfieOnlyEv.res.status, 201);
    const soId = selfieOnlyEv.data.event.id;
    const soCode = selfieOnlyEv.data.event.access_code;

    const soForm = new FormData();
    soForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "personA.jpg");
    soForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "personB.jpg");
    const soUpload = await reqJson(baseUrl, studioJar, `/api/events/${soId}/photos`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: soForm,
    });
    assert.equal(soUpload.res.status, 201);
    const [photoA, photoB] = soUpload.data.photos;

    const descA = Array.from({ length: 128 }, () => 0.12);
    const descB = Array.from({ length: 128 }, () => -0.65);
    await reqJson(baseUrl, studioJar, `/api/events/${soId}/faces`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        entries: [
          { photo_id: photoA.id, descriptors: [descA] },
          { photo_id: photoB.id, descriptors: [descB] },
        ],
      }),
    });

    const freshGuest = new CookieJar();
    const beforeScan = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}`);
    assert.equal(beforeScan.res.status, 200);
    assert.equal(beforeScan.data.event.selfie_only, true);
    assert.equal(beforeScan.data.photos.length, 0);
    assert.equal(beforeScan.data.total_event_photos, 2);

    const scanRes = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": beforeScan.data.csrfToken },
      body: JSON.stringify({ descriptors: [descA] }),
    });
    assert.equal(scanRes.res.status, 200);
    assert.equal(scanRes.data.photos.length, 1);
    assert.equal(scanRes.data.photos[0].id, photoA.id);

    const afterScan = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}`);
    assert.equal(afterScan.data.photos.length, 1);
    assert.equal(afterScan.data.photos[0].id, photoA.id);

    const cleared = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}/match/clear`, {
      method: "POST",
      headers: { "X-CSRF-Token": beforeScan.data.csrfToken },
    });
    assert.equal(cleared.res.status, 200);
    const afterClear = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}`);
    assert.equal(afterClear.data.photos.length, 0);

    // 17b. Upload with inline face_entries automatically indexes faces atomically on upload
    const descAuto = Array.from({ length: 128 }, () => 0.33);
    const autoForm = new FormData();
    autoForm.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "auto-indexed.jpg");
    autoForm.append("face_entries", JSON.stringify([{ indexed: true, descriptors: [descAuto] }]));
    const autoUp = await reqJson(baseUrl, studioJar, `/api/events/${soId}/photos`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: autoForm,
    });
    assert.equal(autoUp.res.status, 201);
    assert.equal(autoUp.data.faces_indexed_total, 1);
    assert.equal(autoUp.data.photos[0].face_indexed, true);
    assert.equal(autoUp.data.photos[0].face_count, 1);

    const autoMatch = await reqJson(baseUrl, freshGuest, `/api/gallery/${soCode}/match`, {
      method: "POST",
      headers: { "X-CSRF-Token": beforeScan.data.csrfToken },
      body: JSON.stringify({ descriptors: [descAuto] }),
    });
    assert.equal(autoMatch.res.status, 200);
    assert.equal(autoMatch.data.photos.length, 1);
    assert.equal(autoMatch.data.photos[0].id, autoUp.data.photos[0].id);

    // 17. Logout & login with new password (verifies login CSRF protection too)
    await reqJson(baseUrl, studioJar, "/api/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    });

    const noLoginCsrf = await reqJson(baseUrl, studioJar, "/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: "maya@example.com", password: "RotatedPassword456!" }),
    });
    assert.equal(noLoginCsrf.res.status, 403);

    const loginCsrf = await getCsrf(baseUrl, studioJar);
    const badLogin = await reqJson(baseUrl, studioJar, "/api/auth/login", {
      method: "POST",
      headers: { "X-CSRF-Token": loginCsrf },
      body: JSON.stringify({ email: "maya@example.com", password: "StrongPassword123!" }),
    });
    assert.equal(badLogin.res.status, 401);

    const goodLogin = await reqJson(baseUrl, studioJar, "/api/auth/login", {
      method: "POST",
      headers: { "X-CSRF-Token": loginCsrf },
      body: JSON.stringify({ email: "maya@example.com", password: "RotatedPassword456!" }),
    });
    assert.equal(goodLogin.res.status, 200);
  });

  it("enforces per-user storage quota and optional invite-code registration", async () => {
    const quotaTmp = fs.mkdtempSync(path.join(os.tmpdir(), "snapfind-quota-"));
    const quotaApp = createApp({
      port: 0,
      uploadDir: path.join(quotaTmp, "uploads"),
      dbPath: path.join(quotaTmp, "quota.sqlite"),
      maxStorageBytesPerUser: 500,
      registrationInviteCode: "STUDIO-2026",
      disableRateLimit: true,
      sessionSecret: "test-secret-with-more-than-thirty-two-characters-1234",
    });
    await new Promise((resolve) => quotaApp.server.listen(0, "127.0.0.1", () => resolve()));
    const qUrl = `http://127.0.0.1:${quotaApp.server.address().port}`;
    try {
      const jar = new CookieJar();
      const csrf0 = await getCsrf(qUrl, jar);

      const noInvite = await reqJson(qUrl, jar, "/api/auth/register", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf0 },
        body: JSON.stringify({
          name: "Quota User",
          email: "quota@example.com",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(noInvite.res.status, 403);

      const reg = await reqJson(qUrl, jar, "/api/auth/register", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf0 },
        body: JSON.stringify({
          name: "Quota User",
          email: "quota@example.com",
          password: "StrongPassword123!",
          invite_code: "STUDIO-2026",
        }),
      });
      assert.equal(reg.res.status, 201);
      const csrf = reg.data.csrfToken;
      const ev = await reqJson(qUrl, jar, "/api/events", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf },
        body: JSON.stringify({ title: "Quota Event" }),
      });
      const sampleJpeg = await makeSampleJpegWithExif();
      const fd = new FormData();
      fd.append("photos", new Blob([sampleJpeg], { type: "image/jpeg" }), "big.jpg");
      const up = await reqJson(qUrl, jar, `/api/events/${ev.data.event.id}/photos`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrf },
        body: fd,
      });
      assert.equal(up.res.status, 413);
    } finally {
      await quotaApp.close();
      fs.rmSync(quotaTmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("exercises real rate-limiter keyGenerators on PIN unlock and guest actions", async () => {
    const rlTmp = fs.mkdtempSync(path.join(os.tmpdir(), "snapfind-rl-"));
    const rlApp = createApp({
      port: 0,
      uploadDir: path.join(rlTmp, "uploads"),
      dbPath: path.join(rlTmp, "rl.sqlite"),
      disableRateLimit: false,
      sessionSecret: "test-secret-with-more-than-thirty-two-characters-1234",
    });
    await new Promise((resolve) => rlApp.server.listen(0, "127.0.0.1", () => resolve()));
    const rlUrl = `http://127.0.0.1:${rlApp.server.address().port}`;
    try {
      const jar = new CookieJar();
      const csrf0 = await getCsrf(rlUrl, jar);
      const reg = await reqJson(rlUrl, jar, "/api/auth/register", {
        method: "POST",
        headers: { "X-CSRF-Token": csrf0 },
        body: JSON.stringify({
          name: "RL User",
          email: "rl@example.com",
          password: "StrongPassword123!",
        }),
      });
      const ev = await reqJson(rlUrl, jar, "/api/events", {
        method: "POST",
        headers: { "X-CSRF-Token": reg.data.csrfToken },
        body: JSON.stringify({ title: "RL PIN Event", pin: "4321" }),
      });
      const guestJar = new CookieJar();
      const gInit = await reqJson(rlUrl, guestJar, `/api/gallery/${ev.data.event.access_code}`);
      const unlock = await reqJson(rlUrl, guestJar, `/api/gallery/${ev.data.event.access_code}/unlock`, {
        method: "POST",
        headers: { "X-CSRF-Token": gInit.data.csrfToken },
        body: JSON.stringify({ pin: "4321" }),
      });
      assert.equal(unlock.res.status, 200);
      assert.equal(unlock.data.ok, true);
    } finally {
      await rlApp.close();
      fs.rmSync(rlTmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
