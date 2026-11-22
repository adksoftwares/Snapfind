const $ = (selector) => document.querySelector(selector);
const code = decodeURIComponent(location.pathname.split("/").filter(Boolean).pop() || "");

function getGuestKey() {
  let key = localStorage.getItem("snapfind_guest_key");
  if (!key || key.length < 8) {
    key = (crypto.randomUUID
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`);
    localStorage.setItem("snapfind_guest_key", key);
  }
  return key;
}

const guestKey = getGuestKey();
let csrfToken = null;
let currentEvent = null;
let photos = [];
let matchedPhotoIds = null;
let matchedScoreById = new Map();
let downloadPickSet = new Set();
let totalEventPhotos = 0;
let capturedSelfieBlob = null;
let faceMatchRequest = null;
let selfiePreviewObjectUrl = null;
let cameraStream = null;
let favouritedSet = new Set();
let selectedSet = new Set();
let activeFilter = "all";
let currentPage = 1;
let totalPages = 1;
let searchTimer = null;
let aiCancelled = false;
let socket = null;\nlet lightboxPhotoId = null;

function esc(value = "") {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function photoTitleFallback(p) {
  return p.original_name || "Event photo";
}

function downloadUrl(url) {
  return url.includes("?") ? `${url}&download=1` : `${url}?download=1`;
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(url, { ...options, method, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function getVisiblePhotos() {
  if (activeFilter === "favourites") {
    return photos.filter((p) => favouritedSet.has(p.id));
  }
  if (activeFilter === "matches" && matchedPhotoIds) {
    return photos
      .filter((p) => matchedPhotoIds.has(p.id))
      .sort((a, b) => {
        const da = matchedScoreById.get(a.id)?.distance ?? 1;
        const db = matchedScoreById.get(b.id)?.distance ?? 1;
        return da - db;
      });
  }
  return photos;
}

function updateFilterCounts() {
  $("#favCount").textContent = String(favouritedSet.size);
  if (matchedPhotoIds) {
    $("#aiFilterTab").classList.remove("hidden");
    $("#matchCount").textContent = String(matchedPhotoIds.size);
  } else {
    $("#aiFilterTab").classList.add("hidden");
  }
  document.querySelectorAll("[data-filter]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.filter === activeFilter);
  });
}

function syncGuestBulkBar(visible = getVisiblePhotos()) {
  const bar = $("#guestBulkBar");
  if (!bar) return;

  const existingIds = new Set(photos.map((p) => p.id));
  for (const id of [...downloadPickSet]) {
    if (!existingIds.has(id)) downloadPickSet.delete(id);
  }

  bar.classList.toggle("hidden", visible.length === 0);
  if (!visible.length) return;

  const visiblePickedCount = visible.filter((p) => downloadPickSet.has(p.id)).length;
  const totalPicked = downloadPickSet.size;

  $("#guestShownCount").textContent = String(visible.length);
  $("#guestDownloadCount").textContent = `${totalPicked} selected`;
  const selectAllEl = $("#guestSelectAll");
  selectAllEl.checked = visiblePickedCount > 0 && visiblePickedCount === visible.length;
  selectAllEl.indeterminate = visiblePickedCount > 0 && visiblePickedCount < visible.length;

  $("#guestClearPickBtn").classList.toggle("hidden", totalPicked === 0);
  const dlBtn = $("#guestDownloadSelectedBtn");
  dlBtn.classList.toggle("hidden", totalPicked === 0);
  if (!dlBtn.disabled) {
    dlBtn.textContent = `↓ Download selected (${totalPicked})`;
  }
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32Bytes(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function buildZipBlob(files) {
  const encoder = new TextEncoder();
  const now = new Date();
  const dosTime =
    ((now.getHours() & 0x1f) << 11) |
    ((now.getMinutes() & 0x3f) << 5) |
    ((now.getSeconds() >> 1) & 0x1f);
  const dosDate =
    ((Math.max(1980, now.getFullYear()) - 1980) << 9) |
    (((now.getMonth() + 1) & 0xf) << 5) |
    (now.getDate() & 0x1f);

  const chunks = [];
  const centralDir = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = encoder.encode(file.name);
    const data = file.bytes;
    const crc = crc32Bytes(data);

    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true);
    lv.setUint16(10, dosTime, true);
    lv.setUint16(12, dosDate, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    local.set(nameBytes, 30);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, dosTime, true);
    cv.setUint16(14, dosDate, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);

    chunks.push(local, data);
    centralDir.push(central);
    offset += local.length + data.length;
  }

  const centralSize = centralDir.reduce((sum, c) => sum + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);

  return new Blob([...chunks, ...centralDir, eocd], { type: "application/zip" });
}

function uniqueFilename(rawName, usedNames) {
  const clean = String(rawName || "photo.jpg").replace(/[\\/:*?"<>|]/g, "_") || "photo.jpg";
  if (!usedNames.has(clean.toLowerCase())) {
    usedNames.add(clean.toLowerCase());
    return clean;
  }
  const dot = clean.lastIndexOf(".");
  const base = dot > 0 ? clean.slice(0, dot) : clean;
  const ext = dot > 0 ? clean.slice(dot) : "";
  let idx = 2;
  while (usedNames.has(`${base} (${idx})${ext}`.toLowerCase())) {
    idx += 1;
  }
  const next = `${base} (${idx})${ext}`;
  usedNames.add(next.toLowerCase());
  return next;
}

function triggerBlobDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function renderPhotos() {
  updateFilterCounts();
  const visible = getVisiblePhotos();
  const grid = $("#galleryGrid");

  grid.innerHTML = visible
    .map((p) => {
      const isFav = favouritedSet.has(p.id);
      const isSel = selectedSet.has(p.id);
      const isPicked = downloadPickSet.has(p.id);
      const matchInfo = activeFilter === "matches" ? matchedScoreById.get(p.id) : null;
      return `
        <article class="gallery-photo ${isPicked ? "is-selected" : ""}">
          <div class="gallery-photo-media">
            <img loading="lazy" src="${esc(p.thumb_url)}" alt="${esc(p.caption || photoTitleFallback(p))}" role="button" tabindex="0" aria-label="Open photo: ${esc(p.caption || photoTitleFallback(p))}" data-open-lightbox="${esc(p.id)}">
            ${matchInfo ? `<span class="match-badge">Approx. similarity ${matchInfo.confidence}/100</span>` : ""}
            <label class="guest-dl-pick" title="Select photo for download">
              <input type="checkbox" class="guest-dl-cb" data-dl-pick="${esc(p.id)}" ${isPicked ? "checked" : ""}>
              <span>Pick</span>
            </label>
          </div>
          <div>
            <span class="photo-title">${esc(p.caption || p.original_name || "Event moment")}</span>
            <div class="gallery-actions">
              <button type="button" class="${isFav ? "fav-on" : ""}" data-fav-toggle="${esc(p.id)}" aria-label="${isFav ? "Remove from favourites" : "Add to favourites"}" aria-pressed="${isFav}" title="${isFav ? "Remove favourite" : "Add favourite"}">${isFav ? "♥" : "♡"}</button>
              <button type="button" data-select-photo="${esc(p.id)}" aria-label="${isSel ? "Photo already selected" : "Request this photo from the studio"}" title="Request photo from studio" ${isSel ? "disabled" : ""}>${isSel ? "✓ Selected" : "Select"}</button>
              <a href="${esc(downloadUrl(p.url))}" download="${esc(p.original_name)}" aria-label="Download original: ${esc(p.original_name || "photo")}" title="Download original">↓</a>
            </div>
          </div>
        </article>
      `;
    })
    .join("");

  if (visible.length === 0) {
    grid.innerHTML = "";
    $("#galleryEmpty").classList.remove("hidden");
    if (currentEvent?.selfie_only && photos.length === 0) {
      $("#galleryEmpty").innerHTML = `<span>Private selfie-only gallery</span><small>Scan your face above to unlock and download only your photos (${totalEventPhotos} photo(s) in this event).</small>`;
    } else {
      $("#galleryEmpty").innerHTML =
        '<span>No photos in this view yet.</span><small>Try switching filters or wait for the photographer to upload photos.</small>';
    }
    $("#galleryMessage").textContent = "";
  } else {
    $("#galleryEmpty").classList.add("hidden");
    $("#galleryMessage").textContent = `Showing ${visible.length} photo(s)`;
  }

  if (totalPages > 1 && activeFilter === "all") {
    $("#paginationControls").classList.remove("hidden");
    $("#pageInfo").textContent = `Page ${currentPage} of ${totalPages}`;
    $("#prevPage").disabled = currentPage <= 1;
    $("#nextPage").disabled = currentPage >= totalPages;
  } else {
    $("#paginationControls").classList.add("hidden");
  }

  syncGuestBulkBar(visible);

  document.querySelectorAll(".guest-dl-cb").forEach((cb) => {
    cb.onchange = () => {
      const pid = cb.dataset.dlPick;
      if (cb.checked) downloadPickSet.add(pid);
      else downloadPickSet.delete(pid);
      cb.closest(".gallery-photo")?.classList.toggle("is-selected", cb.checked);
      syncGuestBulkBar();
    };
  });

  document.querySelectorAll("[data-open-lightbox]").forEach((img) => {
    img.onclick = () => openLightbox(img.dataset.openLightbox);\n    img.onkeydown = (event) => {\n      if (event.key === "Enter" || event.key === " ") {\n        event.preventDefault();\n        openLightbox(img.dataset.openLightbox);\n      }\n    };
  });

  document.querySelectorAll("[data-fav-toggle]").forEach((btn) => {
    btn.onclick = () => toggleFavourite(btn.dataset.favToggle);
  });

  document.querySelectorAll("[data-select-photo]").forEach((btn) => {
    btn.onclick = () => selectPhoto(btn.dataset.selectPhoto);
  });
}

async function toggleFavourite(photoId) {
  $("#galleryError").textContent = "";
  try {
    const res = await api(`/api/gallery/${encodeURIComponent(code)}/favourite`, {
      method: "POST",
      body: JSON.stringify({ photo_id: photoId, guest_key: guestKey }),
    });
    if (res.favourited) {
      favouritedSet.add(photoId);
    } else {
      favouritedSet.delete(photoId);
    }
    renderPhotos();
  } catch (err) {
    $("#galleryError").textContent = err.message;
  }
}

async function selectPhoto(photoId) {
  $("#galleryError").textContent = "";
  const guestName = $("#guestName").value.trim();
  const guestEmail = $("#guestEmail").value.trim();
  try {
    await api(`/api/gallery/${encodeURIComponent(code)}/select`, {
      method: "POST",
      body: JSON.stringify({
        photo_id: photoId,
        guest_name: guestName,
        guest_email: guestEmail,
        guest_key: guestKey,
      }),
    });
    selectedSet.add(photoId);
    renderPhotos();
  } catch (err) {
    $("#galleryError").textContent = err.message;
  }
}

function openLightbox(photoId) {
  const photo = photos.find((p) => p.id === photoId);
  if (!photo) return;
  const isFav = favouritedSet.has(photo.id);
  const isSel = selectedSet.has(photo.id);

  $("#lightboxBody").innerHTML = `
    <img class="lightbox-img" src="${esc(photo.preview_url)}" alt="${esc(photo.caption || photo.original_name)}">
    <div class="lightbox-bar">
      <div>
        <b>${esc(photo.caption || photo.original_name || "Event moment")}</b>
        <p class="muted">${photo.width && photo.height ? `${photo.width} × ${photo.height}px` : ""}</p>
      </div>
      <div class="gallery-actions lightbox-nav-actions">
        <button class="btn sm ghost" id="lbPrev" type="button" aria-label="Previous photo">← Previous</button>
        <span class="lightbox-position" id="lbPosition"></span>
        <button class="btn sm ghost" id="lbNext" type="button" aria-label="Next photo">Next →</button>
        <button class="btn sm ghost" id="lbFav" type="button">${isFav ? "♥ Favourited" : "♡ Favourite"}</button>
        <button class="btn sm ghost" id="lbSelect" type="button" ${isSel ? "disabled" : ""}>${isSel ? "✓ Selected" : "Request / Select"}</button>
        <a class="btn sm" href="${esc(downloadUrl(photo.url))}" download="${esc(photo.original_name)}">↓ Download original</a>
      </div>
    </div>
  `;

  const lbList = getVisiblePhotos();
  const lbIndex = lbList.findIndex((p) => p.id === photoId);
  $("#lbPosition").textContent = lbIndex >= 0 ? `${lbIndex + 1} of ${lbList.length}` : "";
  $("#lbPrev").disabled = lbIndex <= 0;
  $("#lbNext").disabled = lbIndex < 0 || lbIndex >= lbList.length - 1;
  $("#lbPrev").onclick = () => moveLightbox(-1);
  $("#lbNext").onclick = () => moveLightbox(1);

  $("#lbFav").onclick = async () => {
    await toggleFavourite(photo.id);
    openLightbox(photo.id);
  };
  $("#lbSelect").onclick = async () => {
    await selectPhoto(photo.id);
    openLightbox(photo.id);
  };

  if (!$("#lightboxDialog").open) {
    $("#lightboxDialog").showModal();
  }
}

function moveLightbox(direction) {
  const list = getVisiblePhotos();
  const index = list.findIndex((p) => p.id === lightboxPhotoId);
  const next = index + direction;
  if (next >= 0 && next < list.length) openLightbox(list[next].id);
}

document.addEventListener("keydown", (event) => {
  if (!$("#lightboxDialog")?.open) return;
  if (event.key === "ArrowLeft") {
    event.preventDefault();
    moveLightbox(-1);
  } else if (event.key === "ArrowRight") {
    event.preventDefault();
    moveLightbox(1);
  }
});

$("#lightboxClose").onclick = () => $("#lightboxDialog").close();

async function ensureMatchedPhotosLoaded(matchSet) {
  if (!matchSet || matchSet.size === 0) return;
  const missingIds = [...matchSet].filter((id) => !photos.some((p) => p.id === id));
  if (missingIds.length === 0) return;

  const fetched = await api(
    `/api/gallery/${encodeURIComponent(code)}?limit=100&ids=${encodeURIComponent(missingIds.slice(0, 100).join(","))}`
  );
  const existingIds = new Set(photos.map((p) => p.id));
  for (const p of fetched.photos || []) {
    if (!existingIds.has(p.id)) photos.push(p);
  }
}

async function fetchAllEventPhotosForScan() {
  const all = [];
  let page = 1;
  let pages = 1;
  do {
    const res = await api(`/api/gallery/${encodeURIComponent(code)}?page=${page}&limit=100`);
    all.push(...(res.photos || []));
    pages = res.pagination?.total_pages || 1;
    page += 1;
  } while (page <= pages && !aiCancelled);
  return all;
}

async function loadGallery(page = 1) {
  const q = $("#gallerySearch").value.trim();
  const params = new URLSearchParams({
    page: String(page),
    limit: "48",
    guest_key: guestKey,
  });
  if (q) params.set("q", q);

  const data = await api(`/api/gallery/${encodeURIComponent(code)}?${params.toString()}`);
  if (data.csrfToken) csrfToken = data.csrfToken;
  currentEvent = data.event;
  const hasFaceConsent = Boolean(currentEvent.face_match_consent);
  $("#aiConsent").checked = hasFaceConsent;
  setAiConsentControls(hasFaceConsent);

  $("#eventTitle").textContent = currentEvent.title;
  $("#eventMeta").textContent = [currentEvent.event_date, currentEvent.venue]
    .filter(Boolean)
    .join(" · ");
  $("#eventDesc").textContent = currentEvent.description || "";
  $("#galleryBadge").textContent = currentEvent.selfie_only
    ? "PRIVATE SELFIE GALLERY"
    : currentEvent.has_pin
      ? "PRIVATE GALLERY"
      : "EVENT GALLERY";

  if (data.locked) {
    $("#galleryMain").classList.add("locked-mode");
    $("#pinGate").classList.remove("hidden");
    $("#galleryContent").classList.add("hidden");
    return;
  }

  $("#galleryMain").classList.remove("locked-mode");
  $("#pinGate").classList.add("hidden");
  $("#galleryContent").classList.remove("hidden");

  photos = data.photos;
  totalEventPhotos = Number(data.total_event_photos ?? photos.length);
  currentPage = data.pagination.page;
  totalPages = data.pagination.total_pages || 1;
  favouritedSet = new Set(data.favourited_ids || []);
  selectedSet = new Set(data.selected_ids || []);

  if (currentEvent.selfie_only) {
    const content = $("#galleryContent");
    const aiSec = $("#aiSection");
    const filtersEl = content?.querySelector(".gallery-filters");
    if (aiSec && content && filtersEl && aiSec.nextElementSibling !== filtersEl) {
      content.insertBefore(aiSec, filtersEl);
    }
    if (data.selfie_scanned && photos.length > 0 && !matchedPhotoIds) {
      matchedPhotoIds = new Set(photos.map((p) => p.id));
      activeFilter = "matches";
    }
    $("[data-filter='all']")?.classList.toggle("hidden", photos.length === 0);
    $("#aiResetScanBtn")?.classList.toggle("hidden", !(data.selfie_scanned || matchedPhotoIds));
  }

  if (activeFilter === "matches" && matchedPhotoIds && !currentEvent.selfie_only) {
    await ensureMatchedPhotosLoaded(matchedPhotoIds);
  }

  $("#aiSection").classList.toggle("hidden", !currentEvent.ai_enabled);
  if (currentEvent.ai_enabled && data.indexed_faces > 0) {
    $("#aiStatus").textContent = currentEvent.selfie_only
      ? `Ready (${data.indexed_faces} faces indexed). Scan your selfie to reveal only your photos.`
      : `Fast server-side AI search ready (${data.indexed_faces} faces pre-indexed).`;
  } else if (currentEvent.ai_enabled && currentEvent.selfie_only) {
    $("#aiStatus").textContent =
      "Waiting for studio AI face indexing. Ask the photographer to click Index faces in Studio Dashboard.";
  }

  renderPhotos();

  if (!socket && typeof io === "function") {
    socket = io();
    socket.emit("gallery:join", code);
    socket.on("photos:added", () => loadGallery(currentPage));
    socket.on("photos:removed", () => loadGallery(currentPage));
  }
}

$("#pinForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#pinError").textContent = "";
  try {
    const res = await api(`/api/gallery/${encodeURIComponent(code)}/unlock`, {
      method: "POST",
      body: JSON.stringify({ pin: $("#pinInput").value }),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    $("#pinInput").value = "";
    await loadGallery(1);
  } catch (err) {
    $("#pinError").textContent = err.message;
  }
};

$("#guestName").value = localStorage.getItem("snapfind_guest_name") || "";
$("#guestEmail").value = localStorage.getItem("snapfind_guest_email") || "";
$("#guestName").oninput = (e) => localStorage.setItem("snapfind_guest_name", e.target.value);
$("#guestEmail").oninput = (e) => localStorage.setItem("snapfind_guest_email", e.target.value);

$("#gallerySearch").oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadGallery(1), 250);
};

document.querySelectorAll("[data-filter]").forEach((btn) => {
  btn.onclick = () => {
    activeFilter = btn.dataset.filter;
    renderPhotos();
  };
});

$("#prevPage").onclick = () => {
  if (currentPage > 1) loadGallery(currentPage - 1);
};
$("#nextPage").onclick = () => {
  if (currentPage < totalPages) loadGallery(currentPage + 1);
};

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((t) => t.stop());
    cameraStream = null;
  }
  const video = $("#selfieVideo");
  if (video) video.srcObject = null;
  $("#cameraBox")?.classList.add("hidden");
}

function showSelfiePreview(blobOrFile, label, sub = "Analysed locally on your device — never uploaded.") {
  if (selfiePreviewObjectUrl) {
    URL.revokeObjectURL(selfiePreviewObjectUrl);
    selfiePreviewObjectUrl = null;
  }
  if (!blobOrFile) {
    $("#selfiePreviewWrap").classList.add("hidden");
    return;
  }
  if (typeof blobOrFile === "string") {
    $("#selfiePreviewImg").src = blobOrFile;
  } else {
    selfiePreviewObjectUrl = URL.createObjectURL(blobOrFile);
    $("#selfiePreviewImg").src = selfiePreviewObjectUrl;
  }
  $("#selfiePreviewLabel").textContent = label;
  $("#selfiePreviewSub").textContent = sub;
  $("#selfiePreviewWrap").classList.remove("hidden");
}

$("#guestSelectAll").onchange = () => {
  const checked = $("#guestSelectAll").checked;
  const visible = getVisiblePhotos();
  for (const p of visible) {
    if (checked) downloadPickSet.add(p.id);
    else downloadPickSet.delete(p.id);
  }
  renderPhotos();
};

$("#guestClearPickBtn").onclick = () => {
  downloadPickSet.clear();
  renderPhotos();
};

$("#guestDownloadSelectedBtn").onclick = async () => {
  const picked = photos.filter((p) => downloadPickSet.has(p.id));
  if (!picked.length) return;
  $("#galleryError").textContent = "";

  if (picked.length === 1) {
    const single = picked[0];
    const a = document.createElement("a");
    a.href = downloadUrl(single.url);
    a.download = single.original_name || "photo.jpg";
    document.body.appendChild(a);
    a.click();
    a.remove();
    return;
  }

  const btn = $("#guestDownloadSelectedBtn");
  btn.disabled = true;
  let completed = 0;
  btn.textContent = `Preparing ZIP (0/${picked.length})…`;

  try {
    const usedNames = new Set();
    const results = new Array(picked.length);
    let cursor = 0;

    async function worker() {
      while (cursor < picked.length) {
        const idx = cursor++;
        const photo = picked[idx];
        const res = await fetch(downloadUrl(photo.url), { credentials: "same-origin" });
        if (!res.ok) throw new Error(`Failed to fetch ${photo.original_name || "photo"}`);
        const buf = new Uint8Array(await res.arrayBuffer());
        results[idx] = {
          name: uniqueFilename(photo.original_name || `${photo.id}.jpg`, usedNames),
          bytes: buf,
        };
        completed += 1;
        btn.textContent = `Preparing ZIP (${completed}/${picked.length})…`;
      }
    }

    await Promise.all([worker(), worker(), worker()]);
    const zipBlob = buildZipBlob(results.filter(Boolean));
    const safeTitle = String(currentEvent?.title || code || "snapfind")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "snapfind";
    triggerBlobDownload(zipBlob, `${safeTitle}-photos.zip`);
    $("#galleryMessage").textContent = `Downloaded ${picked.length} photo(s) in ${safeTitle}-photos.zip.`;
  } catch (err) {
    $("#galleryError").textContent = err.message || "Bulk download failed";
  } finally {
    btn.disabled = false;
    syncGuestBulkBar();
  }
};

function setAiConsentControls(enabled) {
  $("#selfie").disabled = !enabled;
  $("#aiCameraBtn").disabled = !enabled;
  $("#aiFind").disabled = !enabled;
  $("#selfiePickerLabel").classList.toggle("disabled", !enabled);
  $("#aiMatchOptions").classList.toggle("disabled", !enabled);
  document.querySelectorAll('#aiMatchOptions input[name="aiOpt"]').forEach((el) => {
    el.disabled = !enabled;
  });
}

function getAiMatchOptions() {
  const checked = new Set(
    [...document.querySelectorAll('#aiMatchOptions input[name="aiOpt"]:checked')].map((el) => el.value)
  );
  return {
    angle_distance: checked.has("angle_distance"),
    hair_beard_lighting: checked.has("hair_beard_lighting"),
    distant_group: checked.has("distant_group"),
  };
}

$("#aiConsent").onchange = async (e) => {
  const checked = e.target.checked;
  $("#aiConsent").disabled = true;
  setAiConsentControls(false);
  if (checked) {
    $("#aiStatus").textContent = "Confirming face-discovery consent for this gallery session…";
    try {
      await api(`/api/gallery/${encodeURIComponent(code)}/match/consent`, { method: "POST" });
      setAiConsentControls(true);
      $("#aiStatus").textContent = "Consent active for this gallery session. You can withdraw it at any time.";
    } catch (err) {
      $("#aiConsent").checked = false;
      $("#aiStatus").textContent = err.message || "Consent could not be enabled. Please try again.";
    } finally {
      $("#aiConsent").disabled = false;
    }
    return;
  }

  aiCancelled = true;
  stopCamera();
  capturedSelfieBlob = null;
  $("#selfie").value = "";
  $("#selfieFileName").textContent = "Upload selfie photo…";
  showSelfiePreview(null);
  matchedPhotoIds = null;
  matchedScoreById = new Map();
  downloadPickSet.clear();
  activeFilter = "all";
  if (currentEvent?.selfie_only) photos = [];
  $("#aiResetScanBtn").classList.add("hidden");
  $("#aiStatus").textContent = "Consent withdrawn. Clearing session match results…";
  renderPhotos();
  try {
    const pendingMatch = faceMatchRequest;
    if (pendingMatch) await pendingMatch.catch(() => {});
    await api(`/api/gallery/${encodeURIComponent(code)}/match/clear`, { method: "POST" });
    $("#aiStatus").textContent = "Face discovery consent withdrawn; session match results cleared.";
  } catch {
    $("#aiStatus").textContent = "Consent withdrawn locally. Session results could not be cleared right now; close this gallery session to clear them when it expires.";
  } finally {
    $("#aiConsent").disabled = false;
  }
};

$("#selfie").onchange = (e) => {
  const f = e.target.files[0];
  if (f) {
    capturedSelfieBlob = null;
    stopCamera();
    $("#selfieFileName").textContent = f.name;
    showSelfiePreview(f, `Selected: ${f.name}`);
  } else {
    $("#selfieFileName").textContent = "Upload selfie photo…";
  }
};

$("#aiCameraBtn").onclick = async () => {
  $("#aiStatus").textContent = "";
  if (!navigator.mediaDevices?.getUserMedia) {
    $("#aiStatus").textContent = "Live camera is unavailable in this browser. Please upload a selfie photo instead.";
    return;
  }
  try {
    stopCamera();
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "user", width: { ideal: 960 }, height: { ideal: 720 } },
      audio: false,
    });
    const video = $("#selfieVideo");
    video.srcObject = cameraStream;
    $("#cameraBox").classList.remove("hidden");
    $("#aiStatus").textContent = "Look at the camera in good light and tap Capture selfie.";
  } catch (err) {
    $("#aiStatus").textContent = err?.message || "Camera permission denied. Upload a selfie photo instead.";
  }
};

$("#closeCameraBtn").onclick = () => {
  stopCamera();
};

$("#captureSelfieBtn").onclick = async () => {
  const video = $("#selfieVideo");
  if (!video.videoWidth || !video.videoHeight) {
    $("#aiStatus").textContent = "Camera is still starting up…";
    return;
  }
  const canvas = document.createElement("canvas");
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  if (!blob) return;
  capturedSelfieBlob = blob;
  $("#selfie").value = "";
  $("#selfieFileName").textContent = "Camera selfie captured";
  stopCamera();
  showSelfiePreview(blob, "Live selfie captured — ready to scan");
  $("#aiStatus").textContent = "Selfie captured. Tap Find my photos to match across all angles and distances.";
};

$("#aiCancel").onclick = () => {
  aiCancelled = true;
  $("#aiStatus").textContent = "Scan cancelled.";
  $("#aiCancel").classList.add("hidden");
};

$("#aiFind").onclick = async () => {
  const selfieSource = capturedSelfieBlob || $("#selfie").files[0];
  if (!selfieSource) {
    $("#aiStatus").textContent = "Tap Use camera or upload a selfie photo first.";
    return;
  }
  if (!window.faceapi || !window.SnapFindFace) {
    $("#aiStatus").textContent = "Face matching library could not be loaded. Standard browsing still works.";
    return;
  }

  aiCancelled = false;
  const btn = $("#aiFind");
  btn.disabled = true;
  $("#aiCancel").classList.remove("hidden");
  $("#aiStatus").textContent = "Loading self-hosted face models…";

  try {
    stopCamera();
    await window.SnapFindFace.loadFaceModels();

    if (aiCancelled) return;
    const matchOpts = getAiMatchOptions();
    $("#aiStatus").textContent = "Analysing face shape, angle, hair/beard tolerance, and mirrored views on this device…";
    const query = await window.SnapFindFace.extractSelfieQuery(selfieSource, matchOpts);
    showSelfiePreview(
      query.previewDataUrl,
      `Face analysed (${query.descriptors.length} variant${query.descriptors.length === 1 ? "" : "s"})`,
      "Selfie image stays on this device; face descriptors are shared securely for server matching."
    );

    if (aiCancelled) return;
    const threshold =
      query.threshold ||
      window.SnapFindFace.computeMatchThreshold?.(matchOpts) ||
      window.SnapFindFace.DEFAULT_MATCH_THRESHOLD;

    $("#aiStatus").textContent = "Matching against indexed event faces…";
    const pendingMatch = api(`/api/gallery/${encodeURIComponent(code)}/match`, {
      method: "POST",
      body: JSON.stringify({ descriptors: query.descriptors, threshold }),
    });
    faceMatchRequest = pendingMatch;
    let serverMatch;
    try {
      serverMatch = await pendingMatch;
    } finally {
      faceMatchRequest = null;
    }
    if (aiCancelled) return;

    const matches = new Set();
    const scores = new Map();
    if (serverMatch.indexed_count > 0) {
      if (Array.isArray(serverMatch.photos) && serverMatch.photos.length > 0) {
        if (currentEvent?.selfie_only) {
          photos = serverMatch.photos;
        } else {
          const byId = new Map(photos.map((p) => [p.id, p]));
          for (const mp of serverMatch.photos) {
            if (!byId.has(mp.id)) photos.push(mp);
          }
        }
      } else if (currentEvent?.selfie_only) {
        photos = [];
      }
      for (const m of serverMatch.matches || []) {
        matches.add(m.photo_id);
        scores.set(m.photo_id, { distance: m.distance, confidence: m.confidence });
      }
      $("#aiStatus").textContent = matches.size
        ? `Found ${matches.size} matching photo(s) across ${serverMatch.indexed_count} indexed photos. Selfie image stayed on device; descriptors were sent securely.`
        : `No matches found across ${serverMatch.indexed_count} indexed photos. Try ticking all 3 match options above or taking a clearer selfie.`;
    } else if (currentEvent?.selfie_only) {
      photos = [];
      $("#aiStatus").textContent =
        serverMatch.scanned_photos_count > 0
          ? "All photos in this event were scanned, but no detectable faces were found in them."
          : "Waiting for studio face indexing: open Studio Dashboard → Manage Event once so the event's photos get indexed.";
    } else {
      // Fallback: fetch all pages of lightweight WebP previews and scan multi-scale locally
      $("#aiStatus").textContent = "Fetching event preview list…";
      const allPhotos = await fetchAllEventPhotosForScan();
      const existingIds = new Set(photos.map((p) => p.id));
      for (const p of allPhotos) {
        if (!existingIds.has(p.id)) photos.push(p);
      }

      for (let i = 0; i < allPhotos.length; i++) {
        if (aiCancelled) return;
        const p = allPhotos[i];
        $("#aiStatus").textContent = `Scanning photo ${i + 1} of ${allPhotos.length} (all faces, angles & distances)…`;
        try {
          const evFaces = await window.SnapFindFace.extractEventFaces(p.preview_url);
          let best = 1;
          for (const desc of evFaces.descriptors) {
            const d = window.SnapFindFace.minDescriptorDistance(query.descriptors, desc);
            if (d < best) best = d;
          }
          if (best < threshold) {
            matches.add(p.id);
            const confidence = Math.max(1, Math.min(99, Math.round((1 - best / 0.85) * 100)));
            scores.set(p.id, { distance: Number(best.toFixed(4)), confidence });
          }
        } catch {
          // skip unreadable preview
        }
      }
      $("#aiStatus").textContent = matches.size
        ? `Found ${matches.size} matching photo(s) across ${allPhotos.length} event photos. Selfie image stayed on device; local matching was used.`
        : `Scanned ${allPhotos.length} photo(s) with no strong match. Selfie stayed on device; scan was performed locally.`;
    }

    matchedPhotoIds = matches;
    matchedScoreById = scores;
    if (!currentEvent?.selfie_only) {
      await ensureMatchedPhotosLoaded(matches);
    }
    $("#aiResetScanBtn")?.classList.remove("hidden");
    activeFilter = "matches";
    renderPhotos();
  } catch (err) {
    $("#aiStatus").textContent = err.message || "Face discovery could not be completed.";
  } finally {
    btn.disabled = !$("#aiConsent").checked;
    $("#aiCancel").classList.add("hidden");
  }
};

$("#aiResetScanBtn").onclick = async () => {
  try {
    await api(`/api/gallery/${encodeURIComponent(code)}/match/clear`, { method: "POST" });
  } catch {
    // ignore clear error
  }
  matchedPhotoIds = null;
  matchedScoreById = new Map();
  downloadPickSet.clear();
  capturedSelfieBlob = null;
  $("#selfie").value = "";
  $("#selfieFileName").textContent = "Upload selfie photo…";
  showSelfiePreview(null);
  $("#aiResetScanBtn").classList.add("hidden");
  activeFilter = "all";
  if (currentEvent?.selfie_only) {
    photos = [];
  }
  $("#aiStatus").textContent = "Ready for next selfie scan.";
  renderPhotos();
};

loadGallery(1).catch((err) => {
  $("#eventTitle").textContent = "Gallery unavailable";
  $("#eventDesc").textContent = err.message;
});
