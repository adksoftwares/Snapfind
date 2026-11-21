(function initSnapFindFaceEngine(global) {
  const MODEL_URI = "/vendor/face-api/model";
  const DEFAULT_MATCH_THRESHOLD = 0.63;
  const MATCH_THRESHOLDS = {
    strict: 0.56,
    balanced: 0.63,
    adaptive: 0.67,
  };
  let modelsPromise = null;

  async function loadFaceModels() {
    if (!global.faceapi) {
      throw new Error("Self-hosted face-api library could not be loaded.");
    }
    if (!modelsPromise) {
      const { faceapi } = global;
      modelsPromise = Promise.all([
        faceapi.nets.ssdMobilenetv1.loadFromUri(MODEL_URI),
        faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URI),
        faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URI),
        faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URI),
      ]).catch((err) => {
        modelsPromise = null;
        throw err;
      });
    }
    return modelsPromise;
  }

  function loadHtmlImageFromBlob(blob) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Could not decode image"));
      };
      img.src = url;
    });
  }

  async function decodeSourceBitmap(source) {
    if (typeof source === "string") {
      const res = await fetch(source, { credentials: "same-origin" });
      if (!res.ok) throw new Error("Failed to fetch image");
      source = await res.blob();
    }

    if (source instanceof Blob) {
      if (typeof createImageBitmap === "function") {
        try {
          const bitmap = await createImageBitmap(source, { imageOrientation: "from-image" });
          return {
            drawable: bitmap,
            width: bitmap.width,
            height: bitmap.height,
            cleanup: () => bitmap.close?.(),
          };
        } catch {
          // Fallback to Image element if createImageBitmap options are unsupported
        }
      }
      const img = await loadHtmlImageFromBlob(source);
      return {
        drawable: img,
        width: img.naturalWidth || img.width,
        height: img.naturalHeight || img.height,
        cleanup: () => {},
      };
    }

    if (source instanceof HTMLVideoElement) {
      const w = source.videoWidth || source.width;
      const h = source.videoHeight || source.height;
      if (!w || !h) throw new Error("Camera frame is not ready yet");
      return { drawable: source, width: w, height: h, cleanup: () => {} };
    }

    if (source instanceof HTMLCanvasElement) {
      return { drawable: source, width: source.width, height: source.height, cleanup: () => {} };
    }

    if (source instanceof HTMLImageElement) {
      return {
        drawable: source,
        width: source.naturalWidth || source.width,
        height: source.naturalHeight || source.height,
        cleanup: () => {},
      };
    }

    throw new Error("Unsupported image source");
  }

  async function sourceToNormalizedCanvas(source, { maxDim = 960, paddingRatio = 0 } = {}) {
    const decoded = await decodeSourceBitmap(source);
    try {
      const srcW = decoded.width;
      const srcH = decoded.height;
      if (!srcW || !srcH) throw new Error("Image has zero dimensions");

      const scale = Math.min(1, maxDim / Math.max(srcW, srcH));
      const drawW = Math.max(1, Math.round(srcW * scale));
      const drawH = Math.max(1, Math.round(srcH * scale));
      const padX = Math.round(drawW * paddingRatio);
      const padY = Math.round(drawH * paddingRatio);

      const canvas = document.createElement("canvas");
      canvas.width = drawW + padX * 2;
      canvas.height = drawH + padY * 2;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#f4f5f3";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(decoded.drawable, padX, padY, drawW, drawH);

      return canvas;
    } finally {
      decoded.cleanup();
    }
  }

  function flipCanvasHorizontally(srcCanvas) {
    const canvas = document.createElement("canvas");
    canvas.width = srcCanvas.width;
    canvas.height = srcCanvas.height;
    const ctx = canvas.getContext("2d");
    ctx.translate(canvas.width, 0);
    ctx.scale(-1, 1);
    ctx.drawImage(srcCanvas, 0, 0);
    return canvas;
  }

  function rotateCanvas(srcCanvas, degrees) {
    const rad = (degrees * Math.PI) / 180;
    const canvas = document.createElement("canvas");
    canvas.width = srcCanvas.width;
    canvas.height = srcCanvas.height;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#f4f5f3";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate(rad);
    ctx.drawImage(srcCanvas, -srcCanvas.width / 2, -srcCanvas.height / 2);
    return canvas;
  }

  function buildTightFaceCanvas(srcCanvas, box, marginRatio = 0.28) {
    const padW = Math.round(box.width * marginRatio);
    const padH = Math.round(box.height * marginRatio);
    const sx = Math.max(0, Math.floor(box.x - padW));
    const sy = Math.max(0, Math.floor(box.y - padH));
    const ex = Math.min(srcCanvas.width, Math.ceil(box.x + box.width + padW));
    const ey = Math.min(srcCanvas.height, Math.ceil(box.y + box.height + padH));
    const sw = Math.max(1, ex - sx);
    const sh = Math.max(1, ey - sy);
    const out = document.createElement("canvas");
    const scale = Math.min(2, 512 / Math.max(sw, sh));
    out.width = Math.max(1, Math.round(sw * scale));
    out.height = Math.max(1, Math.round(sh * scale));
    const ctx = out.getContext("2d");
    if ("filter" in ctx) {
      ctx.filter = "contrast(1.06) brightness(1.03)";
    }
    ctx.drawImage(srcCanvas, sx, sy, sw, sh, 0, 0, out.width, out.height);
    return out;
  }

  function boxIoU(a, b) {
    const x1 = Math.max(a.x, b.x);
    const y1 = Math.max(a.y, b.y);
    const x2 = Math.min(a.x + a.width, b.x + b.width);
    const y2 = Math.min(a.y + a.height, b.y + b.height);
    const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
    if (!inter) return 0;
    const areaA = Math.max(1, a.width * a.height);
    const areaB = Math.max(1, b.width * b.height);
    return inter / (areaA + areaB - inter);
  }

  function dedupeDetections(detections, iouThreshold = 0.42) {
    const sorted = [...detections].sort(
      (a, b) => (b.detection?.score || 0) - (a.detection?.score || 0)
    );
    const kept = [];
    for (const det of sorted) {
      const box = det.detection?.box;
      if (!box) continue;
      const duplicate = kept.some((existing) => boxIoU(box, existing.detection.box) > iouThreshold);
      if (!duplicate) kept.push(det);
    }
    return kept;
  }

  function pickPrimaryFace(detections) {
    if (!detections.length) return null;
    return [...detections].sort((a, b) => {
      const areaA = a.detection.box.width * a.detection.box.height;
      const areaB = b.detection.box.width * b.detection.box.height;
      return areaB * (b.detection.score || 0.5) - areaA * (a.detection.score || 0.5);
    })[0];
  }

  function getEyeRollDegrees(landmarks) {
    if (!landmarks || typeof landmarks.getLeftEye !== "function") return 0;
    const leftEye = landmarks.getLeftEye();
    const rightEye = landmarks.getRightEye();
    if (!leftEye?.length || !rightEye?.length) return 0;
    const avg = (pts) =>
      pts.reduce(
        (acc, p) => ({ x: acc.x + p.x / pts.length, y: acc.y + p.y / pts.length }),
        { x: 0, y: 0 }
      );
    const l = avg(leftEye);
    const r = avg(rightEye);
    return (Math.atan2(r.y - l.y, r.x - l.x) * 180) / Math.PI;
  }

  async function detectPrimaryFaceOnCanvas(canvas) {
    const { faceapi } = global;
    const attempts = [
      () => new faceapi.SsdMobilenetv1Options({ minConfidence: 0.3, maxResults: 10 }),
      () => new faceapi.TinyFaceDetectorOptions({ inputSize: 512, scoreThreshold: 0.25 }),
      () => new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.2 }),
    ];

    for (const buildOpts of attempts) {
      const detections = await faceapi
        .detectAllFaces(canvas, buildOpts())
        .withFaceLandmarks()
        .withFaceDescriptors();
      const primary = pickPrimaryFace(detections);
      if (primary) return { primary, canvas, rotation: 0 };
    }

    for (const deg of [-15, 15]) {
      const rotated = rotateCanvas(canvas, deg);
      const detections = await faceapi
        .detectAllFaces(rotated, new faceapi.TinyFaceDetectorOptions({ inputSize: 416, scoreThreshold: 0.22 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      const primary = pickPrimaryFace(detections);
      if (primary) return { primary, canvas: rotated, rotation: deg };
    }

    return null;
  }

  async function extractEventFaces(source) {
    await loadFaceModels();
    const { faceapi } = global;
    const canvas = await sourceToNormalizedCanvas(source, { maxDim: 1280, paddingRatio: 0.04 });

    const [ssdDetections, tinyDetections] = await Promise.all([
      faceapi
        .detectAllFaces(canvas, new faceapi.SsdMobilenetv1Options({ minConfidence: 0.28, maxResults: 100 }))
        .withFaceLandmarks()
        .withFaceDescriptors(),
      faceapi
        .detectAllFaces(canvas, new faceapi.TinyFaceDetectorOptions({ inputSize: 608, scoreThreshold: 0.28 }))
        .withFaceLandmarks()
        .withFaceDescriptors(),
    ]);

    let merged = dedupeDetections([...ssdDetections, ...tinyDetections], 0.42);

    if (!merged.length) {
      const fallbackTiny = await faceapi
        .detectAllFaces(canvas, new faceapi.TinyFaceDetectorOptions({ inputSize: 416, scoreThreshold: 0.2 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      merged = dedupeDetections(fallbackTiny, 0.42);
    }

    return {
      faceCount: merged.length,
      descriptors: merged.map((d) => Array.from(d.descriptor)),
    };
  }

  function computeMatchThreshold(options = {}) {
    let threshold = 0.56;
    if (options.angle_distance) threshold += 0.06;
    if (options.hair_beard_lighting) threshold += 0.05;
    if (options.distant_group) threshold += 0.02;
    return Math.min(0.68, Number(threshold.toFixed(2)));
  }

  async function extractSelfieQuery(source, options = {}) {
    await loadFaceModels();
    const { faceapi } = global;
    const useAngleDistance = options.angle_distance !== false;
    const useHairBeard = options.hair_beard_lighting !== false;
    // Generous padding fixes close-up selfies where the face touches frame edges
    const baseCanvas = await sourceToNormalizedCanvas(source, { maxDim: 960, paddingRatio: 0.14 });
    const detected = await detectPrimaryFaceOnCanvas(baseCanvas);

    if (!detected) {
      throw new Error(
        "No clear face detected in your selfie. Make sure your face is well-lit and centered in frame."
      );
    }

    const { primary, canvas: workingCanvas } = detected;
    const variants = [Array.from(primary.descriptor)];

    if (useAngleDistance) {
      // Mirrored variant compensates for front-camera horizontal mirroring & asymmetry
      const mirroredCanvas = flipCanvasHorizontally(workingCanvas);
      const mirroredDetections = await faceapi
        .detectAllFaces(mirroredCanvas, new faceapi.SsdMobilenetv1Options({ minConfidence: 0.25, maxResults: 5 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      const mirroredPrimary = pickPrimaryFace(mirroredDetections);
      if (mirroredPrimary) {
        variants.push(Array.from(mirroredPrimary.descriptor));
      }
    }

    if (useHairBeard) {
      // Tight lighting-balanced face crop reduces hair/background variance
      const tightCanvas = buildTightFaceCanvas(workingCanvas, primary.detection.box, 0.28);
      const tightDetections = await faceapi
        .detectAllFaces(tightCanvas, new faceapi.SsdMobilenetv1Options({ minConfidence: 0.25, maxResults: 3 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      const tightPrimary = pickPrimaryFace(tightDetections);
      if (tightPrimary) {
        variants.push(Array.from(tightPrimary.descriptor));
      }
    }

    // Eye-roll deskew variant improves angled/tilted selfie matching
    const eyeAngle = getEyeRollDegrees(primary.landmarks);
    if (useAngleDistance && Math.abs(eyeAngle) > 6 && Math.abs(eyeAngle) < 40) {
      const leveledCanvas = rotateCanvas(workingCanvas, -eyeAngle);
      const leveledDetections = await faceapi
        .detectAllFaces(leveledCanvas, new faceapi.SsdMobilenetv1Options({ minConfidence: 0.25, maxResults: 5 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      const leveledPrimary = pickPrimaryFace(leveledDetections);
      if (leveledPrimary) {
        variants.push(Array.from(leveledPrimary.descriptor));
      }
    }

    const previewCanvas = document.createElement("canvas");
    const pScale = Math.min(1, 220 / Math.max(baseCanvas.width, baseCanvas.height));
    previewCanvas.width = Math.max(1, Math.round(baseCanvas.width * pScale));
    previewCanvas.height = Math.max(1, Math.round(baseCanvas.height * pScale));
    previewCanvas.getContext("2d").drawImage(baseCanvas, 0, 0, previewCanvas.width, previewCanvas.height);

    return {
      descriptors: variants,
      threshold: computeMatchThreshold(options),
      previewDataUrl: previewCanvas.toDataURL("image/jpeg", 0.85),
      primaryScore: Number((primary.detection.score || 0).toFixed(2)),
      angleDeg: Math.round(eyeAngle),
    };
  }

  function minDescriptorDistance(queryDescriptors, candidateDescriptor) {
    const { faceapi } = global;
    let best = 1;
    for (const q of queryDescriptors) {
      const dist = faceapi.euclideanDistance(q, candidateDescriptor);
      if (dist < best) best = dist;
    }
    return best;
  }

  global.SnapFindFace = {
    DEFAULT_MATCH_THRESHOLD,
    MATCH_THRESHOLDS,
    computeMatchThreshold,
    loadFaceModels,
    sourceToNormalizedCanvas,
    extractEventFaces,
    extractSelfieQuery,
    minDescriptorDistance,
  };
})(window);
