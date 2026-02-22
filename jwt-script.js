const $ = (id) => document.getElementById(id);

const tokenInput = $("tokenInput");
const verifySecret = $("verifySecret");
const verifyKey = $("verifyKey");
const headerOutput = $("headerOutput");
const payloadOutput = $("payloadOutput");
const structureBadge = $("structureBadge");
const signatureBadge = $("signatureBadge");
const expiryBadge = $("expiryBadge");
const nowTime = $("nowTime");
const editStatus = $("editStatus");
const strengthBadge = $("strengthBadge");
const strengthScore = $("strengthScore");
const insightsList = $("insightsList");
const reportOutput = $("reportOutput");
const copyReport = $("copyReport");

const claimIss = $("claimIss");
const claimSub = $("claimSub");
const claimAud = $("claimAud");
const claimJti = $("claimJti");
const claimIat = $("claimIat");
const claimNbf = $("claimNbf");
const claimExp = $("claimExp");

const metaAlg = $("metaAlg");
const metaTyp = $("metaTyp");
const metaKid = $("metaKid");
const metaLen = $("metaLen");
const metaHeaderBytes = $("metaHeaderBytes");
const metaPayloadBytes = $("metaPayloadBytes");
const metaSigBytes = $("metaSigBytes");

const algSelect = $("algSelect");
const signSecret = $("signSecret");
const signKey = $("signKey");
const headerInput = $("headerInput");
const payloadInput = $("payloadInput");
const tokenOutput = $("tokenOutput");

const copyHeader = $("copyHeader");
const copyPayload = $("copyPayload");
const copyToken = $("copyToken");
const formatHeader = $("formatHeader");
const formatPayload = $("formatPayload");

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

let suppressTokenInput = false;
let lastSource = "token";
let encodeVersion = 0;
let signatureState = { status: "unknown", detail: "" };

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function isHmacAlg(alg) {
  return typeof alg === "string" && alg.startsWith("HS");
}

function isRsaAlg(alg) {
  return typeof alg === "string" && (alg.startsWith("RS") || alg.startsWith("PS"));
}

function isEcAlg(alg) {
  return typeof alg === "string" && alg.startsWith("ES");
}

function hasJsrsasign() {
  return typeof KJUR !== "undefined" && KJUR.jws && KJUR.jws.JWS;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(base64Url) {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad) {
    base64 += "=".repeat(4 - pad);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncodeString(value) {
  return bytesToBase64Url(textEncoder.encode(value));
}

function base64UrlDecodeString(value) {
  return textDecoder.decode(base64UrlToBytes(value));
}

function safeJsonParse(value) {
  try {
    return { data: JSON.parse(value), error: null };
  } catch (error) {
    return { data: null, error: error.message };
  }
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function setBadge(el, state, text) {
  const base = "px-3 py-1 rounded-full text-xs font-semibold";
  const styles = {
    idle: "bg-slate-800 text-slate-300",
    ok: "bg-emerald-500/20 text-emerald-200 border border-emerald-400/40",
    warn: "bg-amber-500/20 text-amber-200 border border-amber-400/40",
    error: "bg-rose-500/20 text-rose-200 border border-rose-400/40",
  };
  el.className = `${base} ${styles[state] || styles.idle}`;
  el.textContent = text;
}

function setClaim(el, value) {
  el.textContent = value ?? "--";
}

function setEditStatus(state, text) {
  const base = "text-xs";
  const styles = {
    idle: "text-slate-400",
    ok: "text-emerald-300",
    warn: "text-amber-300",
    error: "text-rose-300",
  };
  editStatus.className = `${base} ${styles[state] || styles.idle}`;
  editStatus.textContent = text || "";
}

function setMeta(el, value) {
  el.textContent = value ?? "--";
}

function setSignatureState(status, detail) {
  signatureState = { status, detail: detail || "" };
}

function setStrength(score, level) {
  if (score === null || score === undefined) {
    strengthBadge.className = "px-3 py-1 rounded-full bg-slate-800 text-slate-300 text-xs font-semibold";
    strengthBadge.textContent = "Strength: --";
    strengthScore.textContent = "Score: --";
    return;
  }

  const styles = {
    strong: "bg-emerald-500/20 text-emerald-200 border border-emerald-400/40",
    good: "bg-cyan-500/20 text-cyan-200 border border-cyan-400/40",
    fair: "bg-amber-500/20 text-amber-200 border border-amber-400/40",
    weak: "bg-rose-500/20 text-rose-200 border border-rose-400/40",
    critical: "bg-rose-600/30 text-rose-200 border border-rose-400/60",
  };

  strengthBadge.className = `px-3 py-1 rounded-full text-xs font-semibold ${styles[level] || styles.fair}`;
  strengthBadge.textContent = `Strength: ${level}`;
  strengthScore.textContent = `Score: ${score}`;
}

function renderInsights(findings) {
  insightsList.innerHTML = "";
  if (!findings || findings.length === 0) {
    const item = document.createElement("div");
    item.className = "rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2 text-slate-300";
    item.textContent = "No obvious issues detected.";
    insightsList.appendChild(item);
    return;
  }

  const severityStyles = {
    critical: "border-rose-500/50 bg-rose-500/10 text-rose-200",
    high: "border-amber-500/50 bg-amber-500/10 text-amber-200",
    medium: "border-cyan-500/50 bg-cyan-500/10 text-cyan-100",
    low: "border-slate-700 bg-slate-950/60 text-slate-300",
  };

  findings.forEach((finding) => {
    const item = document.createElement("div");
    const style = severityStyles[finding.severity] || severityStyles.low;
    item.className = `rounded-xl border px-3 py-2 ${style}`;
    item.textContent = `${finding.title} ${finding.detail ? `- ${finding.detail}` : ""}`;
    insightsList.appendChild(item);
  });
}

function formatFinding(finding) {
  const detail = finding.detail ? `: ${finding.detail}` : "";
  return `- [${finding.severity.toUpperCase()}] ${finding.title}${detail}`;
}

function updateReport(analysis) {
  if (!analysis) {
    reportOutput.value = "";
    return;
  }

  const statusMap = {
    verified: "verified",
    invalid: "invalid",
    missing_key: "not verified (missing key)",
    unchecked: "not verified",
    none: "unsigned (alg=none)",
    unknown: "unknown",
  };
  const signatureLabel = statusMap[analysis.signatureStatus] || analysis.signatureStatus;

  const lines = [];
  lines.push("# JWT Analysis Report");
  lines.push("");
  lines.push("## Summary");
  lines.push(`- Score: ${analysis.score}`);
  lines.push(`- Strength: ${analysis.level}`);
  lines.push(`- Signature: ${signatureLabel}`);
  lines.push(`- Token length: ${analysis.tokenLength}`);
  lines.push("");
  lines.push("## Header");
  lines.push(analysis.headerJson || "(unavailable)");
  lines.push("");
  lines.push("## Payload");
  lines.push(analysis.payloadJson || "(unavailable)");
  lines.push("");
  lines.push("## Findings");
  if (analysis.findings.length === 0) {
    lines.push("- No obvious issues detected.");
  } else {
    analysis.findings.forEach((finding) => lines.push(formatFinding(finding)));
  }
  lines.push("");
  lines.push("## Recommended Tests");
  if (analysis.recommendations.length === 0) {
    lines.push("- Validate application-specific claims and authorization logic.");
  } else {
    analysis.recommendations.forEach((rec) => lines.push(`- ${rec}`));
  }
  lines.push("");
  lines.push("## Reporting Possibilities");
  analysis.possibilities.forEach((item) => lines.push(`- ${item}`));
  lines.push("");
  lines.push("## Notes");
  analysis.notes.forEach((note) => lines.push(`- ${note}`));

  reportOutput.value = lines.join("\n");
}

function resetClaims() {
  setClaim(claimIss, "--");
  setClaim(claimSub, "--");
  setClaim(claimAud, "--");
  setClaim(claimJti, "--");
  setClaim(claimIat, "--");
  setClaim(claimNbf, "--");
  setClaim(claimExp, "--");
}

function resetMetadata() {
  setMeta(metaAlg, "--");
  setMeta(metaTyp, "--");
  setMeta(metaKid, "--");
  setMeta(metaLen, "--");
  setMeta(metaHeaderBytes, "--");
  setMeta(metaPayloadBytes, "--");
  setMeta(metaSigBytes, "--");
}

function asUnixSeconds(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }
  return null;
}

function unixToLocal(seconds) {
  if (typeof seconds !== "number") return "--";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleString();
}

function updateClaims(payload) {
  if (!payload) {
    resetClaims();
    setBadge(expiryBadge, "idle", "Expiry: --");
    return;
  }

  setClaim(claimIss, payload.iss ?? "--");
  setClaim(claimSub, payload.sub ?? "--");
  setClaim(claimAud, Array.isArray(payload.aud) ? payload.aud.join(", ") : payload.aud ?? "--");
  setClaim(claimJti, payload.jti ?? "--");

  const iat = asUnixSeconds(payload.iat);
  const nbf = asUnixSeconds(payload.nbf);
  const exp = asUnixSeconds(payload.exp);

  setClaim(claimIat, iat !== null ? unixToLocal(iat) : "--");
  setClaim(claimNbf, nbf !== null ? unixToLocal(nbf) : "--");
  setClaim(claimExp, exp !== null ? unixToLocal(exp) : "--");

  const now = Math.floor(Date.now() / 1000);
  if (exp !== null && exp < now) {
    setBadge(expiryBadge, "error", "Expiry: expired");
  } else if (nbf !== null && nbf > now) {
    setBadge(expiryBadge, "warn", "Expiry: not active");
  } else if (exp !== null) {
    setBadge(expiryBadge, "ok", "Expiry: valid");
  } else {
    setBadge(expiryBadge, "warn", "Expiry: none");
  }
}

function safeBytesLength(part) {
  try {
    return `${base64UrlToBytes(part).length} bytes`;
  } catch (error) {
    return "--";
  }
}

function updateMetadata(token, header, parts) {
  const [headerPart, payloadPart, sigPart] = parts || [];
  setMeta(metaLen, token ? `${token.length} chars` : "--");
  setMeta(metaAlg, header?.alg ?? "--");
  setMeta(metaTyp, header?.typ ?? "--");
  setMeta(metaKid, header?.kid ?? "--");
  setMeta(metaHeaderBytes, headerPart ? safeBytesLength(headerPart) : "--");
  setMeta(metaPayloadBytes, payloadPart ? safeBytesLength(payloadPart) : "--");
  setMeta(metaSigBytes, sigPart !== undefined ? safeBytesLength(sigPart) : "--");
}

function parseKeyInfo(pem) {
  if (!pem || !hasJsrsasign() || typeof KEYUTIL === "undefined") return null;
  try {
    const keyObj = KEYUTIL.getKey(pem);
    if (keyObj.n) {
      return { type: "rsa", bits: keyObj.n.bitLength() };
    }
    if (keyObj.curveName) {
      return { type: "ec", curve: keyObj.curveName };
    }
    return { type: "unknown" };
  } catch (error) {
    return { type: "invalid", error: error.message };
  }
}

function getScoreLevel(score) {
  if (score >= 85) return "strong";
  if (score >= 70) return "good";
  if (score >= 50) return "fair";
  if (score >= 30) return "weak";
  return "critical";
}

function analyzeToken(token, header, payload, context = {}) {
  if (!token) {
    setStrength(null, null);
    renderInsights([]);
    updateReport(null);
    return null;
  }

  let score = 100;
  const findings = [];
  const recommendations = [];
  const possibilities = [];
  const notes = [];
  const alg = header?.alg;
  const now = Math.floor(Date.now() / 1000);
  const partsCount = context.partsCount || 0;
  const isEncrypted = partsCount === 5 || header?.enc;
  const hasPayload = payload && typeof payload === "object";

  if (isEncrypted) {
    findings.push({
      severity: "medium",
      title: "Encrypted JWT (JWE)",
      detail: "Payload is not readable without a decryption key.",
    });
    notes.push("JWE tokens require decryption before claim validation.");
    score -= 5;
  }

  if (!header || !payload) {
    findings.push({
      severity: "high",
      title: "Malformed token",
      detail: "Header or payload is not valid JSON.",
    });
    recommendations.push("Ensure JWT parsing handles malformed JSON safely.");
    score -= 30;
  }

  if (!alg) {
    findings.push({
      severity: "critical",
      title: "Missing alg",
      detail: "Algorithm is not defined in the header.",
    });
    recommendations.push("Reject tokens missing the alg header.");
    score -= 40;
  } else if (alg === "none") {
    findings.push({
      severity: "critical",
      title: "Unsigned token",
      detail: "alg=none disables signature protection.",
    });
    recommendations.push("Disallow alg=none unless explicitly required.");
    score = 0;
  } else if (isHmacAlg(alg)) {
    const secret = verifySecret.value || signSecret.value || "";
    if (!secret) {
      findings.push({
        severity: "high",
        title: "Missing HMAC secret",
        detail: "Provide a shared secret to verify HS* signatures.",
      });
      recommendations.push("Verify HS* signatures using a strong shared secret.");
      score -= 15;
    } else if (secret.length < 16) {
      findings.push({
        severity: "critical",
        title: "Weak HMAC secret",
        detail: "Secret is shorter than 16 characters.",
      });
      recommendations.push("Use 32+ character secrets for HS* tokens.");
      score -= 35;
    } else if (secret.length < 32) {
      findings.push({
        severity: "medium",
        title: "Moderate HMAC secret",
        detail: "Consider 32+ characters for stronger HS* security.",
      });
      recommendations.push("Rotate and strengthen HMAC secrets.");
      score -= 15;
    }
  } else if (isRsaAlg(alg) || isEcAlg(alg)) {
    const keyText = (verifyKey.value || signKey.value || "").trim();
    if (!keyText) {
      findings.push({
        severity: "high",
        title: "Missing public key",
        detail: "Provide a key to verify RS/ES/PS signatures.",
      });
      recommendations.push("Verify RS/ES/PS tokens with the correct public key.");
      score -= 15;
    } else {
      const keyInfo = parseKeyInfo(keyText);
      if (keyInfo?.type === "invalid") {
        findings.push({
          severity: "high",
          title: "Key parse failed",
          detail: keyInfo.error || "Unable to parse key.",
        });
        recommendations.push("Use a valid PEM-encoded key for verification.");
        score -= 15;
      } else if (keyInfo?.type === "rsa") {
        if (keyInfo.bits < 2048) {
          findings.push({
            severity: "critical",
            title: "Weak RSA key",
            detail: `RSA key is ${keyInfo.bits} bits (recommend >= 2048).`,
          });
          recommendations.push("Use RSA keys with 2048+ bits.");
          score -= 35;
        } else if (keyInfo.bits < 3072) {
          findings.push({
            severity: "medium",
            title: "RSA key size",
            detail: `${keyInfo.bits} bits (3072+ is stronger).`,
          });
          recommendations.push("Prefer 3072+ bit RSA keys for long-lived systems.");
          score -= 10;
        }
      } else if (keyInfo?.type === "ec" && alg.startsWith("ES")) {
        const curveMap = { ES256: "secp256r1", ES384: "secp384r1", ES512: "secp521r1" };
        const expected = curveMap[alg];
        if (expected && keyInfo.curve && keyInfo.curve !== expected) {
          findings.push({
            severity: "high",
            title: "EC curve mismatch",
            detail: `Key curve is ${keyInfo.curve}, expected ${expected}.`,
          });
          recommendations.push("Match EC curve to the algorithm selected.");
          score -= 20;
        }
      }
    }
  }

  if (signatureState.status === "invalid") {
    findings.push({
      severity: "critical",
      title: "Signature invalid",
      detail: signatureState.detail || "Provided key/secret does not validate the token.",
    });
    recommendations.push("Reject tokens with invalid signatures.");
    score -= 40;
  } else if (signatureState.status === "missing_key") {
    findings.push({
      severity: "high",
      title: "Signature not verified",
      detail: "Key/secret not provided for verification.",
    });
    recommendations.push("Always verify the JWT signature server-side.");
    score -= 15;
  } else if (signatureState.status === "unchecked") {
    findings.push({
      severity: "medium",
      title: "Signature unchecked",
      detail: "Algorithm not verified in this tool.",
    });
    score -= 5;
  }

  if (hasPayload) {
    const exp = asUnixSeconds(payload?.exp);
    const nbf = asUnixSeconds(payload?.nbf);
    const iat = asUnixSeconds(payload?.iat);

    if (exp === null) {
      findings.push({
        severity: "medium",
        title: "Missing exp",
        detail: "Token has no expiration claim.",
      });
      recommendations.push("Set a short expiration (exp) for access tokens.");
      score -= 10;
    } else if (exp < now) {
      findings.push({
        severity: "medium",
        title: "Token expired",
        detail: "exp is in the past.",
      });
      score -= 5;
    } else if (exp - now > 60 * 60 * 24 * 30) {
      findings.push({
        severity: "low",
        title: "Long expiration",
        detail: "Token is valid for more than 30 days.",
      });
      recommendations.push("Consider shorter lifetimes and refresh tokens.");
      score -= 5;
    }

    if (nbf !== null && exp !== null && nbf > exp) {
      findings.push({
        severity: "high",
        title: "nbf after exp",
        detail: "Token starts after it expires.",
      });
      score -= 15;
    }

    if (nbf !== null && nbf > now) {
      findings.push({
        severity: "low",
        title: "Not active yet",
        detail: "nbf is in the future.",
      });
      score -= 2;
    }

    if (iat !== null && iat > now + 300) {
      findings.push({
        severity: "low",
        title: "iat in future",
        detail: "Issued-at time is ahead of current time.",
      });
      score -= 2;
    }
  } else if (!isEncrypted) {
    findings.push({
      severity: "medium",
      title: "Missing payload",
      detail: "Claims are not available for analysis.",
    });
    score -= 5;
  }

  if (header?.typ && header.typ !== "JWT") {
    findings.push({
      severity: "low",
      title: "Non-standard typ",
      detail: `typ is set to ${header.typ}.`,
    });
    score -= 2;
  }

  if (header?.crit && Array.isArray(header.crit) && header.crit.length > 0) {
    findings.push({
      severity: "medium",
      title: "Critical headers",
      detail: `crit=${header.crit.join(", ")} requires strict processing.`,
    });
    recommendations.push("Reject tokens with unknown crit headers.");
    score -= 10;
  }

  const keyUrlFields = ["jku", "x5u"];
  keyUrlFields.forEach((field) => {
    if (header?.[field]) {
      if (typeof header[field] === "string" && header[field].startsWith("http:")) {
        findings.push({
          severity: "critical",
          title: "Insecure key URL",
          detail: `${field} uses HTTP instead of HTTPS.`,
        });
        recommendations.push("Require HTTPS for key URLs.");
        score -= 15;
      }
      findings.push({
        severity: "high",
        title: "Key URL in header",
        detail: `${field} is present. Ensure strict allowlisting.`,
      });
      recommendations.push("Allowlist trusted key URLs and enforce HTTPS.");
      possibilities.push("Test for SSRF or key confusion via attacker-controlled key URLs.");
      score -= 10;
    }
  });

  if (header?.x5c) {
    findings.push({
      severity: "medium",
      title: "x5c present",
      detail: "Ensure certificate chains are validated against a trusted root.",
    });
    recommendations.push("Validate x5c against a trusted CA and pin keys if possible.");
    score -= 5;
  }

  if (header?.zip) {
    findings.push({
      severity: "low",
      title: "zip header present",
      detail: "Compressed JWTs require secure decompression handling.",
    });
    recommendations.push("Defend against compression bombs and enforce limits.");
    score -= 2;
  }

  if (header?.cty && header.cty.toUpperCase() === "JWT") {
    findings.push({
      severity: "low",
      title: "Nested JWT",
      detail: "cty=JWT indicates a nested token; ensure nested validation.",
    });
    recommendations.push("Validate nested JWTs end-to-end.");
    score -= 2;
  }

  if (header?.jwk) {
    findings.push({
      severity: "high",
      title: "Embedded JWK",
      detail: "Attacker-controlled keys can bypass verification if not validated.",
    });
    recommendations.push("Reject untrusted embedded JWKs.");
    possibilities.push("Test for key injection using a crafted jwk header.");
    score -= 10;
  }

  if (header?.kid) {
    const kid = String(header.kid);
    if (/[\\\\/]/.test(kid) || kid.includes("..")) {
      findings.push({
        severity: "high",
        title: "Suspicious kid",
        detail: "kid includes path traversal characters.",
      });
      recommendations.push("Treat kid as an identifier, not a file path.");
      possibilities.push("Test for path traversal or SQL injection via kid.");
      score -= 10;
    }
    if (/['\";|]/.test(kid) || kid.includes("--")) {
      findings.push({
        severity: "medium",
        title: "kid injection risk",
        detail: "kid contains potentially dangerous characters.",
      });
      recommendations.push("Sanitize kid inputs and avoid dynamic file/database lookups.");
      score -= 5;
    }
  }

  if (header?.jwk?.kty && isHmacAlg(alg) && header.jwk.kty !== "oct") {
    findings.push({
      severity: "high",
      title: "Key type mismatch",
      detail: `HS* expects symmetric keys but jwk.kty is ${header.jwk.kty}.`,
    });
    possibilities.push("Test for algorithm confusion (RS->HS) with public key as HMAC secret.");
    score -= 15;
  }

  if (isHmacAlg(alg) && (header?.jku || header?.x5u || header?.x5c)) {
    findings.push({
      severity: "medium",
      title: "HMAC with asymmetric metadata",
      detail: "HS* tokens should not rely on asymmetric key headers.",
    });
    possibilities.push("Test for algorithm confusion by swapping HS/RS tokens.");
    score -= 8;
  }

  if (hasPayload) {
    const payloadKeys = Object.keys(payload);
    const sensitiveKeys = payloadKeys.filter((key) =>
      /pass|secret|token|apikey|api_key|email|ssn|credit|card/i.test(key)
    );
    if (sensitiveKeys.length > 0) {
      findings.push({
        severity: "medium",
        title: "Sensitive claims in payload",
        detail: `Readable fields: ${sensitiveKeys.join(", ")}.`,
      });
      recommendations.push("Avoid storing sensitive data in JWT payloads.");
      score -= 8;
    }
  }

  if (hasPayload && !payload?.iss) {
    findings.push({
      severity: "low",
      title: "Missing iss",
      detail: "Issuer is not set.",
    });
    recommendations.push("Validate iss for multi-tenant systems.");
    score -= 2;
  }

  if (hasPayload && !payload?.aud) {
    findings.push({
      severity: "low",
      title: "Missing aud",
      detail: "Audience is not set.",
    });
    recommendations.push("Validate aud for API-specific tokens.");
    score -= 2;
  }

  if (hasPayload && !payload?.jti) {
    findings.push({
      severity: "low",
      title: "Missing jti",
      detail: "Replay protection may be limited.",
    });
    recommendations.push("Use jti and token revocation lists for high-risk sessions.");
    score -= 2;
  }

  if (token.length > 2000) {
    findings.push({
      severity: "low",
      title: "Large token",
      detail: "Token size may impact header limits.",
    });
    score -= 2;
  }

  if (score < 0) score = 0;
  const level = getScoreLevel(score);

  possibilities.push("Test for algorithm confusion or downgrade attacks.");
  possibilities.push("Check for token replay if jti is not enforced server-side.");
  possibilities.push("Attempt to bypass authorization with modified claims.");
  if (!payload?.exp) {
    possibilities.push("Review token revocation/denylist strategy for long-lived tokens.");
  }
  if (hasPayload && !payload?.jti) {
    possibilities.push("Test replay resistance if jti is not enforced.");
  }

  notes.push("JWT payloads are only base64url-encoded; treat them as plaintext.");
  notes.push("Signature validation must be enforced server-side regardless of client checks.");

  const analysis = {
    score,
    level,
    findings,
    recommendations: Array.from(new Set(recommendations)),
    possibilities: Array.from(new Set(possibilities)),
    notes,
    signatureStatus: signatureState.status,
    tokenLength: token.length,
    headerJson: header ? prettyJson(header) : "",
    payloadJson: payload ? prettyJson(payload) : "",
  };

  setStrength(score, level);
  renderInsights(findings);
  updateReport(analysis);
  return analysis;
}

async function hmacSign(alg, secret, input) {
  const map = {
    HS256: "SHA-256",
    HS384: "SHA-384",
    HS512: "SHA-512",
  };
  const hash = map[alg];
  if (!hash) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: { name: hash } },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(input));
  return bytesToBase64Url(new Uint8Array(signature));
}

function jsrsasignSign(alg, headerObj, payloadObj, key) {
  if (!hasJsrsasign()) {
    return { token: null, error: "Signature library not loaded." };
  }
  try {
    const token = KJUR.jws.JWS.sign(alg, JSON.stringify(headerObj), JSON.stringify(payloadObj), key);
    return { token, error: null };
  } catch (error) {
    return { token: null, error: error.message };
  }
}

function jsrsasignVerify(token, key, alg) {
  if (!hasJsrsasign()) {
    return { ok: false, error: "Signature library not loaded." };
  }
  try {
    if (typeof KJUR.jws.JWS.verify === "function") {
      return { ok: KJUR.jws.JWS.verify(token, key, alg), error: null };
    }
    if (typeof KJUR.jws.JWS.verifyJWT === "function") {
      return { ok: KJUR.jws.JWS.verifyJWT(token, key, { alg: [alg] }), error: null };
    }
    return { ok: false, error: "Verification not supported." };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function updateSignatureStatus(alg, secret, input, signature, token) {
  if (alg === "none") {
    setBadge(signatureBadge, "warn", "Signature: none");
    setSignatureState("none", "alg=none");
    return;
  }
  if (isHmacAlg(alg)) {
    if (!secret) {
      setBadge(signatureBadge, "warn", "Signature: add secret");
      setSignatureState("missing_key", "HMAC secret not provided");
      return;
    }
    const expected = await hmacSign(alg, secret, input);
    if (expected && signature && expected === signature) {
      setBadge(signatureBadge, "ok", "Signature: verified");
      setSignatureState("verified", "");
    } else {
      setBadge(signatureBadge, "error", "Signature: invalid");
      setSignatureState("invalid", "HMAC verification failed");
    }
    return;
  }
  if (alg && (isRsaAlg(alg) || isEcAlg(alg))) {
    const keyText = (verifyKey.value || signKey.value || "").trim();
    if (!keyText) {
      setBadge(signatureBadge, "warn", "Signature: add key");
      setSignatureState("missing_key", "Public key not provided");
      return;
    }
    const result = jsrsasignVerify(token, keyText, alg);
    if (result.ok) {
      setBadge(signatureBadge, "ok", "Signature: verified");
      setSignatureState("verified", "");
    } else {
      setBadge(signatureBadge, "error", "Signature: invalid");
      setSignatureState("invalid", result.error || "Signature verification failed");
      if (result.error) {
        setEditStatus("warn", `Signature check failed: ${result.error}`);
      }
    }
    return;
  }

  setBadge(signatureBadge, "warn", alg ? "Signature: external" : "Signature: unchecked");
  setSignatureState("unchecked", "Verification not supported");
}

function updateNow() {
  nowTime.textContent = new Date().toLocaleString();
}

async function updateDecoderFromToken() {
  if (suppressTokenInput) return;

  const token = tokenInput.value.trim();
  if (!token) {
    headerOutput.value = "";
    payloadOutput.value = "";
    resetClaims();
    resetMetadata();
    setBadge(structureBadge, "idle", "Structure: --");
    setBadge(signatureBadge, "idle", "Signature: --");
    setBadge(expiryBadge, "idle", "Expiry: --");
    analyzeToken(null, null, null);
    setEditStatus("idle", "");
    return;
  }

  const parts = token.split(".");
  if (parts.length === 5) {
    setBadge(structureBadge, "warn", "Structure: JWE");
    let headerRaw = "";
    try {
      headerRaw = base64UrlDecodeString(parts[0]);
    } catch (error) {
      headerOutput.value = "Failed to decode JWE header.";
      payloadOutput.value = error.message;
      resetClaims();
      resetMetadata();
      setBadge(signatureBadge, "warn", "Signature: JWE");
      setBadge(expiryBadge, "idle", "Expiry: --");
      setSignatureState("unchecked", "JWE not verified");
      analyzeToken(token, null, null, { partsCount: parts.length });
      setEditStatus("warn", "Encrypted token (JWE).");
      return;
    }

    const headerJson = safeJsonParse(headerRaw);
    headerOutput.value = headerJson.data
      ? prettyJson(headerJson.data)
      : `Invalid JSON: ${headerJson.error}\n\n${headerRaw}`;
    payloadOutput.value = "Encrypted payload (JWE). Decryption key required.";
    resetClaims();
    updateMetadata(token, headerJson.data, parts);
    setBadge(signatureBadge, "warn", "Signature: JWE");
    setBadge(expiryBadge, "idle", "Expiry: --");
    setSignatureState("unchecked", "JWE not verified");
    analyzeToken(token, headerJson.data, null, { partsCount: parts.length });
    setEditStatus("warn", "JWE detected. Claims are not available without decryption.");
    return;
  }
  if (parts.length !== 3) {
    headerOutput.value = "Invalid token structure.";
    payloadOutput.value = "JWTs must have 3 dot-separated parts.";
    resetClaims();
    resetMetadata();
    setBadge(structureBadge, "error", "Structure: invalid");
    setBadge(signatureBadge, "idle", "Signature: --");
    setBadge(expiryBadge, "idle", "Expiry: --");
    analyzeToken(null, null, null);
    setEditStatus("error", "Token must contain 3 dot-separated parts.");
    return;
  }

  setBadge(structureBadge, "ok", "Structure: ok");

  let headerRaw = "";
  let payloadRaw = "";
  try {
    headerRaw = base64UrlDecodeString(parts[0]);
    payloadRaw = base64UrlDecodeString(parts[1]);
  } catch (error) {
    headerOutput.value = "Failed to decode base64url.";
    payloadOutput.value = error.message;
    resetClaims();
    resetMetadata();
    setBadge(structureBadge, "error", "Structure: decode error");
    setBadge(signatureBadge, "idle", "Signature: --");
    setBadge(expiryBadge, "idle", "Expiry: --");
    analyzeToken(null, null, null);
    setEditStatus("error", "Base64url decode error.");
    return;
  }

  const headerJson = safeJsonParse(headerRaw);
  const payloadJson = safeJsonParse(payloadRaw);

  headerOutput.value = headerJson.data
    ? prettyJson(headerJson.data)
    : `Invalid JSON: ${headerJson.error}\n\n${headerRaw}`;

  payloadOutput.value = payloadJson.data
    ? prettyJson(payloadJson.data)
    : `Invalid JSON: ${payloadJson.error}\n\n${payloadRaw}`;

  updateClaims(payloadJson.data);
  updateMetadata(token, headerJson.data, parts);

  const alg = headerJson.data?.alg;
  const secret = verifySecret.value;
  await updateSignatureStatus(alg, secret, `${parts[0]}.${parts[1]}`, parts[2], token);
  analyzeToken(token, headerJson.data, payloadJson.data, { partsCount: parts.length });

  if (headerJson.data && payloadJson.data && lastSource !== "encoder") {
    headerInput.value = prettyJson(headerJson.data);
    payloadInput.value = prettyJson(payloadJson.data);
    if (headerJson.data.alg && algSelect.value !== headerJson.data.alg) {
      algSelect.value = headerJson.data.alg;
    }
  }

  if (!headerJson.data) {
    setEditStatus("warn", `Header JSON error: ${headerJson.error}`);
  } else if (!payloadJson.data) {
    setEditStatus("warn", `Payload JSON error: ${payloadJson.error}`);
  } else {
    setEditStatus("idle", "");
  }
}

async function updateFromDecodedEdits() {
  const headerText = headerOutput.value.trim();
  const payloadText = payloadOutput.value.trim();

  if (!headerText && !payloadText) {
    setEditStatus("idle", "");
    return;
  }

  const headerParsed = safeJsonParse(headerText);
  if (!headerParsed.data) {
    setBadge(structureBadge, "warn", "Structure: edit error");
    setEditStatus("error", `Header JSON error: ${headerParsed.error}`);
    return;
  }

  const payloadParsed = safeJsonParse(payloadText);
  if (!payloadParsed.data) {
    setBadge(structureBadge, "warn", "Structure: edit error");
    setEditStatus("error", `Payload JSON error: ${payloadParsed.error}`);
    return;
  }

  const header = { ...headerParsed.data };
  if (!header.alg) header.alg = algSelect.value || "HS256";
  if (!header.typ) header.typ = "JWT";

  const alg = header.alg;
  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payloadParsed.data));
  const input = `${headerB64}.${payloadB64}`;

  let token = "";
  if (alg === "none") {
    token = `${input}.`;
    setBadge(signatureBadge, "warn", "Signature: none");
    setEditStatus("warn", "Unsigned token (alg=none).");
  } else if (isHmacAlg(alg)) {
    const secret = verifySecret.value || signSecret.value;
    if (!secret) {
      setBadge(signatureBadge, "warn", "Signature: add secret");
      setEditStatus("warn", "Provide HMAC secret to sign HS* token.");
      return;
    }
    const signature = await hmacSign(alg, secret, input);
    if (!signature) {
      setBadge(signatureBadge, "error", "Signature: unsupported");
      setEditStatus("error", "Unsupported algorithm.");
      return;
    }
    token = `${input}.${signature}`;
    setBadge(signatureBadge, "ok", "Signature: signed");
    setEditStatus("ok", "Token updated from decoded edits.");
  } else if (isRsaAlg(alg) || isEcAlg(alg)) {
    const keyText = (signKey.value || "").trim();
    if (!keyText) {
      setBadge(signatureBadge, "warn", "Signature: add key");
      setEditStatus("warn", "Provide a private key to sign RS/ES/PS tokens.");
      return;
    }
    const result = jsrsasignSign(alg, header, payloadParsed.data, keyText);
    if (!result.token) {
      setBadge(signatureBadge, "error", "Signature: unsupported");
      setEditStatus("error", result.error || "Signing failed.");
      return;
    }
    token = result.token;
    setBadge(signatureBadge, "ok", "Signature: signed");
    setEditStatus("ok", "Token updated from decoded edits.");
  } else {
    setBadge(signatureBadge, "warn", "Signature: external");
    setEditStatus("warn", "Signing for this algorithm is not supported.");
    return;
  }

  suppressTokenInput = true;
  tokenInput.value = token;
  suppressTokenInput = false;

  setBadge(structureBadge, "ok", "Structure: ok");
  updateClaims(payloadParsed.data);
  updateMetadata(token, header, token.split("."));
  const parts = token.split(".");
  await updateSignatureStatus(alg, verifySecret.value, `${parts[0]}.${parts[1]}`, parts[2], token);
  analyzeToken(token, header, payloadParsed.data, { partsCount: parts.length });

  tokenOutput.value = token;
  headerInput.value = prettyJson(header);
  payloadInput.value = prettyJson(payloadParsed.data);
  if (algSelect.value !== alg) algSelect.value = alg;
}

function isJwtLike(value) {
  if (!value) return false;
  return value.split(".").length === 3;
}

function syncTokenFromEncoder(token) {
  if (!isJwtLike(token)) return;
  suppressTokenInput = true;
  tokenInput.value = token;
  suppressTokenInput = false;
  lastSource = "encoder";
  updateDecoderFromToken();
}

async function updateEncoder() {
  const currentVersion = (encodeVersion += 1);
  const alg = algSelect.value;
  const secret = signSecret.value;
  const keyText = signKey.value.trim();

  const headerParsed = safeJsonParse(headerInput.value.trim());
  const payloadParsed = safeJsonParse(payloadInput.value.trim());

  if (!headerParsed.data) {
    tokenOutput.value = `Header JSON error: ${headerParsed.error}`;
    return;
  }
  if (!payloadParsed.data) {
    tokenOutput.value = `Payload JSON error: ${payloadParsed.error}`;
    return;
  }

  const header = { ...headerParsed.data, alg };
  if (!header.typ) {
    header.typ = "JWT";
  }

  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payloadParsed.data));
  const input = `${headerB64}.${payloadB64}`;

  if (alg === "none") {
    tokenOutput.value = `${input}.`;
    syncTokenFromEncoder(tokenOutput.value);
    return;
  }

  if (isHmacAlg(alg)) {
    if (!secret) {
      tokenOutput.value = "HMAC secret is required for HS* algorithms.";
      return;
    }

    const signature = await hmacSign(alg, secret, input);
    if (currentVersion !== encodeVersion) return;

    if (!signature) {
      tokenOutput.value = "Unsupported algorithm.";
      return;
    }

    tokenOutput.value = `${input}.${signature}`;
    syncTokenFromEncoder(tokenOutput.value);
    return;
  }

  if (isRsaAlg(alg) || isEcAlg(alg)) {
    if (!keyText) {
      tokenOutput.value = "Private key is required for RS/ES/PS algorithms.";
      return;
    }
    const result = jsrsasignSign(alg, header, payloadParsed.data, keyText);
    if (currentVersion !== encodeVersion) return;
    if (!result.token) {
      tokenOutput.value = result.error || "Signing failed.";
      return;
    }
    tokenOutput.value = result.token;
    syncTokenFromEncoder(tokenOutput.value);
    return;
  }

  tokenOutput.value = "Unsupported algorithm.";
}

function formatJsonInput(el) {
  const parsed = safeJsonParse(el.value.trim());
  if (parsed.data) {
    el.value = prettyJson(parsed.data);
  }
}

async function copyText(value) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch (error) {
    // ignore clipboard errors
  }
}

function seedDefaults() {
  const now = Math.floor(Date.now() / 1000);
  headerInput.value = prettyJson({ typ: "JWT", alg: "HS256" });
  payloadInput.value = prettyJson({
    sub: "1234567890",
    name: "Ada Lovelace",
    iat: now,
    exp: now + 3600,
  });
}

const scheduleDecodedEdits = debounce(updateFromDecodedEdits, 180);

function wireEvents() {
  tokenInput.addEventListener("input", () => {
    if (suppressTokenInput) return;
    lastSource = "token";
    updateDecoderFromToken();
  });

  verifySecret.addEventListener("input", () => {
    if (lastSource === "decoded") {
      scheduleDecodedEdits();
    } else {
      updateDecoderFromToken();
    }
  });

  verifyKey.addEventListener("input", () => {
    if (lastSource === "decoded") {
      scheduleDecodedEdits();
    } else {
      updateDecoderFromToken();
    }
  });

  headerOutput.addEventListener("input", () => {
    lastSource = "decoded";
    scheduleDecodedEdits();
  });
  payloadOutput.addEventListener("input", () => {
    lastSource = "decoded";
    scheduleDecodedEdits();
  });

  algSelect.addEventListener("change", () => {
    if (lastSource === "decoded") {
      scheduleDecodedEdits();
      return;
    }
    lastSource = "encoder";
    updateEncoder();
  });

  signSecret.addEventListener("input", () => {
    if (lastSource === "decoded") {
      scheduleDecodedEdits();
      return;
    }
    lastSource = "encoder";
    updateEncoder();
  });
  signKey.addEventListener("input", () => {
    if (lastSource === "decoded") {
      scheduleDecodedEdits();
      return;
    }
    lastSource = "encoder";
    updateEncoder();
  });
  headerInput.addEventListener("input", () => {
    lastSource = "encoder";
    updateEncoder();
  });
  payloadInput.addEventListener("input", () => {
    lastSource = "encoder";
    updateEncoder();
  });

  copyHeader.addEventListener("click", () => copyText(headerOutput.value));
  copyPayload.addEventListener("click", () => copyText(payloadOutput.value));
  copyToken.addEventListener("click", () => copyText(tokenOutput.value));
  copyReport.addEventListener("click", () => copyText(reportOutput.value));

  formatHeader.addEventListener("click", () => formatJsonInput(headerInput));
  formatPayload.addEventListener("click", () => formatJsonInput(payloadInput));
}

seedDefaults();
wireEvents();
updateNow();
updateDecoderFromToken();
updateEncoder();
setInterval(updateNow, 1000);
