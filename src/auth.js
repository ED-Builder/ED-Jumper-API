const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64Url(data) {
  let binary = "";
  data.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toBase64Url(new Uint8Array(signature));
}

async function verifySignature(value, signature, secret) {
  const expected = await sign(value, secret);
  return expected.length === signature.length && expected === signature;
}

export async function createToken(secret, ttlSeconds, payloadInput) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = { ...payloadInput, exp };
  const payloadEncoded = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const signature = await sign(payloadEncoded, secret);
  return { token: `v1.${payloadEncoded}.${signature}`, exp };
}

export async function verifyToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") {
    return null;
  }
  const [, payloadEncoded, signature] = parts;
  const isValid = await verifySignature(payloadEncoded, signature, secret);
  if (!isValid) {
    return null;
  }
  const payloadBytes = fromBase64Url(payloadEncoded);
  const payloadText = decoder.decode(payloadBytes);
  const payload = JSON.parse(payloadText);
  if (!payload || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }
  return payload;
}
