import type { Env } from "./types";

export type JsonValue = Record<string, unknown> | unknown[];

export type CorsResult = {
  headers: HeadersInit;
  allowed: boolean;
};

export function jsonResponse(
  data: JsonValue,
  init?: ResponseInit,
  extraHeaders?: HeadersInit
): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extraHeaders) {
    Object.entries(extraHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });
  }
  return new Response(JSON.stringify(data), { ...init, headers });
}

export async function parseJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

export function getCorsHeaders(request: Request, env: Env): CorsResult {
  const origin = request.headers.get("Origin") ?? "";
  const rawAllowed = env.ALLOWED_ORIGINS ?? "";
  const allowedOrigins = rawAllowed
    .split(/[,\s]+/)
    .map((value) => value.trim())
    .filter(Boolean);
  const allowedWildcards = allowedOrigins
    .filter((value) => value.startsWith("*."))
    .map((value) => value.slice(1));

  const baseHeaders: HeadersInit = {
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Max-Age": "86400"
  };

  if (allowedOrigins.length === 0) {
    return {
      headers: {
        ...baseHeaders,
        "Access-Control-Allow-Origin": origin || "*",
        Vary: "Origin"
      },
      allowed: true
    };
  }

  if (origin && allowedOrigins.includes(origin)) {
    return {
      headers: {
        ...baseHeaders,
        "Access-Control-Allow-Origin": origin,
        Vary: "Origin"
      },
      allowed: true
    };
  }

  if (origin && allowedWildcards.length > 0) {
    const originUrl = tryParseOrigin(origin);
    if (originUrl) {
      const hostname = originUrl.hostname;
      const matchedWildcard = allowedWildcards.find((wc) =>
        hostname === wc.slice(1) || hostname.endsWith(wc)
      );
      if (matchedWildcard) {
        return {
          headers: {
            ...baseHeaders,
            "Access-Control-Allow-Origin": origin,
            Vary: "Origin"
          },
          allowed: true
        };
      }
    }
  }

  if (!origin) {
    return {
      headers: {
        ...baseHeaders,
        "Access-Control-Allow-Origin": allowedOrigins[0],
        Vary: "Origin"
      },
      allowed: true
    };
  }

  return {
    headers: {
      ...baseHeaders,
      "Access-Control-Allow-Origin": "null",
      Vary: "Origin"
    },
    allowed: false
  };
}

export function normalizePath(rawPath: string): string | null {
  if (!rawPath) {
    return null;
  }
  const trimmed = rawPath.trim().replace(/^\/+|\/+$/g, "");
  if (!trimmed) {
    return null;
  }
  if (trimmed.includes("/")) {
    return null;
  }
  try {
    return decodeURIComponent(trimmed);
  } catch {
    return null;
  }
}

export function isValidPath(pathValue: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(pathValue);
}

export function isReservedPath(pathValue: string): boolean {
  const reserved = new Set([
    "manage",
    "admin",
    "api",
    "assets",
    "static",
    "favicon.ico",
    "robots.txt"
  ]);
  return reserved.has(pathValue.toLowerCase());
}

export function isValidUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
function tryParseOrigin(origin: string): URL | null {
  try {
    return new URL(origin);
  } catch {
    return null;
  }
}
