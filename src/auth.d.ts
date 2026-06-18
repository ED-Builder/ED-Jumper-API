import type { TokenPayload, UserRole } from "./types";

export function createToken(
  secret: string,
  ttlSeconds: number,
  payloadInput: { sub: string; role: UserRole; userId?: number; username?: string }
): Promise<{ token: string; exp: number }>;

export function verifyToken(token: string, secret: string): Promise<TokenPayload | null>;
