export interface Env {
  DB: D1Database;
  AUTH_SECRET: string;
  ADMIN_PASSWORD_HASH?: string;
  ALLOWED_ORIGINS?: string;
}

export type UserRole = "admin" | "user";

export type PermissionKey = "login" | "create" | "verify" | "profile";

export interface TokenPayload {
  sub: string;
  role: UserRole;
  userId?: number;
  username?: string;
  exp: number;
}

export type LinkVisibility = "moderator" | "verified" | "unknown";

export interface LinkRow {
  id: number;
  path: string;
  url: string;
  password_hash: string | null;
  owner_user_id: number | null;
  created_by_admin: number;
  self_verified: number;
  moderator_verified: number;
  created_at: string;
  updated_at: string;
}

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  avatar_url: string;
  can_login: number;
  can_create: number;
  can_verify: number;
  can_profile: number;
  login_note: string | null;
  create_note: string | null;
  verify_note: string | null;
  profile_note: string | null;
  created_at: string;
  updated_at: string;
}

export interface PermissionNotificationRow {
  id: number;
  user_id: number;
  permission_key: PermissionKey;
  permission_label: string;
  granted: number;
  note: string | null;
  acknowledged_at: string | null;
  created_at: string;
  updated_at: string;
}
