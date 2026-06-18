import type {
  Env,
  LinkRow,
  PermissionKey,
  PermissionNotificationRow,
  UserRow
} from "./types";

export type PermissionState = {
  can_login: number;
  can_create: number;
  can_verify: number;
  can_profile: number;
};

export type PermissionUpdate = Partial<
  Record<"can_login" | "can_create" | "can_verify" | "can_profile", boolean>
>;

export type LinkVisibility = "moderator" | "verified" | "unknown";

export function getPermissionLabel(permissionKey: PermissionKey): string {
  switch (permissionKey) {
    case "login":
      return "登录鉴权";
    case "create":
      return "创建分发";
    case "verify":
      return "验证分发";
    case "profile":
      return "更改个人信息";
  }
}

export function normalizePermissionState(state: PermissionState): PermissionState {
  const next = { ...state };
  if (next.can_login === 0) {
    next.can_create = 0;
    next.can_verify = 0;
    next.can_profile = 0;
  }
  if (next.can_create === 0) {
    next.can_verify = 0;
  }
  return next;
}

export async function getAdminPasswordHash(env: Env): Promise<string | null> {
  if (env.ADMIN_PASSWORD_HASH) {
    return env.ADMIN_PASSWORD_HASH;
  }
  const result = await env.DB.prepare("SELECT value FROM settings WHERE key = ? LIMIT 1")
    .bind("admin_password_hash")
    .first<{ value: string }>();
  return result?.value ?? null;
}

export async function getUserById(env: Env, id: number): Promise<UserRow | null> {
  const result = await env.DB.prepare(
    "SELECT id, username, password_hash, avatar_url, can_login, can_create, can_verify, can_profile, login_note, create_note, verify_note, profile_note, created_at, updated_at FROM users WHERE id = ? LIMIT 1"
  )
    .bind(id)
    .first<UserRow>();
  return result ?? null;
}

export async function getUserByUsername(env: Env, username: string): Promise<UserRow | null> {
  const result = await env.DB.prepare(
    "SELECT id, username, password_hash, avatar_url, can_login, can_create, can_verify, can_profile, login_note, create_note, verify_note, profile_note, created_at, updated_at FROM users WHERE username = ? LIMIT 1"
  )
    .bind(username)
    .first<UserRow>();
  return result ?? null;
}

export async function listUsers(env: Env): Promise<UserRow[]> {
  const result = await env.DB.prepare(
    "SELECT id, username, password_hash, avatar_url, can_login, can_create, can_verify, can_profile, login_note, create_note, verify_note, profile_note, created_at, updated_at FROM users ORDER BY id DESC"
  ).all<UserRow>();
  return result.results ?? [];
}

export async function createUser(env: Env, input: { username: string; avatarUrl: string; passwordHash: string }): Promise<number> {
  const result = await env.DB.prepare(
    "INSERT INTO users (username, avatar_url, password_hash, can_login, can_create, can_verify, can_profile, login_note, create_note, verify_note, profile_note) VALUES (?, ?, ?, 1, 1, 1, 1, ?, ?, ?, ?)"
  )
    .bind(input.username, input.avatarUrl, input.passwordHash, "初始默认授予", "初始默认授予", "初始默认授予", "初始默认授予")
    .run();
 return result.meta.last_row_id as number;
}

export async function updateUserProfile(
  env: Env,
  id: number,
  updates: { username?: string; avatar_url?: string; password_hash?: string }
): Promise<void> {
  const fields: string[] = [];
  const params: (string | number)[] = [];

  if (updates.username !== undefined) {
    fields.push("username = ?");
    params.push(updates.username);
  }
  if (updates.avatar_url !== undefined) {
    fields.push("avatar_url = ?");
    params.push(updates.avatar_url);
  }
  if (updates.password_hash !== undefined) {
    fields.push("password_hash = ?");
    params.push(updates.password_hash);
  }
  if (fields.length === 0) {
    return;
  }
  fields.push("updated_at = CURRENT_TIMESTAMP");
  params.push(id);
  await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...params).run();
}

export async function updateUserPermissions(
  env: Env,
  id: number,
  updates: {
    can_login?: boolean;
    can_create?: boolean;
    can_verify?: boolean;
    can_profile?: boolean;
    login_note?: string | null;
    create_note?: string | null;
    verify_note?: string | null;
    profile_note?: string | null;
  }
): Promise<void> {
  const fields: string[] = [];
  const params: (string | number | null)[] = [];

  if (updates.can_login !== undefined) {
    fields.push("can_login = ?");
    params.push(updates.can_login ? 1 : 0);
  }
  if (updates.can_create !== undefined) {
    fields.push("can_create = ?");
    params.push(updates.can_create ? 1 : 0);
  }
  if (updates.can_verify !== undefined) {
    fields.push("can_verify = ?");
    params.push(updates.can_verify ? 1 : 0);
  }
  if (updates.can_profile !== undefined) {
    fields.push("can_profile = ?");
    params.push(updates.can_profile ? 1 : 0);
  }
  if (updates.login_note !== undefined) {
    fields.push("login_note = ?");
    params.push(updates.login_note);
  }
  if (updates.create_note !== undefined) {
    fields.push("create_note = ?");
    params.push(updates.create_note);
  }
  if (updates.verify_note !== undefined) {
    fields.push("verify_note = ?");
    params.push(updates.verify_note);
  }
  if (updates.profile_note !== undefined) {
    fields.push("profile_note = ?");
    params.push(updates.profile_note);
  }
  if (fields.length === 0) {
    return;
  }
  fields.push("updated_at = CURRENT_TIMESTAMP");
  params.push(id);
  await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...params).run();
}

export async function listPermissionNotifications(
  env: Env,
  userId: number
): Promise<PermissionNotificationRow[]> {
  const result = await env.DB.prepare(
    "SELECT id, user_id, permission_key, permission_label, granted, note, acknowledged_at, created_at, updated_at FROM permission_notifications WHERE user_id = ? ORDER BY id DESC"
  )
    .bind(userId)
    .all<PermissionNotificationRow>();
  return result.results ?? [];
}

export async function listPendingPermissionNotifications(
  env: Env,
  userId: number
): Promise<PermissionNotificationRow[]> {
  const result = await env.DB.prepare(
    "SELECT id, user_id, permission_key, permission_label, granted, note, acknowledged_at, created_at, updated_at FROM permission_notifications WHERE user_id = ? AND acknowledged_at IS NULL ORDER BY id ASC"
  )
    .bind(userId)
    .all<PermissionNotificationRow>();
  return result.results ?? [];
}

export async function acknowledgePermissionNotification(env: Env, id: number, userId: number): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE permission_notifications SET acknowledged_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND acknowledged_at IS NULL"
  )
    .bind(id, userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function insertPermissionNotification(
  env: Env,
  input: {
    userId: number;
    permissionKey: PermissionKey;
    granted: boolean;
    note?: string | null;
  }
): Promise<number> {
  const label = getPermissionLabel(input.permissionKey);
  const result = await env.DB.prepare(
    "INSERT INTO permission_notifications (user_id, permission_key, permission_label, granted, note) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(input.userId, input.permissionKey, label, input.granted ? 1 : 0, input.note ?? null)
    .run();
  return result.meta.last_row_id as number;
}

export async function getLinkByPath(env: Env, pathValue: string): Promise<LinkRow | null> {
  const result = await env.DB.prepare(
    "SELECT id, path, url, password_hash, owner_user_id, created_by_admin, self_verified, moderator_verified, created_at, updated_at FROM links WHERE path = ? LIMIT 1"
  )
    .bind(pathValue)
    .first<LinkRow>();
  return result ?? null;
}

export async function getLinkById(env: Env, id: number): Promise<LinkRow | null> {
  const result = await env.DB.prepare(
    "SELECT id, path, url, password_hash, owner_user_id, created_by_admin, self_verified, moderator_verified, created_at, updated_at FROM links WHERE id = ? LIMIT 1"
  )
    .bind(id)
    .first<LinkRow>();
  return result ?? null;
}

export async function getLinkIdByPath(env: Env, pathValue: string): Promise<number | null> {
  const result = await env.DB.prepare("SELECT id FROM links WHERE path = ? LIMIT 1")
    .bind(pathValue)
    .first<{ id: number }>();
  return result?.id ?? null;
}

export async function listLinks(env: Env): Promise<LinkRow[]> {
  const result = await env.DB.prepare(
    "SELECT id, path, url, password_hash, owner_user_id, created_by_admin, self_verified, moderator_verified, created_at, updated_at FROM links ORDER BY id DESC"
  ).all<LinkRow>();
  return result.results ?? [];
}

export async function listLinksByUser(env: Env, userId: number): Promise<LinkRow[]> {
  const result = await env.DB.prepare(
    "SELECT id, path, url, password_hash, owner_user_id, created_by_admin, self_verified, moderator_verified, created_at, updated_at FROM links WHERE owner_user_id = ? ORDER BY id DESC"
  )
    .bind(userId)
    .all<LinkRow>();
  return result.results ?? [];
}

export async function createLink(
  env: Env,
  input: {
    path: string;
    url: string;
    passwordHash: string | null;
    ownerUserId: number | null;
    createdByAdmin: boolean;
    selfVerified: boolean;
    moderatorVerified: boolean;
  }
): Promise<number> {
  const result = await env.DB.prepare(
    "INSERT INTO links (path, url, password_hash, owner_user_id, created_by_admin, self_verified, moderator_verified) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      input.path,
      input.url,
      input.passwordHash,
      input.ownerUserId,
      input.createdByAdmin ? 1 : 0,
      input.selfVerified ? 1 : 0,
      input.moderatorVerified ? 1 : 0
    )
    .run();
  return result.meta.last_row_id as number;
}

export async function updateLink(
  env: Env,
  id: number,
  updates: {
    path?: string;
    url?: string;
    password_hash?: string | null;
    owner_user_id?: number | null;
    created_by_admin?: boolean;
    self_verified?: boolean;
    moderator_verified?: boolean;
  }
): Promise<void> {
  const fields: string[] = [];
  const params: (string | number | null)[] = [];

  if (updates.path !== undefined) {
    fields.push("path = ?");
    params.push(updates.path);
  }
  if (updates.url !== undefined) {
    fields.push("url = ?");
    params.push(updates.url);
  }
  if (updates.password_hash !== undefined) {
    fields.push("password_hash = ?");
    params.push(updates.password_hash);
  }
  if (updates.owner_user_id !== undefined) {
    fields.push("owner_user_id = ?");
    params.push(updates.owner_user_id);
  }
  if (updates.created_by_admin !== undefined) {
    fields.push("created_by_admin = ?");
    params.push(updates.created_by_admin ? 1 : 0);
  }
  if (updates.self_verified !== undefined) {
    fields.push("self_verified = ?");
    params.push(updates.self_verified ? 1 : 0);
  }
  if (updates.moderator_verified !== undefined) {
    fields.push("moderator_verified = ?");
    params.push(updates.moderator_verified ? 1 : 0);
  }
  if (fields.length === 0) {
    return;
  }
  fields.push("updated_at = CURRENT_TIMESTAMP");
  params.push(id);
  await env.DB.prepare(`UPDATE links SET ${fields.join(", ")} WHERE id = ?`).bind(...params).run();
}

export async function deleteLink(env: Env, id: number): Promise<void> {
  await env.DB.prepare("DELETE FROM links WHERE id = ?").bind(id).run();
}
