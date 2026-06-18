import { createToken, verifyToken } from "./auth.js";
import {
  acknowledgePermissionNotification,
  createLink,
  createUser,
  deleteLink,
  getAdminPasswordHash,
  getLinkById,
  getLinkByPath,
  getLinkIdByPath,
  getPermissionLabel,
  getUserById,
  getUserByUsername,
  insertPermissionNotification,
  listLinks,
  listLinksByUser,
  listPendingPermissionNotifications,
  listUsers,
  normalizePermissionState,
  updateLink,
  updateUserPermissions,
  updateUserProfile
} from "./db";
import type { Env, LinkRow, LinkVisibility, PermissionKey, TokenPayload, UserRow } from "./types";
import {
  getCorsHeaders,
  isReservedPath,
  isValidPath,
  isValidUrl,
  jsonResponse,
  normalizePath,
  parseJson,
  timingSafeEqual
} from "./utils";

const TOKEN_TTL_SECONDS = 15 * 60;

type CheckBody = {
  path?: string;
  password?: string;
};

type AdminLoginBody = {
  passwordHash?: string;
};

type UserAuthBody = {
  username?: string;
  passwordHash?: string;
};

type UserRegisterBody = {
  username?: string;
  passwordHash?: string;
  avatarUrl?: string;
};

type LinkBody = {
  path?: string;
  url?: string;
  password?: string;
  selfVerified?: boolean;
  moderatorVerified?: boolean;
};

type ProfileBody = {
  username?: string;
  avatarUrl?: string;
  passwordHash?: string;
};

type PermissionBody = {
  canLogin?: boolean;
  canCreate?: boolean;
  canVerify?: boolean;
  canProfile?: boolean;
  note?: string;
};

type UserSession = {
  role: "user";
  user: UserRow;
  payload: TokenPayload;
};

type AdminSession = {
  role: "admin";
  payload: TokenPayload;
};

type Session = UserSession | AdminSession;

const PERMISSION_ORDER: Array<{ key: PermissionKey; field: keyof UserRow; label: string }> = [
  { key: "login", field: "can_login", label: "登录鉴权" },
  { key: "create", field: "can_create", label: "创建分发" },
  { key: "verify", field: "can_verify", label: "验证分发" },
  { key: "profile", field: "can_profile", label: "更改个人信息" }
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { headers: corsHeaders, allowed } = getCorsHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!allowed) {
      return jsonResponse({ success: false, reason: "CORS Forbidden" }, { status: 403, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/g, "") || "/";

    if (pathname === "/check" && request.method === "POST") {
      return handleCheck(request, env, corsHeaders);
    }

    if (pathname === "/admin/login" && request.method === "POST") {
      return handleAdminLogin(request, env, corsHeaders);
    }

    if (pathname === "/auth/register" && request.method === "POST") {
      return handleRegister(request, env, corsHeaders);
    }

    if (pathname === "/auth/login" && request.method === "POST") {
      return handleUserLogin(request, env, corsHeaders);
    }

    if (pathname === "/me" && request.method === "GET") {
      const session = await requireSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      return handleMe(activeSession, env, corsHeaders);
    }

    if (pathname.startsWith("/me/notifications/")) {
      const session = await requireSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const match = pathname.match(/^\/me\/notifications\/(\d+)\/ack$/);
      if (match && request.method === "POST") {
        const activeSession = session.session;
        if (!activeSession) {
          return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
        }
        return handleAcknowledgeNotification(activeSession, env, Number(match[1]), corsHeaders);
      }
    }

    if (pathname === "/me/profile" && request.method === "PUT") {
      const session = await requireSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      return handleUpdateProfile(activeSession, request, env, corsHeaders);
    }

    if (pathname === "/user/links" || pathname.startsWith("/user/links/")) {
      const session = await requireUserSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      if (pathname === "/user/links" && request.method === "GET") {
        return handleListUserLinks(activeSession, env, corsHeaders);
      }
      if (pathname === "/user/links" && request.method === "POST") {
        return handleCreateUserLink(activeSession, request, env, corsHeaders);
      }
      const match = pathname.match(/^\/user\/links\/(\d+)$/);
      if (match) {
        const id = Number(match[1]);
        if (request.method === "PUT") {
          return handleUpdateUserLink(activeSession, request, env, id, corsHeaders);
        }
        if (request.method === "DELETE") {
          return handleDeleteUserLink(activeSession, env, id, corsHeaders);
        }
      }
    }

    if (pathname === "/admin/users" && request.method === "GET") {
      const session = await requireAdminSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      return handleListUsers(env, corsHeaders);
    }

    if (pathname.startsWith("/admin/users/")) {
      const session = await requireAdminSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      const linksMatch = pathname.match(/^\/admin\/users\/(\d+)\/links$/);
      if (linksMatch && request.method === "GET") {
        return handleListUserLinksAdmin(env, Number(linksMatch[1]), corsHeaders);
      }
      const match = pathname.match(/^\/admin\/users\/(\d+)$/);
      if (match && request.method === "PUT") {
        return handleUpdateUser(activeSession, request, env, Number(match[1]), corsHeaders);
      }
    }

    if (pathname === "/admin/links" && request.method === "GET") {
      const session = await requireAdminSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      return handleListLinksAdmin(env, corsHeaders);
    }

    if (pathname === "/admin/links" && request.method === "POST") {
      const session = await requireAdminSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      return handleCreateAdminLink(request, env, corsHeaders);
    }

    if (pathname.startsWith("/admin/links/")) {
      const session = await requireAdminSession(request, env);
      if (!session.ok) {
        return jsonResponse({ success: false, reason: session.reason }, { status: session.status, headers: corsHeaders });
      }
      const activeSession = session.session;
      if (!activeSession) {
        return jsonResponse({ success: false, reason: "Invalid token" }, { status: 401, headers: corsHeaders });
      }
      const match = pathname.match(/^\/admin\/links\/(\d+)$/);
      if (match) {
        const id = Number(match[1]);
        if (request.method === "PUT") {
          return handleAdminUpdateLink(request, env, id, corsHeaders);
        }
        if (request.method === "DELETE") {
          return handleDeleteAnyLink(env, id, corsHeaders);
        }
      }
    }

    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
};

function buildSessionTokenPayload(payload: TokenPayload): Session {
  if (payload.role === "admin") {
    return { role: "admin", payload };
  }
  throw new Error("Unexpected payload role");
}

async function requireSession(request: Request, env: Env): Promise<{ ok: boolean; status: number; reason: string; session?: Session }> {
  const payload = await verifyRequestToken(request, env);
  if (!payload) {
    return { ok: false, status: 401, reason: "Invalid token" };
  }
  if (payload.role === "admin") {
    return { ok: true, status: 200, reason: "", session: { role: "admin", payload } };
  }
  if (!payload.userId) {
    return { ok: false, status: 401, reason: "Invalid token" };
  }
  const user = await getUserById(env, payload.userId);
  if (!user) {
    return { ok: false, status: 401, reason: "User not found" };
  }
  return { ok: true, status: 200, reason: "", session: { role: "user", payload, user } };
}

async function requireUserSession(request: Request, env: Env): Promise<{ ok: boolean; status: number; reason: string; session?: UserSession }> {
  const session = await requireSession(request, env);
  if (!session.ok || session.session?.role !== "user") {
    return { ok: false, status: session.status, reason: session.reason || "Forbidden" };
  }
  return { ok: true, status: 200, reason: "", session: session.session };
}

async function requireAdminSession(request: Request, env: Env): Promise<{ ok: boolean; status: number; reason: string; session?: AdminSession }> {
  const session = await requireSession(request, env);
  if (!session.ok || session.session?.role !== "admin") {
    return { ok: false, status: 401, reason: "Admin only" };
  }
  return { ok: true, status: 200, reason: "", session: session.session };
}

async function verifyRequestToken(request: Request, env: Env): Promise<TokenPayload | null> {
  if (!env.AUTH_SECRET) {
    return null;
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.slice("Bearer ".length);
  return await verifyToken(token, env.AUTH_SECRET);
}

function getLinkVisibility(link: LinkRow): LinkVisibility {
  if (link.created_by_admin) {
    return "moderator";
  }
  if (link.moderator_verified) {
    return "moderator";
  }
  if (link.self_verified) {
    return "verified";
  }
  return "unknown";
}

function mapLinkResponse(link: LinkRow, owner?: UserRow | null) {
  const visibility = getLinkVisibility(link);
  const ownerSummary = !link.created_by_admin && owner
    ? {
        id: owner.id,
        username: owner.username,
        avatarUrl: owner.avatar_url
      }
    : null;

  return {
    id: link.id,
    path: link.path,
    url: link.url,
    hasPassword: Boolean(link.password_hash),
    ownerUserId: link.owner_user_id,
    createdByAdmin: Boolean(link.created_by_admin),
    selfVerified: Boolean(link.self_verified),
    moderatorVerified: Boolean(link.moderator_verified),
    visibility,
    owner: ownerSummary,
    createdAt: link.created_at,
    updatedAt: link.updated_at
  };
}

function getPermissionStateFromUser(user: UserRow) {
  return {
    canLogin: Boolean(user.can_login),
    canCreate: Boolean(user.can_create),
    canVerify: Boolean(user.can_verify),
    canProfile: Boolean(user.can_profile)
  };
}

function buildPermissionResponse(user: UserRow) {
  return {
    login: {
      enabled: Boolean(user.can_login),
      note: user.login_note
    },
    create: {
      enabled: Boolean(user.can_create),
      note: user.create_note
    },
    verify: {
      enabled: Boolean(user.can_verify),
      note: user.verify_note
    },
    profile: {
      enabled: Boolean(user.can_profile),
      note: user.profile_note
    }
  };
}

function permissionDeniedResponse(
  permissionKey: PermissionKey,
  user: UserRow,
  note: string | null,
  eventId: number | null,
  corsHeaders: HeadersInit
): Response {
  const label = getPermissionLabel(permissionKey);
  return jsonResponse(
    {
      success: false,
      reason: "Permission Denied",
      permissionKey,
      permissionLabel: label,
      note,
      eventId,
      userId: user.id
    },
    { status: 403, headers: corsHeaders }
  );
}

async function findLatestPendingEventId(env: Env, userId: number, permissionKey: PermissionKey, granted: boolean): Promise<number | null> {
  const result = await env.DB.prepare(
    "SELECT id FROM permission_notifications WHERE user_id = ? AND permission_key = ? AND granted = ? AND acknowledged_at IS NULL ORDER BY id DESC LIMIT 1"
  )
    .bind(userId, permissionKey, granted ? 1 : 0)
    .first<{ id: number }>();
  return result?.id ?? null;
}

async function assertPermission(
  env: Env,
  user: UserRow,
  permissionKey: PermissionKey,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const state = {
    login: user.can_login,
    create: user.can_create,
    verify: user.can_verify,
    profile: user.can_profile
  };
  const enabled = Boolean(state[permissionKey]);
  if (enabled) {
    return null;
  }
  const note =
    permissionKey === "login"
      ? user.login_note
      : permissionKey === "create"
        ? user.create_note
        : permissionKey === "verify"
          ? user.verify_note
          : user.profile_note;
  const eventId = await findLatestPendingEventId(env, user.id, permissionKey, false);
  return permissionDeniedResponse(permissionKey, user, note, eventId, corsHeaders);
}

async function handleCheck(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  let body: CheckBody;
  try {
    body = await parseJson<CheckBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const rawPath = typeof body.path === "string" ? body.path : "";
  const normalizedPath = normalizePath(rawPath);
  if (!normalizedPath || !isValidPath(normalizedPath)) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 200, headers: corsHeaders });
  }

  const link = await getLinkByPath(env, normalizedPath);
  if (!link) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 200, headers: corsHeaders });
  }

  const owner = link.owner_user_id ? await getUserById(env, link.owner_user_id) : null;
  const visibility = getLinkVisibility(link);
  const password = typeof body.password === "string" ? body.password : "";
  const requiresPassword = Boolean(link.password_hash);

  if (requiresPassword && link.password_hash && !timingSafeEqual(link.password_hash, password)) {
    return jsonResponse(
      {
        success: false,
        reason: "Invalid Password",
        requiresPassword,
        visibility,
        link: mapLinkResponse(link, owner),
        owner: !link.created_by_admin && owner
          ? { id: owner.id, username: owner.username, avatarUrl: owner.avatar_url }
          : null
      },
      { status: 200, headers: corsHeaders }
    );
  }

  return jsonResponse(
    {
      success: true,
      url: link.url,
      requiresPassword,
      visibility,
      link: mapLinkResponse(link, owner),
      owner: !link.created_by_admin && owner
        ? { id: owner.id, username: owner.username, avatarUrl: owner.avatar_url }
        : null
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleAdminLogin(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  if (!env.AUTH_SECRET) {
    return jsonResponse({ success: false, reason: "AUTH_SECRET not configured" }, { status: 500, headers: corsHeaders });
  }

  let body: AdminLoginBody;
  try {
    body = await parseJson<AdminLoginBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const passwordHash = typeof body.passwordHash === "string" ? body.passwordHash.trim() : "";
  if (!passwordHash) {
    return jsonResponse({ success: false, reason: "Missing passwordHash" }, { status: 400, headers: corsHeaders });
  }

  const storedHash = await getAdminPasswordHash(env);
  if (!storedHash || !timingSafeEqual(storedHash, passwordHash)) {
    return jsonResponse({ success: false, reason: "Invalid Password" }, { status: 401, headers: corsHeaders });
  }

  const { token, exp } = await createToken(env.AUTH_SECRET, TOKEN_TTL_SECONDS, { sub: "admin", role: "admin" });
  return jsonResponse({ success: true, token, expiresAt: exp, role: "admin" }, { status: 200, headers: corsHeaders });
}

async function handleRegister(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  if (!env.AUTH_SECRET) {
    return jsonResponse({ success: false, reason: "AUTH_SECRET not configured" }, { status: 500, headers: corsHeaders });
  }

  let body: UserRegisterBody;
  try {
    body = await parseJson<UserRegisterBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const username = typeof body.username === "string" ? body.username.trim() : "";
  const avatarUrl = typeof body.avatarUrl === "string" ? body.avatarUrl.trim() : "";
  const passwordHash = typeof body.passwordHash === "string" ? body.passwordHash.trim() : "";
  if (!username || !avatarUrl || !passwordHash) {
    return jsonResponse({ success: false, reason: "Missing fields" }, { status: 400, headers: corsHeaders });
  }
  if (username.length < 2 || username.length > 32) {
    return jsonResponse({ success: false, reason: "Invalid Username" }, { status: 400, headers: corsHeaders });
  }
  if (await getUserByUsername(env, username)) {
    return jsonResponse({ success: false, reason: "Username Already Exists" }, { status: 409, headers: corsHeaders });
  }
  if (!isValidUrl(avatarUrl)) {
    return jsonResponse({ success: false, reason: "Invalid Avatar URL" }, { status: 400, headers: corsHeaders });
  }

  const userId = await createUser(env, { username, avatarUrl, passwordHash });
  const user = await getUserById(env, userId);
  if (!user) {
    return jsonResponse({ success: false, reason: "Create user failed" }, { status: 500, headers: corsHeaders });
  }

  const { token, exp } = await createToken(env.AUTH_SECRET, TOKEN_TTL_SECONDS, {
    sub: username,
    role: "user",
    userId: user.id,
    username: user.username
  });
  return jsonResponse(
    {
      success: true,
      token,
      expiresAt: exp,
      role: "user",
      user: {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url
      }
    },
    { status: 201, headers: corsHeaders }
  );
}

async function handleUserLogin(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  if (!env.AUTH_SECRET) {
    return jsonResponse({ success: false, reason: "AUTH_SECRET not configured" }, { status: 500, headers: corsHeaders });
  }

  let body: UserAuthBody;
  try {
    body = await parseJson<UserAuthBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const username = typeof body.username === "string" ? body.username.trim() : "";
  const passwordHash = typeof body.passwordHash === "string" ? body.passwordHash.trim() : "";
  if (!username || !passwordHash) {
    return jsonResponse({ success: false, reason: "Missing fields" }, { status: 400, headers: corsHeaders });
  }

  const user = await getUserByUsername(env, username);
  if (!user || !timingSafeEqual(user.password_hash, passwordHash)) {
    return jsonResponse({ success: false, reason: "Invalid Credentials" }, { status: 401, headers: corsHeaders });
  }
  if (!user.can_login) {
    return permissionDeniedResponse("login", user, user.login_note, await findLatestPendingEventId(env, user.id, "login", false), corsHeaders);
  }

  const { token, exp } = await createToken(env.AUTH_SECRET, TOKEN_TTL_SECONDS, {
    sub: user.username,
    role: "user",
    userId: user.id,
    username: user.username
  });
  return jsonResponse(
    {
      success: true,
      token,
      expiresAt: exp,
      role: "user",
      user: {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url
      }
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleMe(session: Session, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  if (session.role === "admin") {
    return jsonResponse(
      {
        success: true,
        kind: "admin",
        permissions: {
          login: { enabled: true, note: null },
          create: { enabled: true, note: null },
          verify: { enabled: true, note: null },
          profile: { enabled: true, note: null }
        },
        pendingNotifications: []
      },
      { status: 200, headers: corsHeaders }
    );
  }

  const user = session.user;
  const pendingNotifications = await listPendingPermissionNotifications(env, user.id);
  const links = await listLinksByUser(env, user.id);
  return jsonResponse(
    {
      success: true,
      kind: "user",
      user: {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url
      },
      permissions: buildPermissionResponse(user),
      pendingNotifications,
      ownedLinks: await Promise.all(links.map(async (link) => mapLinkResponse(link, user)))
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleAcknowledgeNotification(
  session: Session,
  env: Env,
  id: number,
  corsHeaders: HeadersInit
): Promise<Response> {
  if (session.role !== "user") {
    return jsonResponse({ success: false, reason: "Forbidden" }, { status: 401, headers: corsHeaders });
  }
  const acknowledged = await acknowledgePermissionNotification(env, id, session.user.id);
  if (!acknowledged) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
  return jsonResponse({ success: true }, { status: 200, headers: corsHeaders });
}

async function handleUpdateProfile(
  session: Session,
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response> {
  if (session.role !== "user") {
    return jsonResponse({ success: false, reason: "Forbidden" }, { status: 401, headers: corsHeaders });
  }
  const denied = await assertPermission(env, session.user, "profile", corsHeaders);
  if (denied) {
    return denied;
  }

  let body: ProfileBody;
  try {
    body = await parseJson<ProfileBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const updates: { username?: string; avatar_url?: string; password_hash?: string } = {};
  if (body.username !== undefined) {
    const username = typeof body.username === "string" ? body.username.trim() : "";
    if (!username || username.length < 2 || username.length > 32) {
      return jsonResponse({ success: false, reason: "Invalid Username" }, { status: 400, headers: corsHeaders });
    }
    const existing = await getUserByUsername(env, username);
    if (existing && existing.id !== session.user.id) {
      return jsonResponse({ success: false, reason: "Username Already Exists" }, { status: 409, headers: corsHeaders });
    }
    updates.username = username;
  }
  if (body.avatarUrl !== undefined) {
    const avatarUrl = typeof body.avatarUrl === "string" ? body.avatarUrl.trim() : "";
    if (!avatarUrl || !isValidUrl(avatarUrl)) {
      return jsonResponse({ success: false, reason: "Invalid Avatar URL" }, { status: 400, headers: corsHeaders });
    }
    updates.avatar_url = avatarUrl;
  }
  if (body.passwordHash !== undefined) {
    const passwordHash = typeof body.passwordHash === "string" ? body.passwordHash.trim() : "";
    if (!passwordHash) {
      return jsonResponse({ success: false, reason: "Invalid Password" }, { status: 400, headers: corsHeaders });
    }
    updates.password_hash = passwordHash;
  }
  if (Object.keys(updates).length === 0) {
    return jsonResponse({ success: false, reason: "No updates provided" }, { status: 400, headers: corsHeaders });
  }

  await updateUserProfile(env, session.user.id, updates);
  const user = await getUserById(env, session.user.id);
  return jsonResponse({ success: true, user }, { status: 200, headers: corsHeaders });
}

async function handleListUsers(env: Env, corsHeaders: HeadersInit): Promise<Response> {
  const users = await listUsers(env);
  const result = await Promise.all(
    users.map(async (user) => {
      const links = await listLinksByUser(env, user.id);
      return {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url,
        permissions: buildPermissionResponse(user),
        linkCount: links.length,
        createdAt: user.created_at,
        updatedAt: user.updated_at
      };
    })
  );
  return jsonResponse({ success: true, users: result }, { status: 200, headers: corsHeaders });
}

async function handleUpdateUser(
  session: AdminSession,
  request: Request,
  env: Env,
  userId: number,
  corsHeaders: HeadersInit
): Promise<Response> {
  let body: PermissionBody & ProfileBody;
  try {
    body = await parseJson<PermissionBody & ProfileBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  const user = await getUserById(env, userId);
  if (!user) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }

  const profileUpdates: { username?: string; avatar_url?: string; password_hash?: string } = {};
  if (body.username !== undefined) {
    const username = typeof body.username === "string" ? body.username.trim() : "";
    if (!username || username.length < 2 || username.length > 32) {
      return jsonResponse({ success: false, reason: "Invalid Username" }, { status: 400, headers: corsHeaders });
    }
    const existing = await getUserByUsername(env, username);
    if (existing && existing.id !== userId) {
      return jsonResponse({ success: false, reason: "Username Already Exists" }, { status: 409, headers: corsHeaders });
    }
    profileUpdates.username = username;
  }
  if (body.avatarUrl !== undefined) {
    const avatarUrl = typeof body.avatarUrl === "string" ? body.avatarUrl.trim() : "";
    if (!avatarUrl || !isValidUrl(avatarUrl)) {
      return jsonResponse({ success: false, reason: "Invalid Avatar URL" }, { status: 400, headers: corsHeaders });
    }
    profileUpdates.avatar_url = avatarUrl;
  }
  if (body.passwordHash !== undefined) {
    const passwordHash = typeof body.passwordHash === "string" ? body.passwordHash.trim() : "";
    if (!passwordHash) {
      return jsonResponse({ success: false, reason: "Invalid Password" }, { status: 400, headers: corsHeaders });
    }
    profileUpdates.password_hash = passwordHash;
  }

  const permissionInput = {
    can_login: body.canLogin,
    can_create: body.canCreate,
    can_verify: body.canVerify,
    can_profile: body.canProfile
  };
  const hasPermissionPatch = Object.values(permissionInput).some((value) => value !== undefined);

  if (Object.keys(profileUpdates).length > 0) {
    await updateUserProfile(env, userId, profileUpdates);
  }

  let updatedUser = await getUserById(env, userId);
  if (!updatedUser) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }

  if (hasPermissionPatch) {
    const before = {
      can_login: updatedUser.can_login,
      can_create: updatedUser.can_create,
      can_verify: updatedUser.can_verify,
      can_profile: updatedUser.can_profile,
      login_note: updatedUser.login_note,
      create_note: updatedUser.create_note,
      verify_note: updatedUser.verify_note,
      profile_note: updatedUser.profile_note
    };
    const merged = normalizePermissionState({
      can_login: body.canLogin !== undefined ? (body.canLogin ? 1 : 0) : before.can_login,
      can_create: body.canCreate !== undefined ? (body.canCreate ? 1 : 0) : before.can_create,
      can_verify: body.canVerify !== undefined ? (body.canVerify ? 1 : 0) : before.can_verify,
      can_profile: body.canProfile !== undefined ? (body.canProfile ? 1 : 0) : before.can_profile
    });

    const note = typeof body.note === "string" ? body.note.trim() : "";
    const changedPermissions: PermissionKey[] = [];
    const updates: {
      can_login?: boolean;
      can_create?: boolean;
      can_verify?: boolean;
      can_profile?: boolean;
      login_note?: string | null;
      create_note?: string | null;
      verify_note?: string | null;
      profile_note?: string | null;
    } = {};
    const beforeState = {
      can_login: before.can_login,
      can_create: before.can_create,
      can_verify: before.can_verify,
      can_profile: before.can_profile
    };
    const mergedState = {
      can_login: merged.can_login,
      can_create: merged.can_create,
      can_verify: merged.can_verify,
      can_profile: merged.can_profile
    };

    PERMISSION_ORDER.forEach(({ key }) => {
      const beforeEnabled = Boolean(beforeState[`can_${key}` as keyof typeof beforeState]);
      const nextEnabled = Boolean(mergedState[`can_${key}` as keyof typeof mergedState]);
      const permissionChanged = beforeEnabled !== nextEnabled;
      if (permissionChanged) {
        changedPermissions.push(key);
      }
      updates[
        key === "login" ? "can_login" : key === "create" ? "can_create" : key === "verify" ? "can_verify" : "can_profile"
      ] = nextEnabled;
      if (permissionChanged) {
        updates[
          key === "login" ? "login_note" : key === "create" ? "create_note" : key === "verify" ? "verify_note" : "profile_note"
        ] = note || null;
      }
    });

    await updateUserPermissions(env, userId, updates);
    for (const permissionKey of changedPermissions) {
      const nextEnabled = Boolean((merged as Record<string, number>)[`can_${permissionKey}`]);
      await insertPermissionNotification(env, {
        userId,
        permissionKey,
        granted: nextEnabled,
        note: note || null
      });
    }

    updatedUser = await getUserById(env, userId);
  }

  const finalUser = updatedUser;
  if (!finalUser) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }

  const links = await listLinksByUser(env, userId);
  return jsonResponse(
    {
      success: true,
      user: {
        id: finalUser.id,
        username: finalUser.username,
        avatarUrl: finalUser.avatar_url,
        permissions: buildPermissionResponse(finalUser),
        linkCount: links.length
      }
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleListUserLinksAdmin(env: Env, userId: number, corsHeaders: HeadersInit): Promise<Response> {
  const user = await getUserById(env, userId);
  if (!user) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
  const links = await listLinksByUser(env, userId);
  return jsonResponse(
    {
      success: true,
      user: {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url
      },
      links: await Promise.all(links.map(async (link) => mapLinkResponse(link, user)))
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleListUserLinks(session: UserSession, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  const links = await listLinksByUser(env, session.user.id);
  return jsonResponse(
    {
      success: true,
      links: await Promise.all(links.map(async (link) => mapLinkResponse(link, session.user)))
    },
    { status: 200, headers: corsHeaders }
  );
}

async function handleCreateUserLink(session: UserSession, request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  const denied = await assertPermission(env, session.user, "create", corsHeaders);
  if (denied) {
    return denied;
  }

  let body: LinkBody;
  try {
    body = await parseJson<LinkBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  if (body.selfVerified !== undefined && body.selfVerified === true) {
    const verifyDenied = await assertPermission(env, session.user, "verify", corsHeaders);
    if (verifyDenied) {
      return verifyDenied;
    }
  }

  return handleCreateLinkCommon(session.user.id, false, request, env, corsHeaders, body);
}

async function handleCreateAdminLink(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  return handleCreateLinkCommon(null, true, request, env, corsHeaders);
}

async function handleCreateLinkCommon(
  ownerUserId: number | null,
  createdByAdmin: boolean,
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  existingBody?: LinkBody
): Promise<Response> {
  let body: LinkBody;
  if (existingBody) {
    body = existingBody;
  } else {
    try {
      body = await parseJson<LinkBody>(request);
    } catch {
      return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
    }
  }

  const rawPath = typeof body.path === "string" ? body.path : "";
  const normalizedPath = normalizePath(rawPath);
  if (!normalizedPath || !isValidPath(normalizedPath) || isReservedPath(normalizedPath)) {
    return jsonResponse({ success: false, reason: "Invalid Path" }, { status: 400, headers: corsHeaders });
  }
  if (typeof body.url !== "string" || !body.url.trim() || !isValidUrl(body.url)) {
    return jsonResponse({ success: false, reason: "Invalid URL" }, { status: 400, headers: corsHeaders });
  }

  const existingId = await getLinkIdByPath(env, normalizedPath);
  if (existingId !== null) {
    return jsonResponse({ success: false, reason: "Path Already Exists" }, { status: 409, headers: corsHeaders });
  }

  const passwordHash = typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
  const selfVerified = body.selfVerified === true;
  const moderatorVerified = createdByAdmin || body.moderatorVerified === true;
  const id = await createLink(env, {
    path: normalizedPath,
    url: body.url.trim(),
    passwordHash,
    ownerUserId,
    createdByAdmin,
    selfVerified,
    moderatorVerified
  });
  return jsonResponse(
    {
      success: true,
      id,
      link: await getLinkById(env, id)
    },
    { status: 201, headers: corsHeaders }
  );
}

async function handleUpdateUserLink(
  session: UserSession,
  request: Request,
  env: Env,
  id: number,
  corsHeaders: HeadersInit
): Promise<Response> {
  const link = await getLinkById(env, id);
  if (!link || link.owner_user_id !== session.user.id) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }

  let body: LinkBody;
  try {
    body = await parseJson<LinkBody>(request);
  } catch {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }

  if (body.path !== undefined || body.url !== undefined || body.password !== undefined) {
    const denied = await assertPermission(env, session.user, "create", corsHeaders);
    if (denied) {
      return denied;
    }
  }

  if (body.selfVerified === true) {
    const denied = await assertPermission(env, session.user, "verify", corsHeaders);
    if (denied) {
      return denied;
    }
  }

  const allowSelfVerify = body.selfVerified !== undefined;

  return handleUpdateLinkCommon(link, request, env, corsHeaders, { allowModeratorEdit: false, allowSelfVerify }, body);
}

async function handleUpdateLinkCommon(
  link: LinkRow,
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  options: { allowModeratorEdit: boolean; allowSelfVerify: boolean },
  existingBody?: LinkBody
): Promise<Response> {
  let body: LinkBody;
  if (existingBody) {
    body = existingBody;
  } else {
    try {
      body = await parseJson<LinkBody>(request);
    } catch {
      return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
    }
  }

  const updates: {
    path?: string;
    url?: string;
    password_hash?: string | null;
    self_verified?: boolean;
    moderator_verified?: boolean;
  } = {};

  if (body.path !== undefined) {
    const normalizedPath = normalizePath(body.path);
    if (!normalizedPath || !isValidPath(normalizedPath) || isReservedPath(normalizedPath)) {
      return jsonResponse({ success: false, reason: "Invalid Path" }, { status: 400, headers: corsHeaders });
    }
    const existingId = await getLinkIdByPath(env, normalizedPath);
    if (existingId !== null && existingId !== link.id) {
      return jsonResponse({ success: false, reason: "Path Already Exists" }, { status: 409, headers: corsHeaders });
    }
    updates.path = normalizedPath;
  }
  if (body.url !== undefined) {
    if (typeof body.url !== "string" || !body.url.trim() || !isValidUrl(body.url)) {
      return jsonResponse({ success: false, reason: "Invalid URL" }, { status: 400, headers: corsHeaders });
    }
    updates.url = body.url.trim();
  }
  if (body.password !== undefined) {
    if (typeof body.password !== "string") {
      return jsonResponse({ success: false, reason: "Invalid Password" }, { status: 400, headers: corsHeaders });
    }
    updates.password_hash = body.password.trim() ? body.password.trim() : null;
  }
  if (options.allowSelfVerify && body.selfVerified !== undefined) {
    updates.self_verified = body.selfVerified === true;
  }
  if (options.allowModeratorEdit && body.moderatorVerified !== undefined) {
    updates.moderator_verified = body.moderatorVerified === true;
  }
  if (Object.keys(updates).length === 0) {
    return jsonResponse({ success: false, reason: "No updates provided" }, { status: 400, headers: corsHeaders });
  }
  await updateLink(env, link.id, updates);
  return jsonResponse({ success: true }, { status: 200, headers: corsHeaders });
}

async function handleUpdateUserLinkAdmin(
  request: Request,
  env: Env,
  id: number,
  corsHeaders: HeadersInit
): Promise<Response> {
  const link = await getLinkById(env, id);
  if (!link) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
  return handleUpdateLinkCommon(link, request, env, corsHeaders, { allowModeratorEdit: true, allowSelfVerify: true });
}

async function handleAdminUpdateLink(request: Request, env: Env, id: number, corsHeaders: HeadersInit): Promise<Response> {
  const body = await parseJson<{
    path?: string;
    url?: string;
    password?: string;
    selfVerified?: boolean;
    moderatorVerified?: boolean;
  }>(request).catch(() => null);
  if (!body) {
    return jsonResponse({ success: false, reason: "Invalid JSON" }, { status: 400, headers: corsHeaders });
  }
  const link = await getLinkById(env, id);
  if (!link) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }

  const updates: {
    path?: string;
    url?: string;
    password_hash?: string | null;
    self_verified?: boolean;
    moderator_verified?: boolean;
  } = {};
  if (body.path !== undefined) {
    const normalizedPath = normalizePath(body.path);
    if (!normalizedPath || !isValidPath(normalizedPath) || isReservedPath(normalizedPath)) {
      return jsonResponse({ success: false, reason: "Invalid Path" }, { status: 400, headers: corsHeaders });
    }
    const existingId = await getLinkIdByPath(env, normalizedPath);
    if (existingId !== null && existingId !== id) {
      return jsonResponse({ success: false, reason: "Path Already Exists" }, { status: 409, headers: corsHeaders });
    }
    updates.path = normalizedPath;
  }
  if (body.url !== undefined) {
    if (typeof body.url !== "string" || !body.url.trim() || !isValidUrl(body.url)) {
      return jsonResponse({ success: false, reason: "Invalid URL" }, { status: 400, headers: corsHeaders });
    }
    updates.url = body.url.trim();
  }
  if (body.password !== undefined) {
    if (typeof body.password !== "string") {
      return jsonResponse({ success: false, reason: "Invalid Password" }, { status: 400, headers: corsHeaders });
    }
    updates.password_hash = body.password.trim() ? body.password.trim() : null;
  }
  if (body.selfVerified !== undefined) {
    updates.self_verified = body.selfVerified === true;
  }
  if (body.moderatorVerified !== undefined) {
    updates.moderator_verified = body.moderatorVerified === true;
  }
  if (Object.keys(updates).length === 0) {
    return jsonResponse({ success: false, reason: "No updates provided" }, { status: 400, headers: corsHeaders });
  }
  await updateLink(env, id, updates);
  return jsonResponse({ success: true }, { status: 200, headers: corsHeaders });
}

async function handleDeleteUserLink(
  session: UserSession,
  env: Env,
  id: number,
  corsHeaders: HeadersInit
): Promise<Response> {
  const link = await getLinkById(env, id);
  if (!link || link.owner_user_id !== session.user.id) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
  await deleteLink(env, id);
  return jsonResponse({ success: true }, { status: 200, headers: corsHeaders });
}

async function handleDeleteAnyLink(env: Env, id: number, corsHeaders: HeadersInit): Promise<Response> {
  const link = await getLinkById(env, id);
  if (!link) {
    return jsonResponse({ success: false, reason: "Not Found" }, { status: 404, headers: corsHeaders });
  }
  await deleteLink(env, id);
  return jsonResponse({ success: true }, { status: 200, headers: corsHeaders });
}

async function handleListLinksAdmin(env: Env, corsHeaders: HeadersInit): Promise<Response> {
  const links = await listLinks(env);
  const result = await Promise.all(
    links.map(async (link) => {
      const owner = link.owner_user_id ? await getUserById(env, link.owner_user_id) : null;
      return mapLinkResponse(link, owner);
    })
  );
  return jsonResponse({ success: true, links: result }, { status: 200, headers: corsHeaders });
}
