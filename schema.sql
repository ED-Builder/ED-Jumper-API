CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    password_hash TEXT,
    owner_user_id INTEGER,
    created_by_admin INTEGER NOT NULL DEFAULT 1,
    self_verified INTEGER NOT NULL DEFAULT 0,
    moderator_verified INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_links_path ON links(path);
CREATE INDEX IF NOT EXISTS idx_links_created_at ON links(created_at);
CREATE INDEX IF NOT EXISTS idx_links_owner_user_id ON links(owner_user_id);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    avatar_url TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    can_login INTEGER NOT NULL DEFAULT 1,
    can_create INTEGER NOT NULL DEFAULT 1,
    can_verify INTEGER NOT NULL DEFAULT 1,
    can_profile INTEGER NOT NULL DEFAULT 1,
    login_note TEXT,
    create_note TEXT,
    verify_note TEXT,
    profile_note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS permission_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permission_key TEXT NOT NULL,
    permission_label TEXT NOT NULL,
    granted INTEGER NOT NULL,
    note TEXT,
    acknowledged_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_permission_notifications_user_id ON permission_notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_permission_notifications_ack ON permission_notifications(acknowledged_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
