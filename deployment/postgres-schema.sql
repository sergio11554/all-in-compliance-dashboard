-- Reference schema for SFM Compliance PostgreSQL mode.
-- Runtime initialization is performed by database.py and remains idempotent.

CREATE TABLE IF NOT EXISTS tenants (
  id text PRIMARY KEY,
  name text NOT NULL,
  slug text UNIQUE NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at bigint NOT NULL,
  updated_at bigint,
  retention_until bigint,
  legal_hold integer NOT NULL DEFAULT 0,
  lifecycle_note text,
  archived_at bigint
);

CREATE TABLE IF NOT EXISTS users (
  id bigserial PRIMARY KEY,
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL,
  created_at bigint NOT NULL,
  active integer NOT NULL DEFAULT 1,
  mfa_secret text,
  mfa_enabled integer NOT NULL DEFAULT 0,
  updated_at bigint,
  last_login_at bigint,
  email text,
  tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id),
  platform_admin integer NOT NULL DEFAULT 0,
  password_change_required integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id),
  tenant_id text,
  csrf_token text NOT NULL,
  expires_at bigint NOT NULL,
  created_at bigint NOT NULL,
  ip text
);

CREATE TABLE IF NOT EXISTS auth_login_limits (
  scope_key text PRIMARY KEY,
  scope text NOT NULL,
  attempt_count integer NOT NULL DEFAULT 0,
  window_started_at bigint NOT NULL,
  blocked_until bigint,
  updated_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id text PRIMARY KEY,
  token_hash text UNIQUE NOT NULL,
  user_id bigint NOT NULL REFERENCES users(id),
  requested_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint,
  requested_ip_hash text,
  delivered_at bigint
);

CREATE TABLE IF NOT EXISTS password_history (
  id text PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id),
  password_hash text NOT NULL,
  created_at bigint NOT NULL,
  changed_by bigint REFERENCES users(id),
  reason text
);

CREATE TABLE IF NOT EXISTS invitations (
  id text PRIMARY KEY,
  token_hash text UNIQUE NOT NULL,
  email text NOT NULL,
  display_name text,
  role text NOT NULL,
  tenant_id text NOT NULL REFERENCES tenants(id),
  invited_by bigint REFERENCES users(id),
  status text NOT NULL DEFAULT 'pending',
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  accepted_at bigint,
  accepted_user_id bigint REFERENCES users(id),
  revoked_at bigint,
  delivery_status text NOT NULL DEFAULT 'manual',
  delivery_attempts integer NOT NULL DEFAULT 0,
  last_sent_at bigint,
  delivered_at bigint,
  delivery_error text
);

CREATE TABLE IF NOT EXISTS oidc_login_states (
  state_hash text PRIMARY KEY,
  provider_id text NOT NULL,
  code_verifier text NOT NULL,
  nonce text NOT NULL,
  redirect_after text,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  ip text
);

CREATE TABLE IF NOT EXISTS oidc_identities (
  provider_id text NOT NULL,
  subject text NOT NULL,
  user_id bigint NOT NULL REFERENCES users(id),
  email text,
  created_at bigint NOT NULL,
  last_login_at bigint,
  PRIMARY KEY(provider_id, subject),
  UNIQUE(provider_id, user_id)
);

CREATE TABLE IF NOT EXISTS workspace_state (
  id integer PRIMARY KEY CHECK(id = 1),
  state_json text NOT NULL,
  updated_at bigint NOT NULL,
  updated_by bigint,
  tenant_id text
);

CREATE TABLE IF NOT EXISTS files (
  id text PRIMARY KEY,
  tenant_id text,
  original_name text NOT NULL,
  stored_name text NOT NULL,
  content_type text NOT NULL,
  size bigint NOT NULL,
  sha256 text NOT NULL,
  nonce text NOT NULL,
  uploaded_by bigint,
  uploaded_at bigint NOT NULL,
  document_id text,
  version_label text,
  previous_file_id text,
  linked_to text,
  classification text,
  scan_status text NOT NULL DEFAULT 'unscanned',
  scan_engine text,
  scan_signature text,
  scan_detail text,
  scanned_at bigint,
  quarantined integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  ts bigint NOT NULL,
  tenant_id text,
  user_id bigint,
  username text,
  action text NOT NULL,
  target_type text,
  target_id text,
  detail_json text,
  ip text,
  previous_hash text,
  event_hash text
);

CREATE TABLE IF NOT EXISTS tenant_events (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  event_type text NOT NULL,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  actor_user_id bigint REFERENCES users(id),
  actor_username text,
  created_at bigint NOT NULL,
  workspace_revision integer
);

CREATE TABLE IF NOT EXISTS tenant_workspace_state (
  tenant_id text PRIMARY KEY REFERENCES tenants(id),
  state_json text NOT NULL,
  updated_at bigint NOT NULL,
  updated_by bigint,
  revision integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS workspace_state_snapshots (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  state_json text NOT NULL,
  saved_at bigint NOT NULL,
  saved_by bigint,
  reason text NOT NULL,
  bytes bigint NOT NULL,
  sha256 text NOT NULL
);

CREATE TABLE IF NOT EXISTS operational_alerts (
  alert_key text PRIMARY KEY,
  severity text NOT NULL,
  source text NOT NULL,
  scope text NOT NULL,
  title text NOT NULL,
  detail text NOT NULL,
  status text NOT NULL DEFAULT 'open',
  action_view text,
  remediation_action text,
  remediation_label text,
  first_seen_at bigint NOT NULL,
  last_seen_at bigint NOT NULL,
  acknowledged_at bigint,
  acknowledged_by bigint,
  resolved_at bigint
);

CREATE TABLE IF NOT EXISTS notification_states (
  tenant_id text NOT NULL REFERENCES tenants(id),
  user_id bigint NOT NULL REFERENCES users(id),
  notification_id text NOT NULL,
  read_at bigint,
  dismissed_at bigint,
  escalated_at bigint,
  updated_at bigint NOT NULL,
  PRIMARY KEY (tenant_id, user_id, notification_id)
);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  notification_id text NOT NULL,
  channel text NOT NULL,
  destination_label text NOT NULL,
  payload_json text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at bigint,
  created_at bigint NOT NULL,
  created_by bigint REFERENCES users(id),
  last_attempt_at bigint,
  sent_at bigint,
  last_error text,
  response_code integer
);

CREATE TABLE IF NOT EXISTS background_jobs (
  id text PRIMARY KEY,
  tenant_id text REFERENCES tenants(id),
  job_type text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  priority integer NOT NULL DEFAULT 50,
  payload_json text NOT NULL DEFAULT '{}',
  result_json text,
  attempts integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 3,
  next_run_at bigint,
  locked_at bigint,
  locked_by text,
  created_at bigint NOT NULL,
  created_by bigint REFERENCES users(id),
  updated_at bigint,
  finished_at bigint,
  last_error text
);

CREATE INDEX IF NOT EXISTS idx_workspace_state_snapshots_tenant ON workspace_state_snapshots(tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_invitations_tenant ON invitations(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON invitations(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expiry ON oidc_login_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON oidc_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_operational_alerts_status ON operational_alerts(status, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_states_user ON notification_states(tenant_id, user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_queue ON notification_deliveries(status, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_tenant ON notification_deliveries(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_jobs_queue ON background_jobs(status, next_run_at, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_background_jobs_tenant ON background_jobs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_files_tenant_uploaded ON files(tenant_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_tenant_quarantine ON files(tenant_id, quarantined, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_log(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_events_stream ON tenant_events(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_tenant_events_created ON tenant_events(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_login_limits_expiry ON auth_login_limits(blocked_until, updated_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at, used_at);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
