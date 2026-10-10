-- Opt-in Orbit City game identity bridge, isolated from mail content.
-- Apply before enabling GAME_LINK_ENABLED. Only keyed one-time code hashes are stored.
CREATE TABLE IF NOT EXISTS account_game_link_codes (
  code_hash TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  CHECK (expires_at > created_at)
);
-- Enforce a single outstanding one-time code per account across concurrent Workers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_game_link_codes_account ON account_game_link_codes(subject_id);
CREATE INDEX IF NOT EXISTS idx_account_game_link_codes_expiry ON account_game_link_codes(expires_at);

-- Durable, idempotent cross-service account-erasure acknowledgements.
-- Recovered from historic account_closures if the game service was unavailable at deletion time.
CREATE TABLE IF NOT EXISTS account_game_deprovision_delivery (
  account_id TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  retry_after INTEGER NOT NULL DEFAULT 0,
  delivered_at INTEGER,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_game_deprovision_retry ON account_game_deprovision_delivery(delivered_at,retry_after);
