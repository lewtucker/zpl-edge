CREATE TABLE IF NOT EXISTS requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT NOT NULL,
    agent_id         TEXT,
    agent_role       TEXT,
    peer_ip          TEXT NOT NULL,
    identity_source  TEXT NOT NULL,

    -- Request
    request_type     TEXT NOT NULL,   -- 'mcp' | 'http' | 'connect'
    dest_host        TEXT NOT NULL,
    dest_port        INTEGER,
    method           TEXT,
    path             TEXT,
    request_headers  TEXT,            -- JSON
    request_body     TEXT,            -- full body or NULL if binary/over limit

    -- MCP fields (NULL for non-MCP)
    mcp_method       TEXT,            -- 'tools/call', 'tools/list', 'initialize', etc.
    tool_name        TEXT,
    tool_args        TEXT,            -- JSON

    -- Response
    response_code    INTEGER,
    response_time_ms INTEGER,
    response_headers TEXT,            -- JSON
    response_body    TEXT,

    -- MCP response
    tool_result      TEXT,            -- JSON content array from tools/call response

    -- Learning pipeline
    is_anomaly       INTEGER DEFAULT 0,
    anomaly_reason   TEXT,
    pattern_id       INTEGER REFERENCES patterns(id),

    -- Policy enforcement
    policy_verdict   TEXT,   -- 'allow' | 'deny' | NULL (log-only mode)
    policy_rule_id   TEXT
);

CREATE TABLE IF NOT EXISTS patterns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT,
    dest_host   TEXT,
    method      TEXT,
    path        TEXT,
    tool_name   TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    count       INTEGER DEFAULT 1,
    zpl_rule    TEXT
);

CREATE TABLE IF NOT EXISTS zpl_rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at      TEXT NOT NULL,
    rule_text         TEXT NOT NULL,
    pattern_ids       TEXT NOT NULL,   -- JSON array
    observation_count INTEGER,
    status            TEXT DEFAULT 'proposed'  -- proposed | approved | active | rejected
);

CREATE INDEX IF NOT EXISTS idx_requests_agent ON requests(agent_id);
CREATE INDEX IF NOT EXISTS idx_requests_ts    ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_tool  ON requests(tool_name);
CREATE INDEX IF NOT EXISTS idx_requests_host  ON requests(dest_host);
CREATE INDEX IF NOT EXISTS idx_patterns_key   ON patterns(agent_id, dest_host, tool_name);
