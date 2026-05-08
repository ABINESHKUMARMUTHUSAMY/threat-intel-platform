-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Flows: time-series, will become a TimescaleDB hypertable
-- ============================================================
CREATE TABLE flows (
    id UUID DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    duration_ms BIGINT,
    fwd_packet_count INTEGER DEFAULT 0,
    bwd_packet_count INTEGER DEFAULT 0,
    fwd_bytes BIGINT DEFAULT 0,
    bwd_bytes BIGINT DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    ack_count INTEGER DEFAULT 0,
    fin_count INTEGER DEFAULT 0,
    rst_count INTEGER DEFAULT 0,
    psh_count INTEGER DEFAULT 0,
    urg_count INTEGER DEFAULT 0,
    iat_mean_ms NUMERIC,
    iat_std_ms NUMERIC,
    iat_min_ms NUMERIC,
    iat_max_ms NUMERIC,
    pkt_len_mean NUMERIC,
    pkt_len_std NUMERIC,
    pkt_len_min INTEGER,
    pkt_len_max INTEGER,
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('flows', 'timestamp', if_not_exists => TRUE);
CREATE INDEX idx_flows_src_ip ON flows (src_ip, timestamp DESC);
CREATE INDEX idx_flows_dst_ip ON flows (dst_ip, timestamp DESC);

-- ============================================================
-- Alerts: emitted by detection service
-- ============================================================
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    flow_id UUID,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    attack_type VARCHAR(50),
    confidence NUMERIC CHECK (confidence >= 0 AND confidence <= 1),
    src_ip INET NOT NULL,
    dst_ip INET,
    description TEXT,
    raw_features JSONB,
    status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive'))
);

CREATE INDEX idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX idx_alerts_status ON alerts (status, timestamp DESC);

-- ============================================================
-- Assets: discovered hosts (passive + active scan)
-- ============================================================
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET UNIQUE NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    authorized BOOLEAN DEFAULT FALSE,
    notes TEXT
);

CREATE INDEX idx_assets_authorized ON assets (authorized);

-- ============================================================
-- Blocklist: actively blocked IPs (with TTL)
-- ============================================================
CREATE TABLE blocklist (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET UNIQUE NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    alert_id UUID REFERENCES alerts(id),
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_blocklist_active ON blocklist (active, expires_at);

-- ============================================================
-- YARA rules: auto-generated signatures
-- ============================================================
CREATE TABLE yara_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    rule_text TEXT NOT NULL,
    source_alert_id UUID REFERENCES alerts(id),
    fp_rate NUMERIC,
    validated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Playbook runs: audit log of every automated action
-- ============================================================
CREATE TABLE playbook_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    playbook_name VARCHAR(50) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    actions_taken JSONB,
    error_message TEXT,
    duration_ms INTEGER
);

CREATE INDEX idx_playbook_runs_alert ON playbook_runs (alert_id);

-- ============================================================
-- Health check table (used by /health endpoints)
-- ============================================================
CREATE TABLE health_check (
    id INTEGER PRIMARY KEY DEFAULT 1,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT single_row CHECK (id = 1)
);

INSERT INTO health_check (id) VALUES (1) ON CONFLICT DO NOTHING;
