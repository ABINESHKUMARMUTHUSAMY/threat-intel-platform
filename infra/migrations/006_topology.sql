CREATE TABLE IF NOT EXISTS host_inventory (
    id              SERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    hostname        VARCHAR(255),
    mac_address     MACADDR,
    os_guess        VARCHAR(255),
    open_ports      JSONB DEFAULT '[]'::jsonb,
    services        JSONB DEFAULT '{}'::jsonb,
    scan_method     VARCHAR(50) DEFAULT 'nmap',
    last_scanned    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role            VARCHAR(50),
    CONSTRAINT host_inventory_role_check
      CHECK (role IS NULL OR role IN ('sensor', 'attacker', 'victim', 'http_server', 'ssh_server', 'dns_server', 'unknown'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_inventory_ip ON host_inventory(ip_address);
CREATE INDEX IF NOT EXISTS idx_host_inventory_last_scanned ON host_inventory(last_scanned DESC);

CREATE TABLE IF NOT EXISTS topology_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    target_subnet   CIDR NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'running',
    hosts_found     INTEGER DEFAULT 0,
    error_message   TEXT,
    CONSTRAINT topology_scans_status_check
      CHECK (status IN ('running', 'success', 'failed'))
);

COMMENT ON TABLE host_inventory IS 'Active scan results — one row per known host in the VPC';
COMMENT ON TABLE topology_scans IS 'History of nmap scan runs for the topology mapper';
