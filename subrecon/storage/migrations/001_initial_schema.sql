CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    root_domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN (
            'pending', 'running', 'completed',
            'failed', 'cancelled'
        )),
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE discovered_subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL COLLATE NOCASE,
    discovered_at TEXT NOT NULL,

    FOREIGN KEY (scan_id)
        REFERENCES scans(scan_id)
        ON DELETE CASCADE,

    UNIQUE (scan_id, hostname)
);

CREATE TABLE subdomain_sources (
    subdomain_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    discovered_at TEXT NOT NULL,

    PRIMARY KEY (subdomain_id, source),

    FOREIGN KEY (subdomain_id)
        REFERENCES discovered_subdomains(id)
        ON DELETE CASCADE
);

CREATE TABLE dns_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER CHECK (ttl IS NULL OR ttl >= 0),
    observed_at TEXT NOT NULL,

    FOREIGN KEY (subdomain_id)
        REFERENCES discovered_subdomains(id)
        ON DELETE CASCADE
);

CREATE TABLE http_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER CHECK (
        status_code IS NULL OR status_code BETWEEN 100 AND 599
    ),
    final_url TEXT,
    title TEXT,
    server TEXT,
    content_type TEXT,
    observed_at TEXT NOT NULL,

    FOREIGN KEY (subdomain_id)
        REFERENCES discovered_subdomains(id)
        ON DELETE CASCADE
);

CREATE TABLE technology_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    source TEXT,
    observed_at TEXT NOT NULL,

    FOREIGN KEY (subdomain_id)
        REFERENCES discovered_subdomains(id)
        ON DELETE CASCADE
);

CREATE TABLE tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN (
            'pending', 'running', 'completed',
            'failed', 'timed_out', 'skipped'
        )),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    error_message TEXT,

    FOREIGN KEY (scan_id)
        REFERENCES scans(scan_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_subdomains_hostname
    ON discovered_subdomains(hostname);

CREATE INDEX idx_dns_subdomain
    ON dns_observations(subdomain_id);

CREATE INDEX idx_http_subdomain
    ON http_observations(subdomain_id);

CREATE INDEX idx_technology_subdomain
    ON technology_observations(subdomain_id);

CREATE INDEX idx_tool_runs_scan
    ON tool_runs(scan_id);
