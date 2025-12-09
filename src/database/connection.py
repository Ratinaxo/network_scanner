import sqlite3
from typing import Optional

def get_connection(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path)

def init_db(conn: sqlite3.Connection) -> None:
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS known_ips (
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        ip TEXT UNIQUE NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        appearings INTEGER DEFAULT 1
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS known_macs (
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        mac TEXT UNIQUE NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        appearings INTEGER DEFAULT 1
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY,
        hostname TEXT,
        first_seen TEXT,
        last_seen TEXT,
        appearings INTEGER DEFAULT 1,
        type TEXT DEFAULT 'unknown'
    )
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_known_ips_device ON known_ips(device_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_known_ips_ip ON known_ips(ip)
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY,
        scanned_at TEXT NOT NULL,
        network TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS sightings (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
        ip TEXT,
        mac TEXT,
        vendor TEXT,
        hostname TEXT,
        scanned_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_sightings_scan ON sightings(scan_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_sightings_device ON sightings(device_id)
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS fingerprint_os(
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        os_name TEXT,
        os_accuracy INTEGER,
        uptime_secs INTEGER,
        hops INTEGER
    )
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_os_scan ON fingerprint_os(scan_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_os_device ON fingerprint_os(device_id)
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS fingerprint_ports(
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        port TEXT,
        prot TEXT,
        service TEXT,
        product TEXT,
        version TEXT
    )
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_device ON fingerprint_ports(device_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_scan ON fingerprint_ports(scan_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_port ON fingerprint_ports(port)
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS fingerprint_services(
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        service_name TEXT,
        data TEXT
    )
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_services_device ON fingerprint_services(device_id)
    """)
    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_fingerprint_services_scan ON fingerprint_services(scan_id)
    """)

    conn.commit()

