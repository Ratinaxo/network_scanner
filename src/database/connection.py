import sqlite3
import os
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path: str):
        """
        Gestiona la conexión y estructura de la base de datos.
        :param db_path: Ruta absoluta al archivo .db
        """
        self.db_path = db_path

    @contextmanager
    def get_connection(self):
        # Aseguramos directorios
        db_dir = os.path.dirname(self.db_path)
        if db_dir: os.makedirs(db_dir, exist_ok=True)
            
        conn = sqlite3.connect(self.db_path, timeout=20, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        
        try:
            yield conn
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """
        Crea las tablas e índices necesarios si no existen.
        """
        with self.get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            c = conn.cursor()

            # --- TABLAS CORE ---
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
                last_deep_scan TEXT,
                appearings INTEGER DEFAULT 1,
                type TEXT DEFAULT 'unknown',
                confidence INTEGER DEFAULT 0
            )
            """)
            # Índices Core
            c.execute("CREATE INDEX IF NOT EXISTS idx_known_ips_device ON known_ips(device_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_known_ips_ip ON known_ips(ip)")

            # --- TABLAS SCANNING ---
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
            # Índices Scanning
            c.execute("CREATE INDEX IF NOT EXISTS idx_sightings_scan ON sightings(scan_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_sightings_device ON sightings(device_id)")

            # --- TABLAS FINGERPRINTING ---
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
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_os_scan ON fingerprint_os(scan_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_os_device ON fingerprint_os(device_id)")

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
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_device ON fingerprint_ports(device_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_scan ON fingerprint_ports(scan_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_ports_port ON fingerprint_ports(port)")

            c.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_services(
                id INTEGER PRIMARY KEY,
                device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
                scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                service_name TEXT,
                data TEXT
            )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_services_device ON fingerprint_services(device_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_services_scan ON fingerprint_services(scan_id)")

            c.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_scripts(
                id INTEGER PRIMARY KEY, 
                device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
                scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                script_id TEXT, 
                output TEXT)
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint_scripts_device ON fingerprint_scripts(device_id)")
            
            conn.commit()