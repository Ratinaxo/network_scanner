import sqlite3
from typing import Optional, List, Tuple, Dict

class DeviceRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.cursor = conn.cursor()
    
    def create_scan(self, scanned_at: str) -> int:
        self.cursor.execute("""
            INSERT INTO scans (scanned_at) VALUES (?)
        """, (scanned_at,))
        return self.cursor.lastrowid

    def resolve_device_id(self, mac: Optional[str], ip: Optional[str]) -> Optional[int]:
        """Intenta encontrar un dispositivo conocido por MAC (prioridad) o IP."""
        if mac:
            self.cursor.execute("SELECT device_id FROM known_macs WHERE mac = ?", (mac,))
            row = self.cursor.fetchone()
            if row and row[0] is not None:
                return row[0]
        if ip:
            self.cursor.execute("SELECT device_id FROM known_ips WHERE ip = ?", (ip,))
            row = self.cursor.fetchone()
            if row and row[0] is not None:
                return row[0]
        return None

    def create_device(self, hostname: str, scanned_at: str) -> int:
        self.cursor.execute("""
            INSERT INTO devices (hostname, first_seen, last_seen, appearings)
            VALUES (?, ?, ?, 1)
        """, (hostname, scanned_at, scanned_at))
        return self.cursor.lastrowid

    def update_device(self, device_id: int, hostname: str, scanned_at: str):
        self.cursor.execute("""
            UPDATE devices
            SET hostname = COALESCE(?, hostname),
                last_seen = ?,
                appearings = appearings + 1
            WHERE id = ?
        """, (hostname, scanned_at, device_id))

    def get_device_details(self, device_id: int) -> Dict:
        cur = self.cursor
        
        # OS match
        cur.execute("SELECT os_name FROM fingerprint_os WHERE device_id = ? ORDER BY os_accuracy DESC LIMIT 1", (device_id,))
        row_os = cur.fetchone()

        # Ports and products
        cur.execute("SELECT port, service, product FROM fingerprint_ports WHERE device_id = ?", (device_id,))
        rows_ports = cur.fetchall()

        # Vendor and hostname
        cur.execute("SELECT vendor, hostname FROM sightings WHERE device_id = ? ORDER BY scanned_at DESC LIMIT 1", (device_id,))
        row_sight = cur.fetchone()

        return {
            "os": row_os[0].lower() if row_os else "",
            "ports": set(int(r[0]) for r in rows_ports if r[0].isdigit()),
            "banners": " ".join([f"{r[1] or ''} {r[2] or ''}" for r in rows_ports]).lower(),
            "vendor": row_sight[0].lower() if row_sight and row_sight[0] else "",
            "hostname": row_sight[1].lower() if row_sight and row_sight[1] else ""
        }
    
    def update_device_type(self, device_id: int, device_type: str):
        self.cursor.execute("UPDATE devices SET type = ? WHERE id = ?", (device_type, device_id))

    def record_ip(self, ip: str, device_id: int, scanned_at: str):
        self.cursor.execute("SELECT id, device_id FROM known_ips WHERE ip = ?", (ip,))
        row = self.cursor.fetchone()
        
        if row:
            ip_id, existing_dev = row
            self.cursor.execute("UPDATE known_ips SET last_seen = ?, appearings = appearings + 1 WHERE id = ?", (scanned_at, ip_id))
            # Lógica de cambio de dueño (DHCP)
            if existing_dev is None or existing_dev != device_id:
                self.cursor.execute("UPDATE known_ips SET device_id = ? WHERE id = ?", (device_id, ip_id))
        else:
            self.cursor.execute("""
                INSERT INTO known_ips (ip, device_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
            """, (ip, device_id, scanned_at, scanned_at))

    def record_mac(self, mac: str, device_id: int, scanned_at: str):
        self.cursor.execute("SELECT id, device_id FROM known_macs WHERE mac = ?", (mac,))
        row = self.cursor.fetchone()
        
        if row:
            mac_id, existing_dev = row
            self.cursor.execute("UPDATE known_macs SET last_seen = ?, appearings = appearings + 1 WHERE id = ?", (scanned_at, mac_id))
            # Lógica de cambio de dueño
            if existing_dev is None or existing_dev != device_id:
                self.cursor.execute("UPDATE known_macs SET device_id = ? WHERE id = ?", (device_id, mac_id))
        else:
            self.cursor.execute("""
                INSERT INTO known_macs (mac, device_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
            """, (mac, device_id, scanned_at, scanned_at))

    def record_sighting(self, scan_id: int, device_id: int, host_data: dict, scanned_at: str):
        self.cursor.execute("""
            INSERT INTO sightings (scan_id, device_id, ip, mac, vendor, hostname, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, device_id, host_data['ip'], host_data['mac'], host_data['vendor'], host_data['hostname'], scanned_at))

    def save_fingerprints(self, device_id: int, scan_id: int, host_data: dict):
        # OS
        if host_data["os_match"]:
            best_os = max(host_data["os_match"], key=lambda x: x["accuracy"])
            self.cursor.execute("""
                INSERT INTO fingerprint_os (device_id, scan_id, os_name, os_accuracy)
                VALUES (?, ?, ?, ?)
            """, (device_id, scan_id, best_os["name"], best_os["accuracy"]))
        
        # Ports
        for p in host_data["ports"]:
            self.cursor.execute("""
                INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service, product, version)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (device_id, scan_id, p["port"], p["protocol"], p["service"], p["product"], p["version"]))

    # --- Métodos para Heurística y Análisis ---
    
    def get_all_device_ids(self) -> List[int]:
        """Retorna una lista con todos los IDs de dispositivos."""
        self.cursor.execute("SELECT id FROM devices")
        return [row[0] for row in self.cursor.fetchall()]

    def get_last_scan_ports(self, device_id: int) -> List[Tuple[str, str]]:
        """
        Retorna los puertos (port, prot) del último escaneo válido de un dispositivo.
        Usado por la heurística.
        """
        self.cursor.execute("SELECT MAX(scan_id) FROM fingerprint_ports WHERE device_id = ?", (device_id,))
        last_scan_row = self.cursor.fetchone()
        if not last_scan_row or last_scan_row[0] is None:
            return []
        
        last_scan_id = last_scan_row[0]
        self.cursor.execute("SELECT port, prot FROM fingerprint_ports WHERE device_id = ? AND scan_id = ?", (device_id, last_scan_id))
        return self.cursor.fetchall()
        
    def get_disappeared_devices(self, current_seen_ids: set, scanned_at: str) -> List[int]:
        self.cursor.execute("SELECT id, last_seen FROM devices")
        all_devs = self.cursor.fetchall()
        return [d[0] for d in all_devs if d[0] not in current_seen_ids and d[1] < scanned_at]