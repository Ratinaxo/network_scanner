import sqlite3
from typing import Optional, List, Tuple, Dict
import src.utils as utils

class DeviceRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.cursor = conn.cursor()
    
    # --- GESTIÓN DE ESCANEOS Y DISPOSITIVOS ---

    def create_scan(self, scanned_at: str) -> int:
        self.cursor.execute("INSERT INTO scans (scanned_at) VALUES (?)", (scanned_at,))
        return self.cursor.lastrowid

    def resolve_device_id(self, mac: Optional[str], ip: Optional[str]) -> Optional[int]:
        if mac:
            self.cursor.execute("SELECT device_id FROM known_macs WHERE mac = ?", (mac,))
            row = self.cursor.fetchone()
            if row and row[0] is not None: return row[0]
        if ip:
            self.cursor.execute("SELECT device_id FROM known_ips WHERE ip = ?", (ip,))
            row = self.cursor.fetchone()
            if row and row[0] is not None: return row[0]
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

    def update_device_type(self, device_id: int, device_type: str):
        self.cursor.execute("UPDATE devices SET type = ? WHERE id = ?", (device_type, device_id))

    # --- TRACKING (IPs, MACs, Sightings) ---

    def record_ip(self, ip: str, device_id: int, scanned_at: str):
        self.cursor.execute("SELECT id, device_id FROM known_ips WHERE ip = ?", (ip,))
        row = self.cursor.fetchone()
        
        if row:
            ip_id, existing_dev = row
            self.cursor.execute("UPDATE known_ips SET last_seen = ?, appearings = appearings + 1 WHERE id = ?", (scanned_at, ip_id))
            if existing_dev is None or existing_dev != device_id:
                self.cursor.execute("UPDATE known_ips SET device_id = ? WHERE id = ?", (device_id, ip_id))
        else:
            self.cursor.execute("INSERT INTO known_ips (ip, device_id, first_seen, last_seen) VALUES (?, ?, ?, ?)", (ip, device_id, scanned_at, scanned_at))

    def record_mac(self, mac: str, device_id: int, scanned_at: str):
        self.cursor.execute("SELECT id, device_id FROM known_macs WHERE mac = ?", (mac,))
        row = self.cursor.fetchone()
        
        if row:
            mac_id, existing_dev = row
            self.cursor.execute("UPDATE known_macs SET last_seen = ?, appearings = appearings + 1 WHERE id = ?", (scanned_at, mac_id))
            if existing_dev is None or existing_dev != device_id:
                self.cursor.execute("UPDATE known_macs SET device_id = ? WHERE id = ?", (device_id, mac_id))
        else:
            self.cursor.execute("INSERT INTO known_macs (mac, device_id, first_seen, last_seen) VALUES (?, ?, ?, ?)", (mac, device_id, scanned_at, scanned_at))

    def record_sighting(self, scan_id: int, device_id: int, host_data: dict, scanned_at: str):
        self.cursor.execute("""
            INSERT INTO sightings (scan_id, device_id, ip, mac, vendor, hostname, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, device_id, host_data['ip'], host_data['mac'], host_data['vendor'], host_data['hostname'], scanned_at))

    # --- FINGERPRINTS ACTIVOS (Nmap) ---

    def save_active_fingerprints(self, device_id: int, scan_id: int, host_data: dict):
        if host_data["os_match"]:
            best_os = max(host_data["os_match"], key=lambda x: x["accuracy"])
            self.cursor.execute("INSERT INTO fingerprint_os (device_id, scan_id, os_name, os_accuracy) VALUES (?, ?, ?, ?)", 
                                (device_id, scan_id, best_os["name"], best_os["accuracy"]))
        
        for p in host_data["ports"]:
            self.cursor.execute("INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service, product, version) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                (device_id, scan_id, p["port"], p["protocol"], p["service"], p["product"], p["version"]))

    def save_scripts_data(self, device_id: int, scan_id: int, host_data: dict):
        if "scripts" in host_data:
            for s in host_data["scripts"]:
                self.cursor.execute("INSERT INTO fingerprint_scripts (device_id, scan_id, script_id, output) VALUES (?, ?, ?, ?)", 
                                    (device_id, scan_id, s["id"], s["output"]))

    # --- FINGERPRINTS PASIVOS (Sniffer) - NUEVO ---

    def save_passive_fingerprint(self, ip: Optional[str], mac: Optional[str], source: str, data: str):
        """
        Guarda datos del sniffer. 
        Si el dispositivo no existe y tenemos MAC, lo creamos.
        """
        # 1. Identificar dispositivo
        device_id = self.resolve_device_id(mac, ip)
        
        # 2. Auto-creación (Si el sniffer ve algo nuevo que Nmap no vio)
        if not device_id and mac:
            # Usamos utils.now_iso() aquí si es posible, o pasamos la fecha como argumento
            # Asumimos que importaste utils o pasas la fecha.
            now = utils.now_iso()
            device_id = self.create_device(f"Unknown (Passive {mac[-4:]})", now)
            self.record_mac(mac, device_id, now)
            if ip: self.record_ip(ip, device_id, now)
            
            # ¡Hacemos commit parcial para asegurar que el ID exista para la siguiente linea!
            self.conn.commit() 

        if device_id:
            # Reutilizamos la tabla fingerprint_services para datos pasivos
            # scan_id es NULL porque no pertenece a un escaneo programado
            self.cursor.execute("""
                INSERT INTO fingerprint_services (device_id, scan_id, service_name, data)
                VALUES (?, NULL, ?, ?)
            """, (device_id, source, data))
            self.conn.commit() # Commit inmediato para el sniffer

    def get_scripts_output(self, device_id: int) -> str:
        """
        Concatena toda la salida de scripts conocida para un dispositivo.
        Usado por el clasificador para buscar keywords.
        """
        self.cursor.execute("SELECT output FROM fingerprint_scripts WHERE device_id = ?", (device_id,))
        rows = self.cursor.fetchall()
        # Une todo en un string minúscula para buscar fácil
        return " ".join([r[0] for r in rows if r[0]]).lower()
    
    # --- LECTURA DE DATOS (Para Análisis) ---

    def get_device_details(self, device_id: int) -> Dict:
        """Recopila TODA la evidencia (Activa y Pasiva) para el clasificador."""
        cur = self.cursor
        
        # 1. OS Activo (Nmap)
        cur.execute("SELECT os_name FROM fingerprint_os WHERE device_id = ? ORDER BY os_accuracy DESC LIMIT 1", (device_id,))
        row_os = cur.fetchone()

        # 2. Puertos y Productos (Nmap)
        cur.execute("SELECT port, service, product FROM fingerprint_ports WHERE device_id = ?", (device_id,))
        rows_ports = cur.fetchall()

        # 3. Scripts NSE (Nmap)
        cur.execute("SELECT output FROM fingerprint_scripts WHERE device_id = ?", (device_id,))
        rows_scripts = cur.fetchall()
        
        # 4. Datos Pasivos (Sniffer - almacenados en fingerprint_services)
        cur.execute("SELECT service_name, data FROM fingerprint_services WHERE device_id = ?", (device_id,))
        rows_passive = cur.fetchall()

        # --- CONSOLIDACIÓN DE TEXTOS ---
        # Juntamos Banners de puertos + Salida de Scripts + Datos del Sniffer en un solo texto analizable
        banners_text = " ".join([f"{r[1] or ''} {r[2] or ''}" for r in rows_ports])
        scripts_text = " ".join([r[0] for r in rows_scripts])
        passive_text = " ".join([f"{r[0]} {r[1]}" for r in rows_passive]) # ej: "passive_dhcp [1,3,6]"
        
        full_text = (banners_text + " " + scripts_text + " " + passive_text).lower()

        # Vendor y Hostname
        cur.execute("SELECT vendor, hostname FROM sightings WHERE device_id = ? ORDER BY scanned_at DESC LIMIT 1", (device_id,))
        row_sight = cur.fetchone()

        return {
            "os": row_os[0].lower() if row_os else "",
            "ports": set(int(r[0]) for r in rows_ports if r[0].isdigit()),
            "banners": full_text, # Ahora 'banners' contiene TODO el texto rico
            "vendor": row_sight[0].lower() if row_sight and row_sight[0] else "",
            "hostname": row_sight[1].lower() if row_sight and row_sight[1] else ""
        }

    def get_all_device_ids(self) -> List[int]:
        self.cursor.execute("SELECT id FROM devices")
        return [row[0] for row in self.cursor.fetchall()]

    def get_last_scan_ports(self, device_id: int) -> List[Tuple[str, str]]:
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