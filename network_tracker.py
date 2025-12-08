#!/usr/bin/python3
import subprocess
import xml.etree.ElementTree as ET
import sqlite3
import datetime
import sys
import shlex
import argparse
import os
from typing import Optional

# Se inicializan luego dinámicamente
DB_PATH = None
LOG_PATH = None
# Si quieres fijar manualmente un rango:
FORCE_SUBNET = None


def log(msg: str):
    """Append a timestamped log entry into LOG_PATH."""
    if not LOG_PATH:
        return
    ts = datetime.datetime.now(datetime.UTC).isoformat()
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass

def now_iso():
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat() + "Z"

def detect_subnet():
    try:
        out = subprocess.check_output(shlex.split("ip route get 1.1.1.1"), text=True)
        parts = out.split()
        if "src" in parts:
            src_ip = parts[parts.index("src") + 1]
            base = ".".join(src_ip.split(".")[:3]) + ".0/24"
            return base
        return None
    except Exception as e:
        log(f"ERROR detect_subnet: {e}")
        return None

def run_nmap(subnet, raw_output_path):
    cmd = [
        "nmap", 
        "-O",             # Detección de Sistema Operativo
        "-sS",            # TCP SYN Scan (Rápido y sigiloso, requiere sudo)
        "-sV",            # Detección de Versiones (Para saber si es Apache, Nginx, etc.)
        "--version-intensity", "5", # (Opcional) 0-9. 1 es rápido, 9 es lento pero preciso.
        "-R",             # DNS Resolution (Reverse lookup siempre)
        "--top-ports", "100", # AUMENTADO: 20 es muy poco para fingerprinting único. 100 es buen balance.
        "--script", "broadcast-dhcp-discover", # Mantiene la detección de MACs robusta
        "-oX", "-",       # Salida XML a stdout
        subnet]
    
    if raw_output_path:
        cmd.insert(-1, "-oN") # Salida txt a output
        cmd.insert(-1, raw_output_path)

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if p.returncode != 0:
        log(f"ERROR nmap: {p.stderr.strip()}")
        print("nmap error output:", p.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    return p.stdout

def parse_nmap_xml(xml_text):
    hosts = []
    root = ET.fromstring(xml_text)
    
    for host in root.findall("host"):
        # --- Datos básicos (Existente) ---
        addr_ipv4 = None
        addr_mac = None
        vendor = None
        hostname = None
        
        status = host.find("status")
        state = status.get("state") if status is not None else None

        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                addr_ipv4 = addr.get("addr")
            elif atype == "mac":
                addr_mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            h = hostnames.find("hostname")
            if h is not None:
                hostname = h.get("name")
        
        # --- NUEVO: Extracción de Fingerprints (OS y Puertos) ---
        
        # 1. OS Detection
        os_list = []
        os_tree = host.find("os")
        if os_tree is not None:
            for osmatch in os_tree.findall("osmatch"):
                os_list.append({
                    "name": osmatch.get("name"),
                    "accuracy": int(osmatch.get("accuracy") or 0)
                })
        
        # 2. Ports & Services
        ports_list = []
        ports_tree = host.find("ports")
        if ports_tree is not None:
            for port in ports_tree.findall("port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                
                # Estado del puerto (open, closed, filtered)
                p_state = port.find("state")
                state_val = p_state.get("state") if p_state is not None else "unknown"
                
                # Si no está abierto, a veces no nos interesa para fingerprinting, 
                # pero guardémoslo si Nmap lo reporta explícitamente.
                if state_val != "open":
                    continue

                service = port.find("service")
                service_name = service.get("name") if service is not None else None
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                
                ports_list.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        hosts.append({
            "ip": addr_ipv4,
            "mac": addr_mac,
            "vendor": vendor,
            "hostname": hostname,
            "state": state,
            "os_match": os_list,    # Nuevo campo
            "ports": ports_list     # Nuevo campo
        })
    return hosts

def save_fingerprints(cur, device_id, scan_id, host_data):
    """Guarda los datos de OS y Puertos en las tablas fingerprint_*."""
    
    # Guardar OS (Tomamos el de mayor accuracy si hay varios)
    if host_data["os_match"]:
        best_os = max(host_data["os_match"], key=lambda x: x["accuracy"])
        cur.execute("""
            INSERT INTO fingerprint_os (device_id, scan_id, os_name, os_accuracy)
            VALUES (?, ?, ?, ?)
        """, (device_id, scan_id, best_os["name"], best_os["accuracy"]))

    # Guardar Puertos
    for p in host_data["ports"]:
        cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service, product, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (device_id, scan_id, p["port"], p["protocol"], p["service"], p["product"], p["version"]))

def init_db(conn):
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS known_ips (
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        ip TEXT UNIQUE NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        appearings INTEGER DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS known_macs (
        id INTEGER PRIMARY KEY,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        mac TEXT UNIQUE NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        appearings INTEGER DEFAULT 0
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY,
        hostname TEXT,
        first_seen TEXT,
        last_seen TEXT,
        appearings INTEGER DEFAULT 0,
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

def record_seen_ip(cur, ip: str, device_id: Optional[int], scanned_at: str) -> int:
    """Registra o actualiza una IP en known_ips, asignando device si es conocido."""
    cur.execute("SELECT id, device_id FROM known_ips WHERE ip = ?", (ip,))
    row = cur.fetchone()

    if row:
        ip_id, existing_dev = row
        cur.execute("""
            UPDATE known_ips
            SET last_seen = ?, appearings = appearings + 1
            WHERE id = ?
        """, (scanned_at, ip_id))

        # --- CORRECCIÓN AQUÍ ---
        # Antes: if device_id and existing_dev is None:
        # Ahora: Si traemos un device_id nuevo y es distinto al que había (o no había nada), actualizamos.
        if device_id and (existing_dev is None or existing_dev != device_id):
            cur.execute("UPDATE known_ips SET device_id = ? WHERE id = ?", (device_id, ip_id))
        # -----------------------

        return ip_id

    # Insert new (esto sigue igual)
    cur.execute("""
        INSERT INTO known_ips (ip, device_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
    """, (ip, device_id, scanned_at, scanned_at))
    return cur.lastrowid

def record_seen_mac(cur, mac: str, device_id: Optional[int], scanned_at: str) -> int:
    """Registra o actualiza una MAC en known_macs, asignando device si es conocido."""
    cur.execute("SELECT id, device_id FROM known_macs WHERE mac = ?", (mac,))
    row = cur.fetchone()

    if row:
        mac_id, existing_dev = row
        cur.execute("""
            UPDATE known_macs
            SET last_seen = ?, appearings = appearings + 1
            WHERE id = ?
        """, (scanned_at, mac_id))

        if device_id and (existing_dev is None or existing_dev != device_id):
            cur.execute("UPDATE known_macs SET device_id = ? WHERE id = ?", (device_id, mac_id))
        return mac_id

    # Insert new
    cur.execute("""
        INSERT INTO known_macs (mac, device_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
    """, (mac, device_id, scanned_at, scanned_at))
    return cur.lastrowid

def ensure_known_ip(cur, ip: Optional[str], scanned_at: str, device_id: Optional[int] = None) -> Optional[int]:
    """Devuelve id de known_ips, creando registro si no existe."""
    if not ip:
        return None
    cur.execute("SELECT id FROM known_ips WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row:
        return row[0]

    # Insert new
    cur.execute("""
        INSERT INTO known_ips (ip, device_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
    """, (ip, device_id, scanned_at, scanned_at))
    return cur.lastrowid

def resolve_device_id(cur, mac: Optional[str], ip: Optional[str]) -> Optional[int]:
    """Devuelve el device_id asociado a MAC o IP conocida, priorizando MAC."""
    if mac:
        cur.execute("SELECT device_id FROM known_macs WHERE mac = ?", (mac,))
        row = cur.fetchone()
        if row and row[0] is not None:
            return row[0]

    if ip:
        cur.execute("SELECT device_id FROM known_ips WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row and row[0] is not None:
            return row[0]

    return None

def resolve_device_by_fingerprint(cur, current_ports: list) -> Optional[int]:
    """
    Intenta identificar un dispositivo comparando sus puertos abiertos actuales
    con la última configuración conocida de todos los dispositivos en la DB.
    
    Retorna device_id si hay una coincidencia fuerte, o None.
    """
    if not current_ports:
        return None # Si no hay puertos abiertos, no podemos huellas digitales (muy arriesgado)

    # Creamos una "firma" del dispositivo actual: Set de cadenas "puerto/proto"
    # Ejemplo: {"80/tcp", "22/tcp"}
    current_signature = set(f"{p['port']}/{p['protocol']}" for p in current_ports)

    # Obtenemos el listado de dispositivos y sus últimos scan_id
    # (Optimización: Podríamos limitar esto a dispositivos vistos en los últimos 30 días)
    cur.execute("SELECT id FROM devices")
    candidates = cur.fetchall()

    best_match_id = None
    
    for (cand_id,) in candidates:
        # Buscamos el ÚLTIMO escaneo de este candidato que tuviera puertos registrados
        cur.execute("""
            SELECT port, prot 
            FROM fingerprint_ports 
            WHERE device_id = ? 
            ORDER BY scan_id DESC
        """, (cand_id,))
        
        rows = cur.fetchall()
        if not rows:
            continue

        # Reconstruimos la firma histórica de este candidato
        # Nota: Como la query trae TODOS los puertos históricos ordenados por scan,
        # debemos filtrar solo los del último scan_id encontrado.
        # Para simplificar la query anterior (que es un poco naive), hacemos algo mejor:
        
        # 1. Obtener el último scan_id con datos para este dispositivo
        cur.execute("""
            SELECT MAX(scan_id) FROM fingerprint_ports WHERE device_id = ?
        """, (cand_id,))
        last_scan_row = cur.fetchone()
        if not last_scan_row or last_scan_row[0] is None:
            continue
        
        last_scan_id = last_scan_row[0]
        
        # 2. Traer puertos de ese scan
        cur.execute("""
            SELECT port, prot FROM fingerprint_ports 
            WHERE device_id = ? AND scan_id = ?
        """, (cand_id, last_scan_id))
        
        cand_ports = cur.fetchall()
        candidate_signature = set(f"{row[0]}/{row[1]}" for row in cand_ports)
        
        # COMPARACIÓN: Jaccard Index o Igualdad Estricta
        # Si los sets son idénticos, es nuestro candidato.
        if current_signature == candidate_signature:
            # ¡MATCH ENCONTRADO!
            # Validamos que sea una firma "fuerte" (no solo puerto 80, que lo tienen todos)
            # Si tiene más de 2 puertos o puertos poco comunes, confiamos.
            if len(current_signature) >= 2 or ("80/tcp" not in current_signature): 
                 return cand_id

    return None

def main():
    global DB_PATH, LOG_PATH

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", help="Directorio para guardar devices.db (Default: ./data)")
    parser.add_argument("--log-dir", help="Directorio para guardar tracker.log (Default: ./logs)")
    parser.add_argument("--force-subnet", help="Forzar subnet, ej: 192.168.1.0/24")
    args = parser.parse_args()
    
    base_path = os.path.dirname(os.path.abspath(__file__))

    # Configuración de Rutas
    if args.data_dir:
        data_dir = os.path.abspath(args.data_dir)
    else:
        data_dir = os.path.join(base_path, "data")

    if args.log_dir:
        log_dir = os.path.abspath(args.log_dir)
    else:
        log_dir = os.path.join(base_path, "logs")

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    
    DB_PATH = os.path.join(data_dir, "devices.db")
    LOG_PATH = os.path.join(log_dir, "tracker.log")
    

    scans_dir = os.path.join(base_path, "scans")
    os.makedirs(scans_dir, exist_ok=True)
    
    # Nombre del archivo: scan_YYYY-MM-DD_HH-MM-SS.txt
    timestamp_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    raw_scan_file = os.path.join(log_dir, f"scan_{timestamp_filename}.txt")
    # ---------------------------------------------------

    subnet = args.force_subnet or FORCE_SUBNET or detect_subnet()


    subnet = args.force_subnet or FORCE_SUBNET or detect_subnet()
    if not subnet:
        log("ERROR: Subred no detectada")
        print("ERROR: Subred no detectada. Usa --force-subnet o revisa tu conexión.", file=sys.stderr)
        sys.exit(1)

    log(f"Starting scan for subnet {subnet}")
    print(f"Scanning {subnet}...")
    print(f"DB: {DB_PATH}")
    print(f"Raw Output: {raw_scan_file}")
    # Ejecución
    xml = run_nmap(subnet, raw_output_path=raw_scan_file)
    hosts = parse_nmap_xml(xml)

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    cur = conn.cursor()

    scanned_at = now_iso()
    cur.execute("INSERT INTO scans (scanned_at) VALUES (?)", (scanned_at,))
    scan_id = cur.lastrowid

    seen = set()
    new_devices = []
    known_devices = []

    for h in hosts:
        ip = h["ip"]
        mac = h["mac"]
        vendor = h["vendor"]
        hostname = h["hostname"]
        
        # 1. Intentar resolver identidad (MAC -> IP)
        device_id = resolve_device_id(cur, mac, ip)
        
        # 2. Fallback a Fingerprinting (Heurística)
        heuristic_msg = ""
        if device_id is None and h["ports"]:
            found_by_fp = resolve_device_by_fingerprint(cur, h["ports"])
            if found_by_fp:
                device_id = found_by_fp
                heuristic_msg = "(Heuristic Match via Ports)"
                log(f"HEURÍSTICA: {ip} identificado como ID {device_id}")

        # --- LÓGICA RESTAURADA ---
        if device_id is None:
            # Es un dispositivo totalmente nuevo
            cur.execute("""
                INSERT INTO devices (hostname, first_seen, last_seen, appearings)
                VALUES (?, ?, ?, ?)
            """, (hostname, scanned_at, scanned_at, 1))
            device_id = cur.lastrowid
            new_devices.append(device_id)
        else:
            # Es un dispositivo conocido
            cur.execute("""
                UPDATE devices
                SET hostname = COALESCE(?, hostname),
                    last_seen = ?,
                    appearings = appearings + 1
                WHERE id = ?
            """, (hostname, scanned_at, device_id))
            known_devices.append(device_id)

        # Actualizar historiales de IP y MAC
        if ip:
            record_seen_ip(cur, ip, device_id, scanned_at)
        if mac:
            record_seen_mac(cur, mac, device_id, scanned_at)

        # Registrar el avistamiento (sighting)
        cur.execute("""
            INSERT INTO sightings (scan_id, device_id, ip, mac, vendor, hostname, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, device_id, ip, mac, vendor, hostname, scanned_at))

        # Guardar Fingerprints (Puertos y OS) vinculados al device_id
        save_fingerprints(cur, device_id, scan_id, h)
        # -------------------------

        seen.add(device_id)
        log(f"Processed: {ip} | MAC: {mac} | ID: {device_id} {heuristic_msg}")

    conn.commit()

    # Detectar dispositivos que no aparecieron
    cur.execute("SELECT id, last_seen FROM devices")
    all_devs = cur.fetchall()
    disappeared = [d[0] for d in all_devs if d[0] not in seen and d[1] < scanned_at]

    summary = f"Scan finished: {len(hosts)} hosts found. New: {len(new_devices)}. Known: {len(known_devices)}. Disappeared: {len(disappeared)}."
    log(summary)
    print(summary)

    conn.close()

if __name__ == "__main__":
    main()

