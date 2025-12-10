#!/usr/bin/python3
import sys
import argparse
import os
import datetime

# Módulos de Configuración y Utilidades
import config
import src.utils as utils

# Capa de Infraestructura
from src.infrastructure.nmap_wrapper import scan
from src.infrastructure.nmap_parser import parse_nmap_xml
# Capa de Datos
from src.database.connection import get_connection, init_db
from src.database.repository import DeviceRepository

# Capa de Análisis
from src.analysis import heuristics, classifier

def main():
    # 1. Configuración de Argumentos y Rutas
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", help="Directorio para guardar devices.db")
    parser.add_argument("--log-dir", help="Directorio para guardar tracker.log")
    parser.add_argument("--force-subnet", help="Forzar subnet, ej: 192.168.1.0/24")
    args = parser.parse_args()
    
    base_path = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(args.data_dir) if args.data_dir else os.path.join(base_path, "data")
    log_dir = os.path.abspath(args.log_dir) if args.log_dir else os.path.join(base_path, "logs")
    scans_dir = os.path.join(base_path, "scans") # Carpeta dedicada a reportes raw

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(scans_dir, exist_ok=True)
    
    # Inyectar configuración global
    config.DB_PATH = os.path.join(data_dir, config.DB_FILENAME)
    config.LOG_PATH = os.path.join(log_dir, config.LOG_FILENAME)
    config.FORCE_SUBNET = args.force_subnet

    # Nombre del archivo raw para este escaneo
    timestamp_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    raw_scan_file = os.path.join(scans_dir, f"scan_{timestamp_filename}.txt")

    # 2. Detección de Red
    subnet = config.FORCE_SUBNET or utils.detect_subnet()
    if not subnet:
        utils.log("ERROR: Subred no detectada")
        print("ERROR: Subred no detectada.", file=sys.stderr)
        sys.exit(1)

    utils.log(f"Starting scan for subnet {subnet}")
    print(f"Scanning {subnet}...")
    print(f"DB: {config.DB_PATH}")

    # 3. Ejecución de Infraestructura (Nmap + Parser)
    xml_output = scan(subnet, raw_output_path=raw_scan_file)
    hosts_data = parse_nmap_xml(xml_output)

    # 4. Interacción con Capa de Datos
    # Usamos 'with' para asegurar que la conexión se cierre aunque haya errores
    with get_connection(config.DB_PATH) as conn:
        init_db(conn) # Asegurar tablas
        repo = DeviceRepository(conn) # Instanciar repositorio

        scanned_at = utils.now_iso()
        scan_id = repo.create_scan(scanned_at)

        seen_ids = set()
        count_new = 0
        count_known = 0

        for host in hosts_data:
            # A. Resolver Identidad (MAC/IP o Heurística)
            device_id = repo.resolve_device_id(host['mac'], host['ip'])
            
            heuristic_log = ""
            if not device_id and host['ports']:
                # Llamada a Capa de Análisis
                device_id = heuristics.match_fingerprint(repo, host['ports'])
                if device_id:
                    heuristic_log = "(Heuristic Match)"
                    utils.log(f"HEURÍSTICA: {host['ip']} identificado como ID {device_id}")

            # B. Gestión del Dispositivo (Crear o Actualizar)
            if not device_id:
                device_id = repo.create_device(host['hostname'], scanned_at)
                count_new += 1
            else:
                repo.update_device(device_id, host['hostname'], scanned_at)
                count_known += 1

            # C. Registrar Evidencia (IP, MAC, Sighting)
            if host['ip']:
                repo.record_ip(host['ip'], device_id, scanned_at)
            if host['mac']:
                repo.record_mac(host['mac'], device_id, scanned_at)
            
            repo.record_sighting(scan_id, device_id, host, scanned_at)
            
            # D. Guardar Fingerprints
            repo.save_fingerprints(device_id, scan_id, host)
            repo.save_scripts_data(device_id, scan_id, host)
            
            # E. Clasificación Automática (Capa de Análisis)
            # Analizamos la data recién guardada para determinar qué es
            new_type = classifier.determine_type(repo, device_id)
            if new_type != "unknown":
                repo.update_device_type(device_id, new_type)

            seen_ids.add(device_id)
            utils.log(f"Processed: {host['ip']} | ID: {device_id} | Type: {new_type} {heuristic_log}")

        # 5. Commit Final y Resumen
        conn.commit()
        
        disappeared = repo.get_disappeared_devices(seen_ids, scanned_at)
        
        summary = (f"Scan finished. Hosts: {len(hosts_data)}. "
                   f"New: {count_new}. Known: {count_known}. Disappeared: {len(disappeared)}.")
        utils.log(summary)
        print(summary)

if __name__ == "__main__":
    main()