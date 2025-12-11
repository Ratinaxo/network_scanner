#!/usr/bin/python3
import sys
import argparse
import os
import datetime

# 1. Importamos config (Esto YA carga .env, calcula rutas y crea carpetas)
import config
import src.utils as utils

# Capas del Sistema
from src.infrastructure.active_scanner import NmapError, NmapScanner
from src.infrastructure.nmap_parser import parse_xml
from src.database.connection import DatabaseManager
from src.database.repository import DeviceRepository
from src.analysis import heuristics, classifier

def main():
    # 2. Configuración de Argumentos (Solo para overrides opcionales)
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", help="Sobrescribir directorio de datos")
    parser.add_argument("--log-dir", help="Sobrescribir directorio de logs")
    parser.add_argument("--force-subnet", help="Sobrescribir subred a escanear")
    args = parser.parse_args()
    
    # 3. Aplicar Overrides (Si el usuario los pidió por CLI)
    # Nota: Modificamos las variables de config directamente
    if args.data_dir:
        config.DATA_DIR = os.path.abspath(args.data_dir)
        # Recalculamos la ruta del archivo DB
        config.DB_PATH = os.path.join(config.DATA_DIR, config.DB_FILENAME)
        os.makedirs(config.DATA_DIR, exist_ok=True)

    if args.log_dir:
        config.LOGS_DIR = os.path.abspath(args.log_dir)
        # Recalculamos la ruta del archivo Log (CORREGIDO)
        config.SCANNER_LOG_PATH = os.path.join(config.LOGS_DIR, config.SCANNER_LOG_FILENAME)
        # Nota: SNIFFER_LOG_PATH también se debería actualizar si ambos usan el mismo dir
        config.SNIFFER_LOG_PATH = os.path.join(config.LOGS_DIR, config.SNIFFER_LOG_FILENAME)
        os.makedirs(config.LOGS_DIR, exist_ok=True)

    if args.force_subnet:
        config.FORCE_SUBNET = args.force_subnet

    # 4. Inicialización de la Base de Datos
    try:
        db_manager = DatabaseManager(config.DB_PATH)
        db_manager.initialize_schema()
    except Exception as e:
        utils.log(f"CRITICAL DB ERROR: {e}")
        print(f"Error inicializando DB en {config.DB_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    # 5. Detección de Red
    subnet = config.FORCE_SUBNET or utils.detect_subnet()
    if not subnet:
        utils.log("ERROR: Subred no detectada")
        print("ERROR: Subred no detectada. Revisa .env o usa --force-subnet.", file=sys.stderr)
        sys.exit(1)

    utils.log(f"Starting scan for subnet {subnet}")
    print(f"Scanning {subnet}...")
    print(f"DB: {config.DB_PATH}")

    # 6. Ejecución de Infraestructura
    timestamp_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # Usamos config.SCANS_DIR que ya viene limpio desde config.py
    raw_scan_file = os.path.join(config.SCANS_DIR, f"scan_{timestamp_filename}.txt")

    try:
        scanner = NmapScanner()
        xml_output = scanner.scan(subnet, raw_output_path=raw_scan_file)
        hosts_data = parse_xml(xml_output)
    except NmapError as e:
        utils.log(f"ERROR LAUNCHING NMAP: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # 7. Procesamiento y Persistencia
    with db_manager.get_connection() as conn:
        repo = DeviceRepository(conn)

        scanned_at = utils.now_iso()
        scan_id = repo.create_scan(scanned_at)

        seen_ids = set()
        count_new = 0
        count_known = 0

        for host in hosts_data:
            # A. Identidad
            device_id = repo.resolve_device_id(host['mac'], host['ip'])
            
            heuristic_log = ""
            if not device_id and host['ports']:
                device_id = heuristics.match_fingerprint(repo, host['ports'])
                if device_id:
                    heuristic_log = "(Heuristic Match)"
                    utils.log(f"HEURÍSTICA: {host['ip']} identificado como ID {device_id}")

            # B. Gestión
            if not device_id:
                device_id = repo.create_device(host['hostname'], scanned_at)
                count_new += 1
            else:
                repo.update_device(device_id, host['hostname'], scanned_at)
                count_known += 1

            # C. Evidencia
            if host['ip']: repo.record_ip(host['ip'], device_id, scanned_at)
            if host['mac']: repo.record_mac(host['mac'], device_id, scanned_at)
            
            repo.record_sighting(scan_id, device_id, host, scanned_at)
            
            # D. Fingerprints (Activos)
            repo.save_active_fingerprints(device_id, scan_id, host) 
            repo.save_scripts_data(device_id, scan_id, host)
            
            # E. Clasificación (Usa datos activos + pasivos acumulados)
            new_type = classifier.determine_type(repo, device_id)
            if new_type != "unknown":
                repo.update_device_type(device_id, new_type)

            seen_ids.add(device_id)
            utils.log(f"Processed: {host['ip']} | ID: {device_id} | Type: {new_type} {heuristic_log}")

        # 8. Cierre
        conn.commit()
        
        disappeared = repo.get_disappeared_devices(seen_ids, scanned_at)
        
        summary = (f"Scan finished. Hosts: {len(hosts_data)}. "
                   f"New: {count_new}. Known: {count_known}. Disappeared: {len(disappeared)}.")
        utils.log(summary)
        print(summary)

if __name__ == "__main__":
    main()