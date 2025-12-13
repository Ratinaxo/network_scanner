#!/usr/bin/python3
import sys
import argparse
import os
import datetime
import signal

# 1. Importamos config (Esto YA carga .env, calcula rutas y crea carpetas)
import config
import src.utils.utils as utils

# Capas del Sistema
from src.infrastructure.active_scanner import NmapError, NmapScanner
from src.infrastructure.nmap_parser import parse_xml
from src.database.connection import DatabaseManager
from src.database.repository import DeviceRepository
from src.analysis import heuristics, classifier

global_lock = None

def signal_handler(sig, frame):
    """Handler que se activa cuando recibe SIGTERM (pkill) o SIGINT (Ctrl+C)."""
    utils.log("STOP: Señal de detención recibida. Limpiando y saliendo...")
    print("\n[!] Deteniendo escaneo limpiamente...")
    
    if global_lock:
        global_lock.release()
        utils.log("LOCK: Candado liberado forzosamente.")
        
    sys.exit(0)

def main():
    global global_lock
    # Registramos los handlers de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 0. Adquirir Candado de Proceso
    global_lock = utils.ProcessLock()
    if not global_lock.acquire():
        utils.log("SKIP: Ya existe un escaneo en curso. Abortando ejecución duplicada.")
        print("SKIP: Ya existe un escaneo en curso.")
        sys.exit(0)


    # 2. Configuración de Argumentos (Solo para overrides opcionales)
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", help="Sobrescribir directorio de datos")
    parser.add_argument("--log-dir", help="Sobrescribir directorio de logs")
    parser.add_argument("--force-subnet", help="Sobrescribir subred a escanear")
    parser.add_argument("--deep", action="store_true", help="Ejecutar escaneo profundo y agresivo")
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
        print(f"[*] Database initialized at {config.DB_PATH}")
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
    raw_scan_file = os.path.join(config.SCANS_DIR, f"scan_{timestamp_filename}.txt")

    try:
        scanner = NmapScanner()
        if args.deep:
            # Modo profundo y agresivo
            utils.log("WARNING: Escaneo PROFUNDO activado. Esto puede tardar un rato.")
            print("WARNING: Escaneo PROFUNDO activado. Esto puede tardar un rato.")
            with db_manager.get_connection() as conn:
                repo = DeviceRepository(conn)
                targets = repo.get_active_ips(minutes=config.DEEP_SCAN_MINUTES_SEEN)

            if not targets:
                utils.log("No active IPs found for deep scan.")
                utils.log("ABORTING...")
                sys.exit(0)

            utils.log(f"TARGETS: {len(targets)} IPs seleccionadas para scan profundo.")
            xml_output = scanner.scan(targets, raw_output_path=raw_scan_file, mode="deep")
        else:
            # Modo rápido (barrido)
            xml_output = scanner.scan(subnet, raw_output_path=raw_scan_file, mode="fast")

        hosts_data = parse_xml(xml_output)

    except NmapError as e:
        err = str(e)
        if "permission denied" in err.lower():
            utils.log("ERROR: Nmap requires elevated privileges. Run as root or with sudo.")
            print("ERROR: Nmap requires elevated privileges. Run as root or with sudo.", file=sys.stderr)
            sys.exit(1)
        elif "no nmap binary found" in err.lower():
            utils.log("ERROR: Nmap binary not found. Please install Nmap.")
            print("ERROR: Nmap binary not found. Please install Nmap.", file=sys.stderr)
            sys.exit(1)
        elif "Code -15" in err or "killed" in err.lower() or "Code -9" in err:
            utils.log("SCAN STOPPED: Scan was manually stopped.")
            print("SCAN STOPPED: Scan was manually stopped.")
            sys.exit(0)
        else:
            utils.log(f"ERROR LAUNCHING NMAP: {e}")
            print(f"ERROR: {e}", file=sys.stderr)

            if global_lock: global_lock.release()
            sys.exit(1)

    # 7. Procesamiento y Persistencia
    try:
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
                classified_type, score = classifier.determine_type(repo, device_id)
                # Asumimos que un score de 2.0 o más es certeza absoluta (100%)
                confidence_percent = min(int((score / 2.0) * 100), 100)

                if classified_type != "unknown":
                    repo.update_device_type(device_id, classified_type, confidence_percent)

                # F. Marcamos si fue escaneo profundo
                if args.deep:
                    repo.mark_deep_scan(device_id, scanned_at)
                    utils.log(f"Device ID {device_id} marked as deeply scanned.")

                seen_ids.add(device_id)
                utils.log(f"Processed: {host['ip']} | ID: {device_id} | Type: {classified_type} ({confidence_percent}%) {heuristic_log}")

                
                seen_ids.add(device_id)

            # 8. Cierre
            conn.commit()
            
            disappeared = repo.get_disappeared_devices(seen_ids, scanned_at)
            
            summary = (f"Scan finished. Hosts: {len(hosts_data)}. "
                    f"New: {count_new}. Known: {count_known}. Disappeared: {len(disappeared)}.")
            utils.log(summary)
            print(summary)
    except Exception as e:
        utils.log(f"CRITICAL ERROR DURING PROCESSING: {e}")
        print(f"CRITICAL ERROR DURING PROCESSING: {e}", file=sys.stderr)
    finally:
        if global_lock:global_lock.release()
        utils.log("LOCK: Candado liberado.")

if __name__ == "__main__":
    main()