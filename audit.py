import sqlite3
import os

# Ajusta la ruta si es necesario
DB_PATH = "/home/ratin/Desktop/network_scanner/data/devices.db"

def run_audit():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: No se encuentra la DB en {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    print("--- AUDITORÍA DE NETWORK SCANNER ---")

    # 1. ¿Tenemos Dispositivos creados?
    c.execute("SELECT count(*) FROM devices")
    dev_count = c.fetchone()[0]
    print(f"Total Dispositivos (devices): {dev_count}")

    # 2. ¿Tenemos Avistamientos Huérfanos?
    c.execute("SELECT count(*) FROM sightings WHERE device_id IS NULL")
    orphan_sightings = c.fetchone()[0]
    c.execute("SELECT count(*) FROM sightings WHERE device_id IS NOT NULL")
    linked_sightings = c.fetchone()[0]
    print(f"Sightings vinculados: {linked_sightings}")
    print(f"Sightings HUÉRFANOS (DeviceID=None): {orphan_sightings}  <-- ESTO DEBERÍA SER 0")

    # 3. ¿Se guardaron los Fingerprints (Puertos)?
    c.execute("SELECT count(*) FROM fingerprint_ports")
    ports_count = c.fetchone()[0]
    print(f"Total Puertos detectados: {ports_count}")

    # 4. Verificación de Relación Fingerprint -> Device
    c.execute("""
        SELECT count(*) 
        FROM fingerprint_ports 
        WHERE device_id IS NULL
    """)
    orphan_ports = c.fetchone()[0]
    print(f"Puertos sin dueño (DeviceID=None): {orphan_ports} <-- ESTO DEBERÍA SER 0")

    # 5. Muestra de un fingerprint guardado (si existe)
    if ports_count > 0:
        print("\n--- Ejemplo de Fingerprint Guardado ---")
        c.execute("""
            SELECT d.hostname, p.port, p.service, p.product, p.version
            FROM fingerprint_ports p
            LEFT JOIN devices d ON p.device_id = d.id
            LIMIT 1
        """)
        row = c.fetchone()
        if row:
            print(f"Host: {row[0]} | Port: {row[1]} ({row[2]}) | Soft: {row[3]} {row[4]}")
        else:
            print("(No se pudo hacer join, verifica orphan ports)")

    conn.close()

if __name__ == "__main__":
    run_audit()
