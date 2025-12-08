import unittest
import sqlite3
import os
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

# Importamos tu script como un módulo
import network_tracker

class TestNetworkScanner(unittest.TestCase):

    def setUp(self):
        """Se ejecuta antes de cada test. Crea una DB en memoria."""
        self.conn = sqlite3.connect(":memory:")
        # Inicializamos el esquema usando tu función
        network_tracker.init_db(self.conn)
        self.cur = self.conn.cursor()

    def tearDown(self):
        """Se ejecuta después de cada test."""
        self.conn.close()

    # ----------------------------------------------------------------
    # 1. PRUEBA DE PARSEO XML (Fundamental para nmap)
    # ----------------------------------------------------------------
    def test_parse_nmap_xml(self):
        """Verifica que el XML se convierta correctamente en una lista de diccionarios."""
        network_tracker.DB_PATH
        # XML simulado de Nmap
        dummy_xml = """
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
                <hostnames>
                    <hostname name="server-prueba" type="user"/>
                </hostnames>
            </host>
            <host>
                <status state="down"/>
                <address addr="192.168.1.11" addrtype="ipv4"/>
            </host>
        </nmaprun>
        """
        
        hosts = network_tracker.parse_nmap_xml(dummy_xml)
        
        # Verificaciones
        self.assertEqual(len(hosts), 2)
        
        # Host 1 (Up)
        h1 = hosts[0]
        self.assertEqual(h1['ip'], "192.168.1.10")
        self.assertEqual(h1['mac'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(h1['hostname'], "server-prueba")
        self.assertEqual(h1['vendor'], "TestVendor")
        self.assertEqual(h1['state'], "up")

        # Host 2 (Down - sin mac)
        h2 = hosts[1]
        self.assertEqual(h2['ip'], "192.168.1.11")
        self.assertIsNone(h2['mac'])

    # ----------------------------------------------------------------
    # 2. PRUEBA DE DETECCIÓN DE SUBNET
    # ----------------------------------------------------------------
    @patch('subprocess.check_output')
    def test_detect_subnet_success(self, mock_subprocess):
        """Simula una respuesta exitosa de 'ip route'."""
        # Simulamos la salida del comando de linux
        mock_subprocess.return_value = "1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.45 uid 1000"
        
        subnet = network_tracker.detect_subnet()
        self.assertEqual(subnet, "192.168.1.0/24")

    @patch('subprocess.check_output')
    def test_detect_subnet_failure(self, mock_subprocess):
        """Simula un fallo o salida inesperada."""
        mock_subprocess.side_effect = Exception("Command failed")
        subnet = network_tracker.detect_subnet()
        self.assertIsNone(subnet)

    # ----------------------------------------------------------------
    # 3. PRUEBA DE LÓGICA DE BASE DE DATOS (Identity Resolution)
    # ----------------------------------------------------------------
    def test_resolve_device_new(self):
        """Si no existe IP ni MAC, debe devolver None (es un dispositivo nuevo)."""
        dev_id = network_tracker.resolve_device_id(self.cur, "AA:AA:AA:AA:AA:AA", "10.0.0.1")
        self.assertIsNone(dev_id)

    def test_record_and_resolve_flow(self):
        """Flujo completo: Crear dispositivo -> Registrar IP/MAC -> Verificar resolución."""
        
        # 1. Crear manualmente un dispositivo en la tabla devices
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('my-ipad')")
        device_id_created = self.cur.lastrowid
        
        mac_fake = "11:22:33:44:55:66"
        ip_fake = "192.168.1.100"
        scanned_at = "2023-01-01T12:00:00Z"

        # 2. Asociar MAC e IP a ese dispositivo usando tus funciones
        network_tracker.record_seen_mac(self.cur, mac_fake, device_id_created, scanned_at)
        network_tracker.record_seen_ip(self.cur, ip_fake, device_id_created, scanned_at)

        # 3. Probar resolución por MAC (Prioridad)
        resolved_id = network_tracker.resolve_device_id(self.cur, mac_fake, "0.0.0.0")
        self.assertEqual(resolved_id, device_id_created, "Debería resolver por MAC conocida")

        # 4. Probar resolución por IP (si la MAC cambia o viene vacía)
        resolved_id_ip = network_tracker.resolve_device_id(self.cur, None, ip_fake)
        self.assertEqual(resolved_id_ip, device_id_created, "Debería resolver por IP conocida")

    def test_ip_mobility(self):
        """Verifica qué pasa si una IP conocida cambia de dueño (DHCP lease change)."""
        # Dispositivo A
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('Device A')")
        dev_a = self.cur.lastrowid
        network_tracker.record_seen_ip(self.cur, "192.168.1.50", dev_a, "2023-01-01")

        # Dispositivo B (Ahora toma la IP .50)
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('Device B')")
        dev_b = self.cur.lastrowid
        
        # La función record_seen_ip tiene lógica para actualizar el device_id si ya existe la IP?
        # Revisando tu código: 'UPDATE known_ips SET device_id = ?' ocurre si 'device_id and existing_dev is None'.
        # TU LÓGICA ACTUAL NO CAMBIA EL DUEÑO SI YA TIENE UNO. Esto es un comportamiento que el test revelará.
        
        # Forzamos update simulando la lógica que esperaríamos
        # Forzamos update simulando la lógica que esperaríamos
        network_tracker.record_seen_ip(self.cur, "192.168.1.50", dev_b, "2023-01-02")
        
        self.cur.execute("SELECT device_id FROM known_ips WHERE ip='192.168.1.50'")
        owner = self.cur.fetchone()[0]
        
        # AHORA CAMBIAMOS ESTO: Queremos que sea dev_b
        self.assertEqual(owner, dev_b, "El dueño de la IP debería actualizarse si cambia el dispositivo")
    
    # ----------------------------------------------------------------
    # 4. PRUEBA DE PARSEO AVANZADO (Fingerprint Parsing)
    # ----------------------------------------------------------------
    def test_parse_nmap_xml_with_fingerprints(self):
        """Verifica la extracción de OS y puertos abiertos (state=open) y el filtrado."""
        
        # XML simulado, ahora incluyendo OS y detalles de puertos (80 abierto, 23 cerrado)
        dummy_xml = """
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <address addr="AA:AA:AA:AA:AA:AA" addrtype="mac"/>
                <hostnames><hostname name="test-server"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack"/>
                        <service name="http" product="Apache httpd" version="2.4.29"/>
                    </port>
                    <port protocol="tcp" portid="23">
                        <state state="closed" reason="reset"/>
                        <service name="telnet"/>
                    </port>
                    <port protocol="udp" portid="161">
                        <state state="open" reason="udp-response"/>
                        <service name="snmp"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Linux 4.x" accuracy="98"/>
                    <osmatch name="Linux 3.x" accuracy="95"/>
                </os>
            </host>
        </nmaprun>
        """
        
        hosts = network_tracker.parse_nmap_xml(dummy_xml)
        self.assertEqual(len(hosts), 1)
        h = hosts[0]

        # Verificación de OS
        self.assertEqual(len(h['os_match']), 2)
        self.assertEqual(h['os_match'][0]['name'], "Linux 4.x")
        self.assertEqual(h['os_match'][0]['accuracy'], 98)

        # Verificación de Puertos (solo debe incluir los abiertos)
        self.assertEqual(len(h['ports']), 2) # 80/tcp y 161/udp (el 23 es cerrado y se filtra)
        
        # Puerto 80
        p80 = next((p for p in h['ports'] if p['port'] == "80"), None)
        self.assertIsNotNone(p80)
        self.assertEqual(p80['service'], "http")
        self.assertEqual(p80['product'], "Apache httpd")
        
        # Puerto 161
        p161 = next((p for p in h['ports'] if p['port'] == "161"), None)
        self.assertIsNotNone(p161)
        self.assertEqual(p161['protocol'], "udp")

    # ----------------------------------------------------------------
    # 5. PRUEBA DE HEURÍSTICA DE FINGERPRINTING (resolve_device_by_fingerprint)
    # ----------------------------------------------------------------
    def test_resolve_by_fingerprint_match(self):
        """Prueba una coincidencia exacta de firma de puertos."""

        # 1. SETUP: Crear Dispositivo Conocido (ID 1)
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('Server-A')")
        dev_a = self.cur.lastrowid
        scan_id_a = 1

        # 2. Registrar su huella digital histórica (22 y 80)
        # Simula la inserción que haría save_fingerprints
        self.cur.execute("INSERT INTO scans (id, scanned_at) VALUES (?, ?)", (scan_id_a, network_tracker.now_iso()))
        self.cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service)
            VALUES (?, ?, '22', 'tcp', 'ssh')
        """, (dev_a, scan_id_a, ))
        self.cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service)
            VALUES (?, ?, '80', 'tcp', 'http')
        """, (dev_a, scan_id_a, ))
        self.conn.commit()

        # 3. PRUEBA: Simular un nuevo host con la misma firma de puertos
        current_ports = [
            {'port': '22', 'protocol': 'tcp', 'service': 'ssh', 'product': None, 'version': None},
            {'port': '80', 'protocol': 'tcp', 'service': 'http', 'product': None, 'version': None},
        ]

        resolved_id = network_tracker.resolve_device_by_fingerprint(self.cur, current_ports)
        
        # Debe coincidir con el dispositivo conocido (ID 1)
        self.assertEqual(resolved_id, dev_a, "La firma idéntica (22/tcp, 80/tcp) debería resultar en el Device ID 1")


    def test_resolve_by_fingerprint_mismatch(self):
        """Prueba que no haya coincidencia si la firma es distinta."""
        
        # 1. SETUP: Crear Dispositivo Conocido (ID 1)
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('Server-A')")
        dev_a = self.cur.lastrowid
        scan_id_a = 1

        # Registrar huella digital histórica (22 y 80)
        self.cur.execute("INSERT INTO scans (id, scanned_at) VALUES (?, ?)", (scan_id_a, network_tracker.now_iso()))
        self.cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service)
            VALUES (?, ?, '22', 'tcp', 'ssh')
        """, (dev_a, scan_id_a, ))
        self.cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service)
            VALUES (?, ?, '80', 'tcp', 'http')
        """, (dev_a, scan_id_a, ))
        self.conn.commit()

        # 3. PRUEBA: Simular un nuevo host con firma DIFERENTE (solo 443)
        current_ports = [
            {'port': '443', 'protocol': 'tcp', 'service': 'https', 'product': None, 'version': None},
        ]

        resolved_id = network_tracker.resolve_device_by_fingerprint(self.cur, current_ports)
        
        # No debe coincidir, pues las firmas son distintas
        self.assertIsNone(resolved_id, "Firmas distintas (443 vs 22/80) no deben resultar en match")

    def test_resolve_by_fingerprint_insufficient_ports(self):
        """Prueba la regla de que no debe haber match si solo hay 1 puerto común (como 80)."""
        
        # 1. SETUP: Crear Dispositivo Conocido (ID 1)
        self.cur.execute("INSERT INTO devices (hostname) VALUES ('IoT-device')")
        dev_a = self.cur.lastrowid
        scan_id_a = 1

        # Registrar huella digital histórica (Solo 80)
        self.cur.execute("INSERT INTO scans (id, scanned_at) VALUES (?, ?)", (scan_id_a, network_tracker.now_iso()))
        self.cur.execute("""
            INSERT INTO fingerprint_ports (device_id, scan_id, port, prot, service)
            VALUES (?, ?, '80', 'tcp', 'http')
        """, (dev_a, scan_id_a, ))
        self.conn.commit()

        # 3. PRUEBA: Simular un nuevo host con solo el puerto 80.
        current_ports = [
            {'port': '80', 'protocol': 'tcp', 'service': 'http', 'product': None, 'version': None},
        ]

        resolved_id = network_tracker.resolve_device_by_fingerprint(self.cur, current_ports)
        
        # Según la regla de la heurística, un solo puerto común no debe generar match fuerte
        self.assertIsNone(resolved_id, "Un solo puerto común (80) es insuficiente para match fuerte.")

if __name__ == '__main__':
    unittest.main()
