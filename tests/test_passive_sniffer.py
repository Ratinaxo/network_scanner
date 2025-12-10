import unittest
from unittest.mock import patch, MagicMock
from scapy.all import Ether, IP, UDP, TCP, DHCP, BOOTP, DNS, DNSQR, Raw
import time

# Importamos la CLASE, no funciones sueltas
# Asegúrate de que el nombre del archivo sea 'passive_sniffer.py' (con doble 's')
from src.infrastructure.passive_sniffer import PassiveSniffer

class TestPassiveSniffer(unittest.TestCase):

    def setUp(self):
        """
        Se ejecuta antes de CADA test. 
        Aquí creamos una instancia fresca del Sniffer.
        """
        # Mockeamos el logger donde se usa (en el módulo passive_sniffer)
        self.patcher = patch('src.infrastructure.passive_sniffer.log')
        self.mock_log = self.patcher.start()
        
        # Instanciamos la clase (sin repositorio real para estos tests)
        self.sniffer = PassiveSniffer(interface="test_iface")

    def tearDown(self):
        self.patcher.stop()

    # --- TEST 1: ANÁLISIS DE TTL ---
    def test_process_ttl_new_and_change(self):
        src_ip = "192.168.1.50"
        
        # 1. Primer paquete (TTL 64 - Linux)
        pkt1 = IP(src=src_ip, dst="192.168.1.1", ttl=64)
        
        # Llamamos al método DE LA INSTANCIA (self.sniffer)
        # Accedemos a _process_ttl aunque sea 'privado' para testearlo aisladamente
        self.sniffer._process_ttl(pkt1)
        
        # Verificamos log
        self.mock_log.assert_called_with(f"PASSIVE [TTL] IP: {src_ip} | TTL: 64 (Linux/Android/iOS)")
        self.mock_log.reset_mock()

        # 2. Segundo paquete (Mismo TTL) -> No debería loguear (Caché interna de la instancia)
        self.sniffer._process_ttl(pkt1)
        self.mock_log.assert_not_called()

        # 3. Tercer paquete (Cambio de TTL a 128 - Windows)
        pkt2 = IP(src=src_ip, dst="192.168.1.1", ttl=128)
        self.sniffer._process_ttl(pkt2)
        
        # Verificamos que detectó el cambio leyendo la caché interna de la instancia
        self.mock_log.assert_called()
        args, _ = self.mock_log.call_args
        self.assertIn("TTL CHANGE", args[0])
        
        # Verificamos que el estado interno de la clase cambió
        self.assertEqual(self.sniffer.ttl_cache[src_ip], 128)

    # --- TEST 2: ANÁLISIS DE DNS Y DESDUPLICACIÓN ---
    def test_process_dns_logic(self):
        src_ip = "10.0.0.5"
        domain = "apple.com"
        
        # Construimos paquete DNS
        # Nota: Scapy a veces añade un punto al final del qname al decodificar
        dns_layer = DNS(rd=1, qr=0, qd=DNSQR(qname=domain))
        pkt = IP(src=src_ip) / UDP(sport=5353, dport=53) / dns_layer
        
        # 1. Primera consulta
        self.sniffer._process_dns(pkt)
        self.mock_log.assert_called()
        self.assertIn("Apple", self.mock_log.call_args[0][0])
        self.mock_log.reset_mock()

        # 2. Segunda consulta inmediata -> Ignorada por caché
        self.sniffer._process_dns(pkt)
        self.mock_log.assert_not_called()

        # 3. Simular paso del tiempo manipulando la caché de la INSTANCIA
        cache_key = f"{src_ip}|{domain}."
        # Forzamos que parezca que pasó hace 1 hora
        self.sniffer.dns_cache[cache_key] = time.time() - (self.sniffer.dns_cooldown + 10)
        
        self.sniffer._process_dns(pkt)
        self.mock_log.assert_called()

    # --- TEST 3: ANÁLISIS DE DHCP ---
    def test_process_dhcp_fingerprint(self):
        mac = "aa:bb:cc:dd:ee:ff"
        options = [
            ("message-type", "request"),
            ("param_req_list", [1, 3, 6]), # Firma simulada
            ("hostname", "Test-iPhone"),
            "end"
        ]
        
        pkt = Ether(src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") / \
              UDP(sport=68, dport=67) / \
              BOOTP(chaddr=b'\xaa\xbb\xcc\xdd\xee\xff') / \
              DHCP(options=options)

        self.sniffer._process_dhcp(pkt)
        
        self.mock_log.assert_called()
        log_msg = self.mock_log.call_args[0][0]
        self.assertIn("Test-iPhone", log_msg)
        self.assertIn("Sig: [1,3,6]", log_msg)

    # --- TEST 4: ANÁLISIS DE HTTP ---
    def test_process_http_ua(self):
        src_ip = "192.168.1.100"
        ua_string = "Mozilla/5.0 (TestBot)"
        # Payload HTTP crudo
        payload = f"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua_string}\r\n\r\n".encode()
        
        pkt = IP(src=src_ip) / TCP(dport=80) / Raw(load=payload)
        
        self.sniffer._process_http(pkt)
        
        self.mock_log.assert_called()
        self.assertIn(ua_string, self.mock_log.call_args[0][0])

if __name__ == '__main__':
    unittest.main()