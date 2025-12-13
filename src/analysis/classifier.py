import re
from collections import defaultdict

def determine_type(repo, device_id: int) -> tuple[str, float]:
    """
    Clasifica el dispositivo basándose en un sistema de puntuación ponderada.
    Incluye una fase de 'Ajuste Fino' para desambiguar (ej: Android vs TV).
    """
    # 1. Obtener Datos
    data = repo.get_device_details(device_id)
    
    os_nmap = (data["os"] or "").lower()
    open_ports = data["ports"]
    vendor = (data["vendor"] or "").lower()
    hostname = (data["hostname"] or "").lower()
    full_text = (data["banners"] or "").lower() # Incluye TTL, DHCP sigs, Scripts output

    # Tabla de Puntuaciones
    scores = defaultdict(float)
    
    # =========================================================================
    # 1. EVIDENCIA PASIVA (SNIFFER & BANNERS)
    # =========================================================================
    
    # TTL
    if "ttl: 128" in full_text: scores['windows'] += 1.5
    elif "ttl: 64" in full_text:
        # TTL 64 es base Linux. Damos puntos base suaves.
        scores['linux_device'] += 0.2
        scores['android'] += 0.2
        scores['router'] += 0.1 # Muchos routers son Linux

    # DHCP Hostnames & Signatures
    if "android" in full_text or "galaxy" in full_text:
        scores['android'] += 1.0 # Subimos peso
    if "msft" in full_text or "desktop-" in hostname:
        scores['windows'] += 1.0

    # =========================================================================
    # 2. EVIDENCIA DE PUERTOS (FUNCIONALIDAD)
    # =========================================================================
    
    # -- ROUTERS --
    # Puerto 53 (DNS) es el rey de los routers domésticos
    if 53 in open_ports:
        scores['router'] += 1.5 
    if 80 in open_ports and 443 in open_ports and 53 in open_ports:
        scores['router'] += 1.0 # Combo breaker para routers

    # -- IMPRESORAS --
    if 9100 in open_ports or 631 in open_ports:
        scores['printer'] += 1.2

    # -- TV & CAST --
    # 8008/8009 son exclusivos de Google Cast (Android TV / Chromecast)
    if 8009 in open_ports or 8008 in open_ports: 
        scores['smart_tv_stick'] += 2.0 # Puntaje altísimo para forzar TV
        scores['android'] -= 0.5 # Bajamos Android genérico para que gane TV

    # -- CONSOLAS --
    if 3074 in open_ports: scores['game_console'] += 0.8
    
    # -- WINDOWS / MAC / SSH --
    if 3389 in open_ports: scores['windows'] += 0.8
    if 548 in open_ports: scores['mac_computer'] += 1.0
    if 62078 in open_ports: scores['apple_ios'] += 2.0
    if 22 in open_ports: scores['linux_device'] += 0.5

    # =========================================================================
    # 3. EVIDENCIA DE VENDOR (HARDWARE)
    # =========================================================================
    if "samsung" in vendor:
        scores['android'] += 0.6
        scores['smart_tv'] += 0.4
        scores['game_console'] -= 5.0 # VETO TOTAL: Samsung no hace consolas
    elif "apple" in vendor:
        scores['apple_device'] += 0.5
    elif "nintendo" in vendor:
        scores['game_console'] += 2.0
    elif "sony" in vendor:
        scores['smart_tv'] += 0.5
        scores['game_console'] += 0.5
    elif any(x in vendor for x in ['cisco', 'linksys', 'huawei', 'tp-link', 'ubiquiti', 'mikrotik', 'zte', 'arris']):
        scores['router'] += 1.2
    elif "google" in vendor and ("chromecast" in full_text or 8008 in open_ports):
        scores['smart_tv_stick'] += 1.5

    # =========================================================================
    # 4. EVIDENCIA DE HOSTNAME (REGEX MEJORADO)
    # =========================================================================
    
    # Detección de modelos Galaxy (A25, S23, etc)
    # Busca "A25", "S24" al inicio o entre guiones
    if re.search(r"(?i)\b[as]\d{2}\b", hostname) or "galaxy" in hostname:
        scores['android'] += 1.5 # Boost fuerte para tu celular

    if "gateway" in hostname: scores['router'] += 1.0
    if "tv" in hostname or "bravia" in hostname: scores['smart_tv'] += 1.2
    if "chromecast" in hostname: scores['smart_tv_stick'] += 1.5
    
    # =========================================================================
    # 5. OS DETECTADO (NMAP) - CON ESCEPTICISMO
    # =========================================================================
    # Nmap suele confundir Linux embebido con Android.
    
    if "windows" in os_nmap: scores['windows'] += 0.7
    
    if "android" in os_nmap:
        # Si Nmap dice Android, sumamos a ambos, pero dejamos que los puertos decidan
        scores['android'] += 0.6
        scores['smart_tv'] += 0.4 
        if "tv" in os_nmap: scores['smart_tv'] += 1.0

    # Falso positivo Xbox: Nmap ve puertos UPnP y grita Xbox.
    if "game console" in os_nmap or "xbox" in os_nmap:
        scores['game_console'] += 0.3 # Puntaje muy bajo, requiere confirmación de vendor o puertos
        
    # =========================================================================
    # 6. FASE DE AJUSTE FINO (DESEMPATES LÓGICOS)
    # =========================================================================
    
    # Ordenamos preliminarmente
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    if not sorted_scores: return "unknown", 0.0
    
    winner, score = sorted_scores[0]

    # REGLA MAESTRA: Desambiguación Android vs TV
    # Si el ganador es Android, pero tiene puertos de TV, forzamos TV
    if winner == "android":
        if 8008 in open_ports or 8009 in open_ports or "tv" in hostname or "chromecast" in full_text:
            return "smart_tv_stick", max(score, 1.5)
        if "smart_tv" in scores and scores['smart_tv'] > 0.8:
             # Si Smart TV estaba cerca, probablemente sea TV (las TVs reportan ser Android)
             return "smart_tv", score

    # REGLA MAESTRA: Desambiguación Linux vs Router
    # Si gana Linux/Android pero tiene puerto 53 (DNS), es un Router
    if winner in ["linux_device", "android"] and 53 in open_ports:
        return "router", max(score, 1.5)

    # REGLA MAESTRA: Limpieza Apple
    if scores['apple_device'] > 0:
        if scores['mac_computer'] > scores['apple_ios']: scores['apple_device'] = 0
        elif scores['apple_ios'] > scores['mac_computer']: scores['apple_device'] = 0
    
    # Recalculamos ganador tras ajustes
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    winner, score = sorted_scores[0]

    if score < 0.4:
        # Fallbacks por vendor si la confianza es muy baja
        if "samsung" in vendor: return "android", 0.5
        if "apple" in vendor: return "apple_device", 0.5
        return "unknown", score

    return winner, score