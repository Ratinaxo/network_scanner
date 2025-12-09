def determine_type(repo, device_id: int) -> str:
    """
    Determina el tipo de dispositivo usando un enfoque de 'Embudo de Especificidad'.
    Orden: Hostname -> Puertos Específicos -> OS Específico -> Vendor -> Genérico.
    """
    
    # 1. Obtenemos datos limpios desde el Repo
    data = repo.get_device_details(device_id)
    
    os_name = data["os"]
    open_ports = data["ports"]
    banners = data["banners"]
    vendor = data["vendor"]
    hostname = data["hostname"]

    # --- REGLA 1: EVIDENCIA EN EL HOSTNAME (Muy fuerte) ---
    if "iphone" in hostname: return "mobile_ios"
    if "ipad" in hostname: return "tablet_ios"
    if "android" in hostname: return "android_device"
    if "tv" in hostname or "bravia" in hostname: return "smart_tv"
    if "ps5" in hostname or "xbox" in hostname: return "gaming_console"
    if "printer" in hostname: return "printer"

    # --- REGLA 2: SERVICIOS INEQUÍVOCOS (Puertos y Banners) ---
    # Impresoras
    if 9100 in open_ports or 631 in open_ports or "jetdirect" in banners:
        return "printer"
    
    # IoT / Streaming (Antes que Linux genérico)
    if "castv2" in banners or "chromecast" in banners or 8009 in open_ports:
        return "smart_tv_stick"
    if "alexa" in banners or "sonos" in banners:
        return "audio_device"
    if "homepod" in banners or "airplay" in banners:
        return "audio_device"
    
    # NAS (Storage)
    if "synology" in banners or "qnap" in banners or 548 in open_ports:
        return "nas"

    # --- REGLA 3: INFRAESTRUCTURA DE RED ---
    # Routers (Regla mejorada)
    # Si tiene DNS (53) y Web (80/443), es router.
    if 53 in open_ports and (80 in open_ports or 443 in open_ports):
        return "router"
    if "openwrt" in os_name or "pfsense" in os_name:
        return "router"
    if "wap" in os_name:
        return "access_point"

    # --- REGLA 4: SISTEMAS OPERATIVOS (De específico a general) ---
    # Windows
    if "windows" in os_name:
        if "server" in os_name or 389 in open_ports: # LDAP port
            return "server_windows"
        return "pc_windows"
    
    # Apple (No iOS)
    if "macos" in os_name or "osx" in os_name or "macbook" in hostname:
        return "mac_computer"
    
    # Móviles (Si Nmap detectó el OS)
    if "ios" in os_name: return "mobile_ios"
    if "android" in os_name: return "android_device" # Tablets/Phones

    # Linux Genérico (El "basurero" de categorías)
    if "linux" in os_name:
        # Intentamos refinar Linux
        if 22 in open_ports and 80 in open_ports: return "server_linux"
        if 22 in open_ports: return "linux_device" # Probablemente un server o RPi
        return "linux_device" # Default Linux

    # --- REGLA 5: VENDOR (Último recurso) ---
    if "apple" in vendor: return "apple_device"
    if "espressif" in vendor: return "esp_iot"
    if "raspberry" in vendor: return "raspberry_pi"
    if "nintendo" in vendor: return "gaming_console"
    if "samsung" in vendor or "lg" in vendor: return "smart_device"

    return "unknown"