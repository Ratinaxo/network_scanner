from typing import List, Dict, Any, Optional

def jacard_index(set1: set, set2: set) -> float:
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    if union == 0:
        return 0.0
    return intersection / union

def match_fingerprint(repo, current_ports: List[Dict[str, Any]]) -> Optional[int]:
    """
    Intenta identificar un dispositivo comparando sus puertos abiertos actuales
    con la historia en la base de datos.
    """
    if not current_ports:
        return None

    # Firma actual: {"80/tcp", "22/tcp"}
    current_signature = set(f"{p['port']}/{p['protocol']}" for p in current_ports)

    # Obtenemos todos los IDs conocidos
    candidate_ids = repo.get_all_device_ids()
   
    best_match_id = None
    highest_score = 0.0 

    for cand_id in candidate_ids:
        # Obtenemos puertos del último escaneo de este candidato usando el Repo
        cand_ports_rows = repo.get_last_scan_ports(cand_id)
        
        # cand_ports_rows viene como [(port, prot), ...]
        candidate_signature = set(f"{row[0]}/{row[1]}" for row in cand_ports_rows)

        if not current_signature:
            continue
        
        score = jacard_index(current_signature, candidate_signature)
            # Filtro de calidad
        if score > 0.6 and score > highest_score:
            highest_score = score
            best_match_id = cand_id

    return best_match_id