print('Mini SOC Analyzer iniciado')
# soc_analyzer.py
eventos = [
    {"timestamp":"2025-03-10 09:00:10","ip":"192.168.1.10","usuario":"admin","evento":"login","status":"sucesso","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:01:12","ip":"192.168.1.15","usuario":"admin","evento":"login","status":"falha","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:01:15","ip":"192.168.1.15","usuario":"admin","evento":"login","status":"falha","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:01:17","ip":"192.168.1.15","usuario":"admin","evento":"login","status":"falha","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:02:03","ip":"10.0.0.25","usuario":"-","evento":"scan_porta","status":"detectado","porta":80,"servico":"http"},
    {"timestamp":"2025-03-10 09:02:05","ip":"10.0.0.25","usuario":"-","evento":"scan_porta","status":"detectado","porta":443,"servico":"https"},
    {"timestamp":"2025-03-10 09:03:20","ip":"172.16.0.5","usuario":"maria","evento":"login","status":"sucesso","porta":443,"servico":"webapp"},
    {"timestamp":"2025-03-10 09:04:33","ip":"8.8.8.8","usuario":"-","evento":"acesso_externo","status":"permitido","porta":80,"servico":"web"},
    {"timestamp":"2025-03-10 09:05:10","ip":"192.168.1.20","usuario":"joao","evento":"login","status":"falha","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:05:12","ip":"192.168.1.20","usuario":"joao","evento":"login","status":"falha","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:05:14","ip":"192.168.1.20","usuario":"joao","evento":"login","status":"sucesso","porta":22,"servico":"ssh"},
    {"timestamp":"2025-03-10 09:06:50","ip":"203.0.113.50","usuario":"-","evento":"scan_porta","status":"detectado","porta":21,"servico":"ftp"},
    {"timestamp":"2025-03-10 09:07:01","ip":"203.0.113.50","usuario":"-","evento":"scan_porta","status":"detectado","porta":22,"servico":"ssh"}
]

def contar_eventos(lista_eventos):
    contagem = {}
    for e in lista_eventos:
        if e["evento"] == "login":
            tipo_evento = f"{e['evento']}_{e['status']}"
        else:
            tipo_evento = e["evento"]
        contagem[tipo_evento] = contagem.get(tipo_evento, 0) + 1
    return contagem

def identificar_bruteforce(lista_eventos):
    falhas_por_ip = {}
    for e in lista_eventos:
        if e["evento"] == "login" and e["status"] == "falha":
            ip = e["ip"]
            falhas_por_ip[ip] = falhas_por_ip.get(ip, 0) + 1
            
    # Corrigido "em" para "in" aqui:
    ips_bruteforce = [ip for ip, qtd in falhas_por_ip.items() if qtd >= 3]
    return ips_bruteforce

def identificar_scanners(lista_eventos):
    scans_por_ip = {}
    for e in lista_eventos:
        if e["evento"] == "scan_porta":
            ip = e["ip"]
            scans_por_ip[ip] = scans_por_ip.get(ip, 0) + 1
            
    # Corrigido "em" para "in" aqui:
    ips_scanners = [ip for ip, qtd in scans_por_ip.items() if qtd >= 2]
    return ips_scanners

def listar_ips_unicos(lista_eventos):
    ips = set()
    for e in lista_eventos:
        ips.add(e["ip"])
    return list(ips)

def classificar_risco(ip, bruteforce_ips, scanner_ips):
    if ip in bruteforce_ips:
        return "[ALTO RISCO - Brute Force]"
    elif ip in scanner_ips:
        return "[MÉDIO RISCO - Scanner]"
    else:
        return "[BAIXO RISCO]"

def gerar_relatorio(lista_eventos):
    total_eventos = len(lista_eventos)
    resumo_tipos = contar_eventos(lista_eventos)
    ips_unicos = listar_ips_unicos(lista_eventos)
    bruteforce = identificar_bruteforce(lista_eventos)
    scanners = identificar_scanners(lista_eventos)

    print("\n=== MINI SOC ANALYZER ===")
    print(f"Total de eventos analisados: {total_eventos}\n")
    
    print("Resumo por tipo:")
    for tipo, quantidade in resumo_tipos.items():
        print(f"  - {tipo}: {quantidade}")
        
    print("\nIPs únicos monitorados:")
    for ip in ips_unicos:
        risco = classificar_risco(ip, bruteforce, scanners)
        print(f"  {ip} {risco}")
        
    print("\nPossível brute force:")
    if bruteforce:
        for ip in bruteforce:
            print(f"  -> {ip}")
    else:
        print("  Nenhum detectado.")
        
    print("\nPossível scanner:")
    if scanners:
        for ip in scanners:
            print(f"  -> {ip}")
    else:
        print("  Nenhum detectado.")
    print("=========================\n")

if __name__ == "__main__":
    gerar_relatorio(eventos)