#!/usr/bin/env python3
"""
=============================================================================
SIMULACIÓN COMPLETA — SERVIDOR VÍCTIMA + ATAQUE RANSOMWARE
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

USO — un solo comando desde la CLI de Mininet:
    mininet> h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 python3 ataque_completo.py &

    Mininet lanza el script en los 10 hosts simultáneamente.
    Cada host detecta su propia IP y decide su rol:
      • 10.0.10.1 (h1) → espera 3s a que los servidores suban, luego ATACA
      • Cualquier otra IP  → levanta servidores TCP en puertos críticos

MÉTRICAS QUE SE DISPARAN (desde h1):
    M1 (peso 25) — flujos nuevos en puertos críticos > 20/30s  → +25
    M2 (peso 20) — destinos únicos > 8  (h2..h10 = 9 destinos) → +20
    M4 (peso 15) — Packet-In flood > 400/min                   → +15
    ─────────────────────────────────────────────────────────────────
    Puntaje total esperado: 60 → CRÍTICO ✓  (umbral ≥ 60)

PUERTOS SIMULADOS (= CRITICAL_PORTS en ryu_controller.py):
    445  → SMB       5985 → WinRM
    135  → RPC       139  → NetBIOS
    3389 → RDP
=============================================================================
"""

import socket
import threading
import time
import random
import sys
from datetime import datetime

# ─── CONFIGURACIÓN COMPARTIDA ────────────────────────────────────────────────

ATTACKER_IP    = '10.0.10.1'          # h1 siempre es el atacante
CRITICAL_PORTS = [445, 135, 3389, 139, 5985]

# Targets: h2..h10 en VLAN OPS
TARGETS = [f'10.0.10.{i}' for i in range(2, 11)]   # 9 hosts

TIMEOUT_SEC    = 0.5
INTERVAL_SEC   = 0.05    # 50 ms entre conexiones
SCAN_CYCLE_SEC = 30      # ventana de tiempo de M1/M2
TOTAL_CYCLES   = 8       # 8 × 30s ≈ 4 min de ataque
SERVER_STARTUP_SEC = 3   # segundos que espera h1 antes de atacar

# ─── UTILIDADES ──────────────────────────────────────────────────────────────

RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

_running = True

def ts():
    return datetime.now().strftime('%H:%M:%S')

def log(color, tag, msg):
    print(f'{color}[{ts()}][{tag}]{RESET} {msg}', flush=True)

def my_ip():
    """Detecta la IP del host actual (primera interfaz no-loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.0.10.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # fallback: hostname resolution
        return socket.gethostbyname(socket.gethostname())


# ═══════════════════════════════════════════════════════════════════════════════
#  ROL VÍCTIMA — levanta servidores TCP en puertos críticos
# ═══════════════════════════════════════════════════════════════════════════════

def handle_client(conn):
    """Acepta la conexión y la cierra limpiamente (simula servicio activo)."""
    try:
        conn.sendall(b'\x00\x00')
        conn.recv(256)
    except Exception:
        pass
    finally:
        conn.close()


def servidor_en_puerto(port):
    """Hilo: escucha en un puerto y acepta conexiones indefinidamente."""
    global _running
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', port))
        srv.listen(50)
        srv.settimeout(1.0)
        log(GREEN, 'SERVIDOR', f'Puerto {port} activo')
        while _running:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()
    except PermissionError:
        log(RED, 'SERVIDOR', f'Puerto {port}: sin permiso (¿falta sudo?)')
    except Exception as e:
        log(RED, 'SERVIDOR', f'Puerto {port}: {e}')


def rol_victima(ip):
    """Comportamiento de host víctima: levantar servidores y esperar."""
    print(f'\n{BOLD}[{ts()}][VÍCTIMA] {ip} — levantando {len(CRITICAL_PORTS)} servidores TCP{RESET}')
    for port in CRITICAL_PORTS:
        threading.Thread(target=servidor_en_puerto, args=(port,), daemon=True).start()
    log(GREEN, 'VÍCTIMA', f'{ip} lista — esperando conexiones del atacante...')
    # Mantener vivo hasta Ctrl+C o señal externa
    try:
        while _running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  ROL ATACANTE — movimiento lateral ransomware (M1 + M2 + M4)
# ═══════════════════════════════════════════════════════════════════════════════

def conectar(target, port):
    """Intenta una conexión TCP. Retorna True si conectó."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_SEC)
        s.connect((target, port))
        s.close()
        return True
    except Exception:
        return False


# ── M2: reconocimiento — fan-out destinos únicos ─────────────────────────────

def fase_reconocimiento():
    """
    Contacta los 9 hosts objetivo en todos los puertos críticos.
    Registra 9 destinos únicos → dispara M2 (umbral=8).
    """
    log(YELLOW, 'FASE-1', f'Reconocimiento: {len(TARGETS)} destinos × {len(CRITICAL_PORTS)} puertos')
    contactados = set()
    for target in TARGETS:
        for port in CRITICAL_PORTS:
            ok = conectar(target, port)
            estado = f'{GREEN}OK{RESET}' if ok else f'{BLUE}cerrado{RESET}'
            log(BLUE, 'PROBE', f'{target}:{port} → {estado}')
            contactados.add(target)
            time.sleep(INTERVAL_SEC)
    log(YELLOW, 'FASE-1',
        f'{len(contactados)} destinos únicos contactados '
        f'(umbral M2=8 → {"DISPARA ✓" if len(contactados) > 8 else "NO dispara ✗"})')


# ── M1: flood de conexiones en ventana de 30s ────────────────────────────────

def fase_flood(ciclo):
    """
    Flood aleatorio durante 30s para superar umbral M1=20 flujos/30s.
    """
    log(RED, f'CICLO-{ciclo}', f'Flood durante {SCAN_CYCLE_SEC}s...')
    flujos = 0
    t0 = time.time()
    while time.time() - t0 < SCAN_CYCLE_SEC:
        conectar(random.choice(TARGETS), random.choice(CRITICAL_PORTS))
        flujos += 1
        time.sleep(INTERVAL_SEC)
    dispara = flujos > 20
    log(RED, f'CICLO-{ciclo}',
        f'{flujos} flujos en {time.time()-t0:.1f}s → '
        f'M1 {"DISPARA ✓" if dispara else "no dispara ✗"}')
    return flujos


# ── M4: Packet-In flood (hilo paralelo) ──────────────────────────────────────

def hilo_packet_in_flood():
    """
    Hilo paralelo: varía el puerto de origen en cada intento para que
    cada paquete tenga una 5-tupla diferente → el switch no cachea el flujo
    → cada paquete genera Packet-In al controlador → dispara M4 (>400/min).
    """
    log(BLUE, 'M4-FLOOD', 'Iniciando (~20 pkts/s ≈ 1200 Packet-In/min)')
    while _running:
        target = random.choice(TARGETS)
        port   = random.choice(CRITICAL_PORTS)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.bind(('0.0.0.0', random.randint(49152, 65534)))
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)


def rol_atacante():
    """Comportamiento completo del host atacante (h1)."""
    global _running

    print(f'\n{BOLD}{"="*65}{RESET}')
    print(f'{BOLD}  SIMULACIÓN RANSOMWARE — MOVIMIENTO LATERAL{RESET}')
    print(f'{BOLD}  Universidad Católica de Colombia — 2026{RESET}')
    print(f'{BOLD}{"="*65}{RESET}')
    print(f'  Atacante : {ATTACKER_IP}  (h1 — VLAN OPS)')
    print(f'  Objetivos: {TARGETS[0]} .. {TARGETS[-1]}  ({len(TARGETS)} hosts)')
    print(f'  Puertos  : {CRITICAL_PORTS}')
    print(f'  Ciclos   : {TOTAL_CYCLES} × {SCAN_CYCLE_SEC}s')
    print()
    print(f'  Métricas objetivo:')
    print(f'    M1 (peso 25) flujos >20/30s      → +25')
    print(f'    M2 (peso 20) destinos únicos >8  → +20')
    print(f'    M4 (peso 15) Packet-In >400/min  → +15')
    print(f'    {"─"*38}')
    print(f'    {BOLD}Total esperado: 60 → CRÍTICO ✓{RESET}')
    print(f'{BOLD}{"="*65}{RESET}\n')

    # Esperar a que las víctimas levanten sus servidores
    log(YELLOW, 'ATACANTE', f'Esperando {SERVER_STARTUP_SEC}s a que los servidores estén listos...')
    time.sleep(SERVER_STARTUP_SEC)

    # Verificación rápida
    activos = sum(1 for t in TARGETS if conectar(t, CRITICAL_PORTS[0]))
    log(YELLOW, 'CHECK', f'{activos}/{len(TARGETS)} hosts con servidor activo en puerto {CRITICAL_PORTS[0]}')
    if activos == 0:
        log(RED, 'WARN', 'Ningún servidor detectado — el ataque puede no disparar M1/M2')

    # ── Fase 1: reconocimiento → M2 ──────────────────────────────────────────
    print(f'\n{BOLD}{"─"*65}{RESET}')
    print(f'{BOLD}  FASE 1 — RECONOCIMIENTO (M2){RESET}')
    print(f'{BOLD}{"─"*65}{RESET}')
    fase_reconocimiento()
    time.sleep(1)

    # ── Fase 3: Packet-In flood en paralelo → M4 ──────────────────────────────
    print(f'\n{BOLD}{"─"*65}{RESET}')
    print(f'{BOLD}  FASE 3 — PACKET-IN FLOOD en background (M4){RESET}')
    print(f'{BOLD}{"─"*65}{RESET}')
    threading.Thread(target=hilo_packet_in_flood, daemon=True).start()

    # ── Fase 2: ciclos de flood → M1 ─────────────────────────────────────────
    print(f'\n{BOLD}{"─"*65}{RESET}')
    print(f'{BOLD}  FASE 2 — FLOOD DE CONEXIONES en ciclos de {SCAN_CYCLE_SEC}s (M1){RESET}')
    print(f'{BOLD}{"─"*65}{RESET}')
    total = 0
    for ciclo in range(1, TOTAL_CYCLES + 1):
        print(f'\n  {YELLOW}── Ciclo {ciclo}/{TOTAL_CYCLES} ──{RESET}')
        total += fase_flood(ciclo)
        if ciclo < TOTAL_CYCLES:
            time.sleep(1)

    _running = False
    print(f'\n{BOLD}{"="*65}{RESET}')
    print(f'{BOLD}  ATAQUE COMPLETADO — {total} flujos totales{RESET}')
    print(f'{BOLD}{"="*65}{RESET}')
    print(f'  Revisa el log de Ryu para ver [CRÍTICO] puntaje ≥ 60')
    print(f'{"="*65}\n')


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT — detección automática de rol
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    ip = my_ip()
    print(f'[{ts()}] IP detectada: {ip}', flush=True)

    if ip == ATTACKER_IP:
        rol_atacante()
    else:
        rol_victima(ip)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        _running = False
        print(f'\n[{ts()}] Detenido por el usuario.')
        sys.exit(0)
