#!/usr/bin/env python3
"""
=============================================================================
HONEYPOT DE LA VLAN 999 — PROYECTO DE GRADO
Universidad Católica de Colombia — 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  Escucha TCP en los puertos críticos, acepta cada conexión, la cierra y
  escribe una línea JSON por intento:
    {"ts", "ip_origen", "puerto_origen", "ip_destino", "puerto_destino"}

  En la topología, nft (redirect) entrega al honeypot las conexiones dirigidas
  a cualquier IP; el destino que intentó el atacante se lee con
  SO_ORIGINAL_DST. Sin NAT (por ejemplo en localhost) se usa la dirección
  local del socket.

USO:
    topology_project.py lo arranca solo en el host honeypot (con su filtro nft).
    A mano, solo si no está corriendo:  mininet> honeypot python3 honeypot.py &
    python3 honeypot.py --puertos 18445,18022 --log /tmp/prueba.jsonl

  Solo librería estándar. Termina limpio con Ctrl+C (o SIGTERM).
=============================================================================
"""

import argparse
import json
import os
import selectors
import signal
import socket
import struct
import sys
from datetime import datetime, timezone

PUERTOS_CRITICOS = (22, 135, 139, 445, 3389, 5985)
LOG_POR_DEFECTO  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'logs', 'honeypot.jsonl')
SO_ORIGINAL_DST  = 80   # linux/netfilter_ipv4.h (no está en el módulo socket)


def destino_original(conn):
    """(ip, puerto) que el cliente intentó alcanzar antes del redirect de nft."""
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        puerto, ip = struct.unpack_from('!2xH4s', raw)
        return socket.inet_ntoa(ip), puerto
    except OSError:
        return conn.getsockname()[:2]


def ts_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def abrir_escuchas(host, puertos):
    escuchas = []
    for puerto in puertos:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, puerto))
        s.listen(64)
        s.setblocking(False)
        escuchas.append(s)
    return escuchas


def _sigterm(signum, frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description='Honeypot TCP de la VLAN 999')
    parser.add_argument('--puertos', default=','.join(map(str, PUERTOS_CRITICOS)),
                        help='lista separada por comas (por defecto los críticos)')
    parser.add_argument('--log', default=LOG_POR_DEFECTO,
                        help=f'archivo JSONL (por defecto {LOG_POR_DEFECTO})')
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()

    puertos = [int(p) for p in args.puertos.split(',') if p.strip()]
    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)

    # Ctrl+C también cuando se lanza con "&" (el shell lo deja ignorado) y
    # SIGTERM (por ejemplo al cerrar Mininet) terminan igual
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, _sigterm)

    escuchas = abrir_escuchas(args.host, puertos)
    sel = selectors.DefaultSelector()
    for s in escuchas:
        sel.register(s, selectors.EVENT_READ)
    print(f'[{ts_utc()}] Honeypot escuchando en {args.host} puertos {puertos} '
          f'— log: {args.log}', flush=True)

    try:
        with open(args.log, 'a', encoding='utf-8') as log:
            while True:
                for key, _ in sel.select():
                    try:
                        conn, (ip_o, puerto_o) = key.fileobj.accept()
                    except (BlockingIOError, InterruptedError):
                        continue
                    ip_d, puerto_d = destino_original(conn)
                    conn.close()
                    linea = {'ts': ts_utc(), 'ip_origen': ip_o, 'puerto_origen': puerto_o,
                             'ip_destino': ip_d, 'puerto_destino': puerto_d}
                    log.write(json.dumps(linea) + '\n')
                    log.flush()
                    print(json.dumps(linea), flush=True)
    except KeyboardInterrupt:
        print(f'\n[{ts_utc()}] Honeypot detenido.', flush=True)
    finally:
        sel.close()
        for s in escuchas:
            s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
