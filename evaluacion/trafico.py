#!/usr/bin/env python3
"""
=============================================================================
GENERADOR DE TRÁFICO PARA LA EVALUACIÓN (R4 / objetivo 3)
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Se ejecuta DENTRO de un host de Mininet (lo lanza orquestador.py). Solo
librería estándar, compatible con Python 3.8+.

Subcomandos:
  victima      Escucha TCP en los puertos indicados, acepta, lee y descarta
               lo que llegue, y escribe una línea JSON por conexión:
               {"ts", "ip_origen", "puerto_origen", "ip_local", "puerto_local", "bytes"}
  conexiones   Abre conexiones TCP a cada (destino, puerto), opcionalmente
               envía N bytes, con un intervalo entre conexiones. Escribe una
               línea JSON por intento (ts, destino, puerto, ok, bytes).

Ejemplos:
  python3 trafico.py victima --puertos 135,139,445,3389,5985,8080,5001 --log /tmp/v.jsonl
  python3 trafico.py conexiones --destinos 10.0.10.2-5 --puertos 445 --bytes 65536 \
          --intervalo 0.2 --ciclos 3 --log /tmp/a.jsonl
=============================================================================
"""

import argparse
import json
import os
import random
import selectors
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone

PUERTOS_VICTIMA = (135, 139, 445, 3389, 5985, 8080, 5001)
_corriendo = True


def ahora_iso():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


class Bitacora:
    """Escribe líneas JSON con flush inmediato (el orquestador puede matar el proceso)."""

    def __init__(self, ruta):
        self._lock = threading.Lock()
        self._f = open(ruta, 'a', buffering=1) if ruta else None

    def escribir(self, fila):
        if self._f is None:
            return
        with self._lock:
            self._f.write(json.dumps(fila, ensure_ascii=False) + '\n')


def expandir_destinos(texto):
    """'10.0.10.2-5,10.0.20.1' → ['10.0.10.2', ..., '10.0.10.5', '10.0.20.1']."""
    destinos = []
    for parte in texto.split(','):
        parte = parte.strip()
        if not parte:
            continue
        base, _, ultimo = parte.rpartition('.')
        if '-' in ultimo:
            ini, fin = (int(x) for x in ultimo.split('-'))
            destinos += [f'{base}.{i}' for i in range(ini, fin + 1)]
        else:
            destinos.append(parte)
    return destinos


def expandir_puertos(texto):
    return [int(p) for p in texto.split(',') if p.strip()]


# ═════════════════════════════════════════════════════════════════════════════
#  VÍCTIMA
# ═════════════════════════════════════════════════════════════════════════════

def _atender(conn, direccion, local, bitacora):
    ts_aceptada = ahora_iso()   # la hora que cuenta es la de aceptación, no la de cierre
    total = 0
    try:
        conn.settimeout(5)
        conn.sendall(b'\x00\x00')
        while True:
            datos = conn.recv(65536)
            if not datos:
                break
            total += len(datos)
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()
    bitacora.escribir({'ts': ts_aceptada, 'ip_origen': direccion[0], 'puerto_origen': direccion[1],
                       'ip_local': local[0], 'puerto_local': local[1], 'bytes': total})


def victima(args):
    bitacora = Bitacora(args.log)
    sel = selectors.DefaultSelector()
    for puerto in expandir_puertos(args.puertos):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((args.ip, puerto))
        except OSError as e:
            print(f'[victima] puerto {puerto}: {e}', file=sys.stderr, flush=True)
            continue
        srv.listen(128)
        srv.setblocking(False)
        sel.register(srv, selectors.EVENT_READ)
    print(f'[victima] escuchando en {args.puertos}', flush=True)
    while _corriendo:
        for clave, _ in sel.select(timeout=0.5):
            try:
                conn, direccion = clave.fileobj.accept()
            except OSError:
                continue
            conn.setblocking(True)
            local = conn.getsockname()
            threading.Thread(target=_atender, args=(conn, direccion, local, bitacora), daemon=True).start()


# ═════════════════════════════════════════════════════════════════════════════
#  CONEXIONES (ataque o tráfico benigno, según los parámetros del escenario)
# ═════════════════════════════════════════════════════════════════════════════

def conectar(destino, puerto, n_bytes, timeout):
    """(ok, bytes_enviados). Nunca lanza excepción."""
    enviados = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((destino, puerto))
        if n_bytes:
            bloque = os.urandom(min(n_bytes, 65536))
            while enviados < n_bytes:
                parte = bloque[:n_bytes - enviados]
                s.sendall(parte)
                enviados += len(parte)
        return True, enviados
    except OSError:
        return False, enviados
    finally:
        s.close()


def conexiones(args):
    bitacora = Bitacora(args.log)
    pares = [(d, p) for d in expandir_destinos(args.destinos) for p in expandir_puertos(args.puertos)]
    if args.max_pares:
        pares = pares[:args.max_pares]
    if args.espera_inicial:
        time.sleep(args.espera_inicial)
    t0 = time.time()
    ciclo = 0
    while _corriendo and (args.ciclos == 0 or ciclo < args.ciclos):
        orden = list(pares)
        if args.aleatorio:
            random.shuffle(orden)
        for destino, puerto in orden:
            if not _corriendo or (args.duracion and time.time() - t0 >= args.duracion):
                return
            ok, enviados = conectar(destino, puerto, args.bytes, args.timeout)
            bitacora.escribir({'ts': ahora_iso(), 'destino': destino, 'puerto': puerto,
                               'ok': ok, 'bytes': enviados})
            time.sleep(args.intervalo)
        ciclo += 1
        if args.duracion and time.time() - t0 >= args.duracion:
            return


def _detener(*_):
    global _corriendo
    _corriendo = False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='modo', required=True)

    v = sub.add_parser('victima')
    v.add_argument('--puertos', default=','.join(map(str, PUERTOS_VICTIMA)))
    v.add_argument('--ip', default='0.0.0.0')
    v.add_argument('--log')

    c = sub.add_parser('conexiones')
    c.add_argument('--destinos', required=True, help='lista con rangos: 10.0.10.2-5,10.0.10.9')
    c.add_argument('--puertos', required=True, help='lista: 445,135')
    c.add_argument('--bytes', type=int, default=0, help='bytes a enviar por conexión')
    c.add_argument('--intervalo', type=float, default=0.1, help='segundos entre conexiones')
    c.add_argument('--ciclos', type=int, default=1, help='repeticiones de la lista (0 = sin fin)')
    c.add_argument('--duracion', type=float, default=0, help='corta tras N segundos (0 = sin límite)')
    c.add_argument('--max-pares', type=int, default=0, help='usa solo los primeros N pares (destino, puerto)')
    c.add_argument('--aleatorio', action='store_true', help='baraja el orden en cada ciclo')
    c.add_argument('--espera-inicial', type=float, default=0)
    c.add_argument('--timeout', type=float, default=1.0)
    c.add_argument('--semilla', type=int)
    c.add_argument('--log')

    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, _detener)
    signal.signal(signal.SIGINT, _detener)
    if getattr(args, 'semilla', None) is not None:
        random.seed(args.semilla)
    (victima if args.modo == 'victima' else conexiones)(args)


if __name__ == '__main__':
    main()
