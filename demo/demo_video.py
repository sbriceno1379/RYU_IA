#!/usr/bin/env python3
"""
=============================================================================
DEMO CORTA PARA VIDEO — Ryu-IA + agente sdn-agent-v2
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Muestra el flujo completo en pocos minutos, con salidas claras en pantalla:
  1. Arranca Ryu y la topología de Mininet (3 switches, VLAN OPS y ADM, honeypot).
  2. Tráfico normal: h1 hace ping a h2 (funciona).
  3. Incidente 1: h1 propaga por SMB (445) a la VLAN OPS (tipo WannaCry).
     Incidente 2: h11 se mueve por RDP/WinRM (3389, 5985) en la VLAN ADM.
  4. Para cada incidente: Ryu BLOQUEA (DROP en s1, s2 y s3), se ve la alerta
     JSON que Ryu envía, el agente la recibe (202), la explica y recomienda.
  5. El operador decide: aprobar aquí, aprobar en el panel o no hacer nada.
     Ryu solo cambia el bloqueo cuando el operador lo aprueba.

No es la evaluación de la tesis (eso es evaluacion/): un solo intento por
incidente, sin repeticiones ni estadísticas.

USO (el agente ya corriendo en :8081 con su .env; Mininet necesita sudo):
  python3 demo/demo_video.py --dry-run                 # verificaciones, sin sudo
  sudo -E /usr/bin/python3 demo/demo_video.py          # demo con 2 incidentes
  sudo -E /usr/bin/python3 demo/demo_video.py --incidentes 1 --pausas

Los tokens se leen de AGENT_TOKEN y OPERADOR_TOKEN o, si faltan, del .env
del agente (--env-agente). Ningún secreto va en este archivo.
Solo librería estándar.
=============================================================================
"""

import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

DIR_DEMO = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(DIR_DEMO)
RYU_API = 'http://127.0.0.1:8080'
AGENTE = 'http://127.0.0.1:8081'
RYU_CMD = '.venv/bin/ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633 --wsapi-port 8080'
HONEYPOT_ENV = {'HONEYPOT_DPID': '3', 'HONEYPOT_PUERTO': '3', 'HONEYPOT_MAC': '00:00:00:00:09:99'}
SWITCHES = ('s1', 's2', 's3')
GRACIA_RYU_S = 30   # STARTUP_GRACE_SEC de ryu_controller.py
PUERTOS_VICTIMA = (135, 139, 445, 3389, 5985)

INCIDENTES = [
    {'titulo': 'Ransomware por SMB en la VLAN OPS (tipo WannaCry/PsExec)',
     'mitre': 'T1021.002 SMB + T1570 transferencia de herramientas',
     'host': 'h1', 'ip': '10.0.10.1', 'vecino': 'h2',
     'destinos': [f'10.0.10.{i}' for i in range(2, 11)], 'puertos': [445],
     'bytes': 614400, 'intervalo': 0.3},
    {'titulo': 'Movimiento lateral por RDP y WinRM en la VLAN ADM',
     'mitre': 'T1021.001 RDP + T1021.006 WinRM',
     'host': 'h11', 'ip': '10.0.20.1', 'vecino': 'h12',
     'destinos': [f'10.0.20.{i}' for i in range(2, 11)], 'puertos': [3389, 5985],
     'bytes': 32768, 'intervalo': 0.2},
]

# ─── Pantalla ────────────────────────────────────────────────────────────────
R, V, A, AZ, N, G, X = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[1m', '\033[90m', '\033[0m'
PAUSAS = False


def hora():
    return datetime.now().strftime('%H:%M:%S')


def paso(texto):
    print(f'\n{N}{AZ}{"═" * 72}\n  {texto}\n{"═" * 72}{X}', flush=True)


def ok(texto):
    print(f'{G}[{hora()}]{X} {V}✔{X} {texto}', flush=True)


def aviso(texto):
    print(f'{G}[{hora()}]{X} {A}!{X} {texto}', flush=True)


def mal(texto):
    print(f'{G}[{hora()}]{X} {R}✘{X} {texto}', flush=True)


def info(texto):
    print(f'{G}[{hora()}]{X}   {texto}', flush=True)


def bloque(texto, color=''):
    for linea in texto.splitlines():
        print(f'      {color}{linea}{X}')


def pausa(texto='Enter para continuar'):
    if PAUSAS:
        input(f'\n{A}  ⏸  {texto}...{X}')


def cuenta_atras(segundos, texto):
    fin = time.time() + segundos
    while (restante := fin - time.time()) > 0:
        print(f'\r{G}[{hora()}]{X}   {texto}: {restante:4.0f} s ', end='', flush=True)
        time.sleep(min(1, restante))
    print()


# ─── Procesos dentro de los hosts de Mininet ─────────────────────────────────

def modo_victima():
    """Escucha en los puertos críticos, acepta y descarta lo que llegue."""
    def atender(conn):
        try:
            conn.settimeout(5)
            while conn.recv(65536):
                pass
        except OSError:
            pass
        finally:
            conn.close()

    def escuchar(puerto):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', puerto))
        srv.listen(128)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=atender, args=(conn,), daemon=True).start()

    for p in PUERTOS_VICTIMA:
        threading.Thread(target=escuchar, args=(p,), daemon=True).start()
    while True:
        time.sleep(3600)


def modo_ataque(destinos, puertos, n_bytes, intervalo, duracion):
    """Conexiones TCP a cada (destino, puerto), en bucle, enviando n_bytes."""
    carga = os.urandom(min(n_bytes, 65536)) if n_bytes else b''
    t0 = time.time()
    while time.time() - t0 < duracion:
        for d in destinos:
            for p in puertos:
                s = socket.socket()
                s.settimeout(1)
                try:
                    s.connect((d, p))
                    enviados = 0
                    while enviados < n_bytes:
                        s.sendall(carga[:n_bytes - enviados])
                        enviados += min(len(carga), n_bytes - enviados)
                    print(f'{hora()} {d}:{p} conectado, {enviados} B', flush=True)
                except OSError as e:
                    print(f'{hora()} {d}:{p} falló ({e})', flush=True)
                finally:
                    s.close()
                time.sleep(intervalo)
                if time.time() - t0 >= duracion:
                    return


# ─── HTTP ────────────────────────────────────────────────────────────────────

def http(metodo, url, cabeceras, cuerpo=None, timeout=5):
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(url, data=datos, method=metodo,
                                 headers={**cabeceras, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or 'null')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or 'null')
        except ValueError:
            return e.code, None


class Clientes:
    def __init__(self, agent_token, operador_token):
        self.ryu_h = {'X-Agent-Token': agent_token}
        self.op_h = {'X-Operador-Token': operador_token}

    def ryu(self, ruta):
        return http('GET', RYU_API + ruta, self.ryu_h)[1]

    def bloqueados(self):
        try:
            return {f['ip']: f for f in (self.ryu('/ryu/hosts/bloqueados') or [])}
        except Exception:
            return {}

    def agente(self, metodo, ruta, cuerpo=None, timeout=10):
        return http(metodo, AGENTE + ruta, self.op_h, cuerpo, timeout)


def esperar(condicion, timeout, paso_s=0.5):
    limite = time.time() + timeout
    while time.time() < limite:
        try:
            valor = condicion()
            if valor:
                return valor
        except Exception:
            pass
        time.sleep(paso_s)
    return None


def puerto_ocupado(puerto):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', puerto)) == 0


def leer_tokens(ruta_env):
    tokens = {k: os.environ.get(k, '') for k in ('AGENT_TOKEN', 'OPERADOR_TOKEN')}
    if all(tokens.values()) or not os.path.isfile(ruta_env):
        return tokens
    with open(ruta_env, encoding='utf-8') as f:
        for linea in f:
            clave, _, valor = linea.strip().partition('=')
            if clave in tokens and not tokens[clave]:
                tokens[clave] = valor.strip().strip('"').strip("'")
    return tokens


def alerta_en_log(ruta_log, ip):
    """El JSON que Ryu envió al agente para esa IP (Ryu lo registra antes de enviarlo)."""
    marca = f'Payload JSON para {ip}:'
    try:
        with open(ruta_log, encoding='utf-8', errors='replace') as f:
            texto = f.read()
    except OSError:
        return None
    pos = texto.rfind(marca)
    if pos < 0:
        return None
    inicio = texto.find('{', pos)
    try:
        return json.JSONDecoder().raw_decode(texto[inicio:])[0]
    except ValueError:
        return None


# ─── Pasos de un incidente ───────────────────────────────────────────────────

def ping(net, origen, destino):
    return ' 0% packet loss' in net.get(origen).cmd(f'ping -c1 -W1 {net.get(destino).IP()}')


def drop_en_switches(net, ip):
    con_regla = []
    for nombre in SWITCHES:
        salida = net.get(nombre).cmd(f'ovs-ofctl -O OpenFlow13 dump-flows {nombre}')
        if any('priority=100' in l and f'nw_src={ip}' in l for l in salida.splitlines()):
            con_regla.append(nombre)
    return con_regla


def mostrar_alerta(alerta):
    if not alerta:
        aviso('No encontré la alerta en el log de Ryu')
        return
    alerta = {k: v for k, v in alerta.items() if k != 'solicitud_al_agente'}
    ok(f'Alerta JSON que Ryu envió a POST {AGENTE}/api/alertas (con X-Agent-Token):')
    bloque(json.dumps(alerta, indent=2, ensure_ascii=False), G)
    info(f'{G}(se omite "solicitud_al_agente": el agente la ignora por diseño){X}')


def seguir_agente(cli, ip, ids_vistos):
    """Espera el incidente del agente para esa IP y su explicación. Devuelve el incidente."""
    def nuevo():
        _, lista = cli.agente('GET', '/api/incidentes?limite=20')
        return next((i for i in lista or [] if i['host_origen'] == ip and i['id'] not in ids_vistos), None)

    inc = esperar(nuevo, 20)
    if not inc:
        mal('El agente no registró el incidente (¿está corriendo y con el mismo AGENT_TOKEN?)')
        return None
    ids_vistos.add(inc['id'])
    ok(f'Agente: respondió 202 {{"estado":"recibido","incidente_id":{inc["id"]},'
       f'"acciones_ryu":["mantener_bloqueo"]}}')
    info('El agente explica el incidente (LLM, o reglas de respaldo si el LLM no responde)...')

    def explicado():
        _, d = cli.agente('GET', f'/api/incidentes/{inc["id"]}')
        return d if d and d.get('t_explicado') and d.get('decision_politica') is not None else None

    det = esperar(explicado, 90, 1) or cli.agente('GET', f'/api/incidentes/{inc["id"]}')[1] or inc
    color = R if det.get('veredicto') == 'confirmado' else A
    ok(f'Explicación lista (fuente: {det.get("fuente_explicacion")})')
    info(f'Veredicto: {color}{N}{det.get("veredicto")}{X}   severidad: {det.get("severidad")}   '
         f'confianza: {det.get("confianza")}   MITRE: {det.get("tecnica_mitre")}')
    if det.get('explicacion'):
        bloque(textwrap.fill(det['explicacion'][:700], 90))
    if det.get('recomendacion_operador'):
        info(f'{N}Recomendación al operador:{X} {det["recomendacion_operador"]}')
    info(f'Acción propuesta: {N}{det.get("accion_propuesta")}{X}   '
         f'decisión de la política: {det.get("decision_politica")}')
    if esperar(lambda: cli.agente('GET', f'/api/incidentes/{inc["id"]}')[1].get('t_notificado'), 10, 1):
        ok('Notificación enviada (correo por Apps Script) y visible en el panel')
    else:
        aviso('Sin correo confirmado en 10 s (¿APPSCRIPT_URL en el .env del agente?); el panel sí lo muestra')
    return det


def decidir_operador(cli, ip, inc, modo):
    """El operador decide sobre la recomendación pendiente. Ryu solo cambia si se aprueba."""
    _, pendientes = cli.agente('GET', '/api/recomendaciones?estado=pendiente')
    rec = next((r for r in pendientes or [] if r.get('incidente_id') == inc['id'] or r.get('host') == ip), None)
    if not rec:
        ok(f'No hay acción pendiente: el agente recomienda mantener el DROP total de {ip}')
        return
    info(f'{N}Recomendación #{rec["id"]} pendiente:{X} {A}{rec["accion"]}{X} '
         f'(confianza {rec.get("confianza")})')
    if rec.get('justificacion'):
        bloque(textwrap.fill(rec['justificacion'], 90))

    if modo == 'preguntar':
        r = input(f'\n{A}  Operador: ¿aprobar "{rec["accion"]}" para {ip}? '
                  f'[s = aprobar aquí / p = lo apruebo en el panel / n = no]: {X}').strip().lower()
        modo = {'s': 'auto', 'p': 'panel'}.get(r, 'no')
    if modo == 'no':
        ok(f'El operador no aprobó: {ip} sigue en DROP total')
        return
    antes = cli.bloqueados().get(ip, {}).get('modo')
    if modo == 'panel':
        info(f'Aprueba la recomendación #{rec["id"]} en el panel {AGENTE} (espero hasta 3 min)...')
        if not esperar(lambda: cli.bloqueados().get(ip, {}).get('modo') != antes, 180, 1):
            aviso('No hubo cambio en Ryu; el host sigue como estaba')
            return
    else:
        codigo, res = cli.agente('POST', f'/api/recomendaciones/{rec["id"]}/aprobar', timeout=30)
        estado = (res or {}).get('estado')
        if codigo != 200 or estado != 'ejecutada':
            mal(f'La acción no se aplicó (HTTP {codigo}, estado {estado}); el agente deja el DROP total')
            return
        ok(f'Operador aprobó #{rec["id"]} → el agente llamó a la API REST de Ryu (:8080)')
    fila = cli.bloqueados().get(ip)
    ok(f'Ryu: {ip} pasó de {antes} a {N}{fila.get("modo") if fila else "desbloqueado"}{X}')


def ejecutar_incidente(n, inc, net, cli, args, dir_logs, ids_vistos):
    paso(f'INCIDENTE {n}: {inc["titulo"]}')
    info(f'Origen {inc["host"]} ({inc["ip"]}) → {inc["destinos"][0]}..{inc["destinos"][-1].rsplit(".", 1)[1]} '
         f'puertos {inc["puertos"]}   [{inc["mitre"]}]')
    pausa('Enter para lanzar el ataque')
    salida = open(os.path.join(dir_logs, f'ataque_{inc["host"]}.out'), 'w')
    cmd = [sys.executable, os.path.abspath(__file__), '_ataque', ','.join(inc['destinos']),
           ','.join(map(str, inc['puertos'])), str(inc['bytes']), str(inc['intervalo']), str(args.max_ataque)]
    proc = net.get(inc['host']).popen(cmd, stdout=salida, stderr=subprocess.STDOUT)
    t0 = time.time()
    ok(f'Ataque lanzado desde {inc["host"]}. Ryu vigila M1 a M5...')

    fila = None
    while time.time() - t0 < args.max_ataque + 10:
        fila = cli.bloqueados().get(inc['ip'])
        if fila:
            break
        print(f'\r{G}[{hora()}]{X}   esperando detección: {time.time() - t0:4.0f} s ', end='', flush=True)
        time.sleep(0.5)
    print()
    proc.terminate()
    salida.close()
    if not fila:
        mal(f'Ryu no bloqueó {inc["ip"]} en {args.max_ataque} s (revisa {dir_logs}/ryu.log)')
        return
    ok(f'{R}{N}Ryu BLOQUEÓ {inc["ip"]}{X} a los {time.time() - t0:.1f} s (modo {fila["modo"]}), '
       'antes de avisar al agente')
    switches = drop_en_switches(net, inc['ip'])
    ok(f'Regla DROP prioridad 100 instalada en: {", ".join(switches) or "ninguno"}')
    if ping(net, inc['host'], inc['vecino']):
        aviso(f'{inc["host"]} todavía llega a {inc["vecino"]}')
    else:
        ok(f'Prueba: {inc["host"]} ya no llega a {inc["vecino"]} (ping falla)')
    pausa('Enter para ver la alerta JSON')

    mostrar_alerta(esperar(lambda: alerta_en_log(os.path.join(dir_logs, 'ryu.log'), inc['ip']), 5))
    if args.sin_agente:
        return
    pausa('Enter para ver qué hizo el agente')
    det = seguir_agente(cli, inc['ip'], ids_vistos)
    if det:
        pausa('Enter para la decisión del operador')
        decidir_operador(cli, inc['ip'], det, args.aprobar)


# ─── Demo completa ───────────────────────────────────────────────────────────

def verificar(args, tokens):
    paso('VERIFICACIONES')
    fallas = 0
    if os.path.isfile(os.path.join(REPO, '.venv/bin/ryu-manager')):
        ok('ryu-manager en .venv')
    else:
        mal('No está .venv/bin/ryu-manager (ver Instalación en README.md)')
        fallas += 1
    for clave in ('AGENT_TOKEN', 'OPERADOR_TOKEN'):
        if tokens[clave]:
            ok(f'{clave} definido')
        elif clave == 'AGENT_TOKEN' or not args.sin_agente:
            mal(f'Falta {clave}: expórtalo o revisa --env-agente ({args.env_agente})')
            fallas += 1
    if not args.sin_agente:
        try:
            _, salud = http('GET', AGENTE + '/api/salud', {}, timeout=2)
            ok(f'Agente respondiendo en {AGENTE} (versión {salud.get("version")})')
        except Exception:
            mal(f'El agente no responde en {AGENTE}: arráncalo (uvicorn app.main:app --port 8081) '
                'o usa --sin-agente')
            fallas += 1
    for p in (6633, 8080):
        if puerto_ocupado(p):
            mal(f'Puerto {p} ocupado: cierra Ryu o el mock de Ryu del agente; esta demo arranca su propio Ryu')
            fallas += 1
    return fallas


def correr(args, tokens):
    from mininet.log import setLogLevel
    sys.path.insert(0, REPO)
    import topology_project as topo

    setLogLevel('warning')
    dir_logs = os.path.join(REPO, 'logs', 'demo_' + datetime.now().strftime('%Y%m%d_%H%M%S'))
    os.makedirs(dir_logs, exist_ok=True)
    cli = Clientes(tokens['AGENT_TOKEN'], tokens['OPERADOR_TOKEN'])
    env = {**os.environ, 'AGENT_TOKEN': tokens['AGENT_TOKEN'], **HONEYPOT_ENV}
    usuario = os.environ.get('SUDO_USER')
    net, ryu, victimas, salida_ryu = None, None, [], None

    try:
        paso('PASO 1 — ARRANQUE: Ryu (OpenFlow 1.3, :6633, API :8080) y Mininet')
        subprocess.call(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # antes de Ryu
        salida_ryu = open(os.path.join(dir_logs, 'ryu.log'), 'w')
        ryu = subprocess.Popen(shlex.split(RYU_CMD), cwd=REPO, env=env, stdout=salida_ryu,
                               stderr=subprocess.STDOUT, **({'user': usuario} if usuario else {}))
        t_ryu = time.time()
        if not esperar(lambda: cli.ryu('/ryu/estado'), 30):
            raise RuntimeError(f'La API de Ryu no respondió en 30 s (ver {dir_logs}/ryu.log)')
        ok(f'Ryu arrancó{" como " + usuario if usuario else ""} (log en {dir_logs}/ryu.log)')

        net, _c0, s1, s2, s3, ops, adm = topo.build_topology()
        net.start()
        time.sleep(3)
        topo.configure_vlans(s1, s2, s3, n_ops=10, n_adm=10)
        honeypot = topo.setup_honeypot(net, s3)
        if not esperar(lambda: len(cli.ryu('/ryu/estado')['switches']) >= 3, 60):
            raise RuntimeError('Los 3 switches no se conectaron a Ryu en 60 s')
        ok('Topología arriba: s1 (OPS h1-h10, VLAN 10), s2 (ADM h11-h20, VLAN 20), s3 core')
        ok('Honeypot VLAN 999 listo (10.0.99.1)' if honeypot else 'Honeypot no disponible (sin A8)')
        for grupo in (ops, adm):   # Ryu aprende las estaciones durante la gracia
            for i, h in enumerate(grupo):
                h.cmd(f'ping -c1 -W1 {grupo[(i + 1) % len(grupo)].IP()} > /dev/null 2>&1')
        atacantes = {i['host'] for i in INCIDENTES[:args.incidentes]}
        for h in ops + adm:
            if h.name not in atacantes:
                victimas.append(h.popen([sys.executable, os.path.abspath(__file__), '_victima'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        ok(f'Servicios simulados (SMB, RPC, NetBIOS, RDP, WinRM) en {len(victimas)} equipos')

        paso('PASO 2 — TRÁFICO NORMAL')
        for inc in INCIDENTES[:args.incidentes]:
            estado = f'{V}funciona{X}' if ping(net, inc['host'], inc['vecino']) else f'{R}falla{X}'
            info(f'ping {inc["host"]} → {inc["vecino"]}: {estado}')
        restante = GRACIA_RYU_S + 3 - (time.time() - t_ryu)
        if restante > 0:
            cuenta_atras(restante, 'Período de gracia de Ryu (no evalúa métricas)')
        estado = cli.ryu('/ryu/estado')
        ok(f'Ryu listo: {len(estado["switches"])} switches, {estado.get("hosts_bloqueados", 0)} bloqueados')
        pausa('Enter para el primer incidente')

        ids_vistos = set()
        if not args.sin_agente:
            _, previos = cli.agente('GET', '/api/incidentes?limite=50')
            ids_vistos = {i['id'] for i in previos or []}
        for n, inc in enumerate(INCIDENTES[:args.incidentes], 1):
            ejecutar_incidente(n, inc, net, cli, args, dir_logs, ids_vistos)

        paso('RESUMEN')
        filas = cli.bloqueados()
        for ip, f in filas.items():
            info(f'{ip:<12} modo {N}{f["modo"]}{X} desde {f["desde"]}')
        if not filas:
            info('Ningún host aislado')
        info(f'Panel del agente: {AGENTE}  ·  logs: {dir_logs}')
        input(f'\n{A}  Enter para apagar la demo (Ryu y Mininet)...{X}')
    finally:
        for p in victimas:
            p.terminate()
        if net is not None:
            net.stop()
        if ryu is not None and ryu.poll() is None:
            ryu.terminate()
            try:
                ryu.wait(5)
            except subprocess.TimeoutExpired:
                ryu.kill()
        if salida_ryu:
            salida_ryu.close()
        subprocess.call(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.environ.get('SUDO_UID'):   # que los logs queden del usuario, no de root
            for raiz, dirs, archivos in os.walk(dir_logs):
                for nombre in [raiz] + [os.path.join(raiz, a) for a in archivos]:
                    os.chown(nombre, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        ok('Demo apagada')


def main(argv=None):
    global PAUSAS
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['_victima']:
        return modo_victima()
    if argv[:1] == ['_ataque']:
        d, p, b, i, t = argv[1:6]
        return modo_ataque(d.split(','), [int(x) for x in p.split(',')], int(b), float(i), float(t))

    casa = os.path.expanduser(f'~{os.environ.get("SUDO_USER", "")}')
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--incidentes', type=int, choices=(1, 2), default=2,
                        help='1 = solo SMB en OPS; 2 = también RDP/WinRM en ADM (por defecto)')
    parser.add_argument('--aprobar', choices=('preguntar', 'panel', 'auto', 'no'), default='preguntar',
                        help='cómo decide el operador la recomendación (por defecto se pregunta en pantalla)')
    parser.add_argument('--pausas', action='store_true', help='espera Enter entre pasos (para narrar)')
    parser.add_argument('--sin-agente', action='store_true', help='solo Ryu: detección, bloqueo y alerta JSON')
    parser.add_argument('--max-ataque', type=float, default=90, help='segundos máximos de cada ataque')
    parser.add_argument('--env-agente', default=os.path.join(casa, 'Desktop/sdn-agent-v2/.env'),
                        help='de aquí se leen AGENT_TOKEN y OPERADOR_TOKEN si no están exportados')
    parser.add_argument('--dry-run', action='store_true', help='solo verificaciones y plan, sin sudo')
    args = parser.parse_args(argv)
    PAUSAS = args.pausas

    print(f'{N}\n  DEMO Ryu-IA + agente LLM — respuesta a movimiento lateral de ransomware en SDN{X}')
    tokens = leer_tokens(args.env_agente)
    fallas = verificar(args, tokens)
    if args.dry_run:
        paso('PLAN')
        for n, inc in enumerate(INCIDENTES[:args.incidentes], 1):
            info(f'Incidente {n}: {inc["host"]} ({inc["ip"]}) — {inc["titulo"]}')
        info(f'Decisión del operador: {args.aprobar}   pausas: {"sí" if args.pausas else "no"}')
        info('Para correrla: sudo -E /usr/bin/python3 demo/demo_video.py ' + ' '.join(
            a for a in argv if a != '--dry-run'))
        return 1 if fallas else 0
    if fallas:
        raise SystemExit(f'\n{fallas} verificación(es) fallaron; corrige y vuelve a intentar.')
    if os.geteuid() != 0:
        raise SystemExit('Mininet necesita root: sudo -E /usr/bin/python3 demo/demo_video.py')
    correr(args, tokens)
    return 0


if __name__ == '__main__':
    sys.exit(main())
