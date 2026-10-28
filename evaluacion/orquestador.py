#!/usr/bin/env python3
"""
=============================================================================
ORQUESTADOR DE LA EVALUACIÓN (R4 / objetivo 3)
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Ejecuta N repeticiones de cada escenario de escenarios_r4.json, en orden
aleatorio y con Ryu recién arrancado en cada corrida (sin estado heredado:
puntajes, conjunto east-west de M5, hosts bloqueados). Por cada corrida
escribe una línea en manifiesto.jsonl con las marcas de tiempo y las rutas
de las bitácoras; evaluar.py calcula después las métricas.

Corrida:
  1. mn -c, arranca Ryu (como el usuario que llamó a sudo) con su log propio.
  2. Levanta la topología de topology_project.py y espera los 3 switches.
  3. Calentamiento: cada host hace un ping a un vecino de su VLAN (dentro
     del período de gracia, para que Ryu conozca las estaciones).
  4. Arranca trafico.py victima en todos los hosts que no originan tráfico.
  5. Cumplida la gracia, anota t_inicio y lanza los procesos del escenario.
  6. Consulta GET /ryu/hosts/bloqueados cada 0,25 s. Termina al pasar
     --post-bloqueo segundos desde el primer bloqueo, al terminar los
     procesos o al llegar a duracion_max_s.
  7. Revisa la regla DROP (priority=100) en s1, s2 y s3, para todo y apaga.
Al terminar la serie corre evaluar.py y deja el informe (resumen.md,
corridas.csv, evaluacion.json) en la carpeta de la serie.

Ryu nunca desbloquea aquí: se reinicia en cada corrida. El agente NO hace
falta: sin él se evalúan la detección, la contención y los tiempos de Ryu.
Si está corriendo en :8081 (con AGENT_TOKEN y OPERADOR_TOKEN exportados),
el informe agrega sus incidentes.

USO (un solo comando; Mininet necesita sudo y Ryu lo arranca este script):
  sudo /usr/bin/python3 evaluacion/orquestador.py                 # serie completa
  sudo /usr/bin/python3 evaluacion/orquestador.py --solo A6 --repeticiones 1   # humo
  python3 evaluacion/orquestador.py --dry-run                     # solo muestra el plan
=============================================================================
"""

import argparse
import json
import os
import random
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

DIR_EVAL = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(DIR_EVAL)
RYU_API = 'http://127.0.0.1:8080'
AGENTE_SALUD = 'http://127.0.0.1:8081/api/salud'
RYU_CMD = '.venv/bin/ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633 --wsapi-port 8080'
SWITCHES = ('s1', 's2', 's3')
GRACIA_RYU_S = 30   # STARTUP_GRACE_SEC de ryu_controller.py


def ahora_iso():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}', flush=True)


# ─── Plan ────────────────────────────────────────────────────────────────────

def cargar_escenarios(ruta, solo=None):
    with open(ruta, encoding='utf-8') as f:
        escenarios = json.load(f)['escenarios']
    if solo:
        ids = [s.strip() for s in solo.split(',') if s.strip()]
        desconocidos = set(ids) - {e['id'] for e in escenarios}
        if desconocidos:
            raise SystemExit(f'Escenarios desconocidos: {sorted(desconocidos)}')
        escenarios = [e for e in escenarios if e['id'] in ids]
    return escenarios


def armar_plan(escenarios, repeticiones, semilla):
    """Lista de corridas (escenario, repetición) en orden aleatorio reproducible."""
    plan = [{'escenario': e['id'], 'repeticion': r} for e in escenarios for r in range(1, repeticiones + 1)]
    rng = random.Random(semilla)
    rng.shuffle(plan)
    for i, corrida in enumerate(plan, 1):
        corrida['orden'] = i
        corrida['semilla'] = rng.randrange(1, 2**31)
    return plan


def ip_de_host(nombre):
    """h1..h10 → 10.0.10.x; h11..h20 → 10.0.20.(x-10). Igual que topology_project.py."""
    n = int(nombre.lstrip('h'))
    return f'10.0.10.{n}' if n <= 10 else f'10.0.20.{n - 10}'


def comando(plantilla, log_path, semilla, python='python3'):
    return plantilla.format(python=python, trafico=os.path.join(DIR_EVAL, 'trafico.py'),
                            repo=REPO, log=log_path, semilla=semilla)


# ─── Ryu ─────────────────────────────────────────────────────────────────────

def ryu_get(ruta, token, timeout=2):
    req = urllib.request.Request(RYU_API + ruta, headers={'X-Agent-Token': token})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def esperar(condicion, timeout, paso=0.5):
    limite = time.time() + timeout
    while time.time() < limite:
        try:
            if condicion():
                return True
        except Exception:
            pass
        time.sleep(paso)
    return False


def arrancar_ryu(ryu_cmd, log_path, env):
    usuario = os.environ.get('SUDO_USER')   # Ryu corre sin root, como en PLAN.md
    salida = open(log_path, 'w')
    extra = {'user': usuario} if usuario and os.geteuid() == 0 else {}
    return subprocess.Popen(shlex.split(ryu_cmd), cwd=REPO, stdout=salida, stderr=subprocess.STDOUT,
                            env=env, **extra), salida


def detener(proc, espera=5):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(espera)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ─── Corrida ─────────────────────────────────────────────────────────────────

def drop_en_switches(net, ip):
    """Switches donde está la regla DROP de prioridad 100 para esa ip."""
    con_regla = []
    for nombre in SWITCHES:
        salida = net.get(nombre).cmd(f'ovs-ofctl -O OpenFlow13 dump-flows {nombre}')
        for linea in salida.splitlines():
            if 'priority=100' in linea and f'nw_src={ip}' in linea and ',' in linea:
                con_regla.append(nombre)
                break
    return con_regla


def ejecutar_corrida(corrida, escenario, args, dir_corrida, env):
    from mininet.log import setLogLevel
    sys.path.insert(0, REPO)
    import topology_project as topo   # noqa: E402 (requiere Mininet)

    setLogLevel('warning')
    token = env.get('AGENT_TOKEN', '')
    registro = {**corrida, 'corrida_id': os.path.basename(dir_corrida), 'bloque': args.bloque,
                'etiqueta': escenario['etiqueta'], 'dificil': escenario.get('dificil', False),
                'sospechosos': escenario.get('sospechosos', []),
                'metricas_previstas': escenario.get('metricas_previstas', []),
                'origenes': [ip_de_host(p['host']) for p in escenario['procesos']],
                'logs': {'ryu': os.path.join(dir_corrida, 'ryu.log'), 'victimas': {}, 'procesos': {}},
                'error': None}

    subprocess.call(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ryu, ryu_salida = arrancar_ryu(args.ryu_cmd, registro['logs']['ryu'], env)
    t_ryu = time.time()
    registro['t_ryu_inicio'] = ahora_iso()
    net, procesos, victimas = None, [], []
    try:
        if not esperar(lambda: ryu_get('/ryu/estado', token) is not None, 30):
            raise RuntimeError('La API de Ryu no respondió en 30 s (¿AGENT_TOKEN?, ¿.venv?)')
        net, _c0, s1, s2, s3, ops, adm = topo.build_topology()
        net.start()
        time.sleep(3)
        topo.configure_vlans(s1, s2, s3, n_ops=10, n_adm=10)
        if args.honeypot:
            topo.setup_honeypot(net, s3)
        if not esperar(lambda: len(ryu_get('/ryu/estado', token)['switches']) >= 3, 30):
            raise RuntimeError('Los 3 switches no se conectaron a Ryu en 30 s')

        # Calentamiento dentro de la gracia: Ryu aprende las estaciones (workstation_ips)
        for grupo in (ops, adm):
            for i, h in enumerate(grupo):
                vecino = grupo[(i + 1) % len(grupo)]
                h.cmd(f'ping -c1 -W1 {vecino.IP()} > /dev/null 2>&1')

        origenes = {p['host'] for p in escenario['procesos']}
        for h in ops + adm:
            if h.name in origenes:
                continue
            ruta = os.path.join(dir_corrida, f'victima_{h.name}.jsonl')
            registro['logs']['victimas'][h.name] = ruta
            victimas.append(h.popen(['python3', os.path.join(DIR_EVAL, 'trafico.py'), 'victima', '--log', ruta],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

        restante = args.gracia - (time.time() - t_ryu)
        if restante > 0:
            log(f'  esperando {restante:.0f} s de gracia de Ryu')
            time.sleep(restante)
        if ryu_get('/ryu/hosts/bloqueados', token):
            raise RuntimeError('Hay hosts bloqueados antes de empezar el escenario')

        registro['t_inicio'] = ahora_iso()
        t0 = time.time()
        for i, p in enumerate(escenario['procesos']):
            ruta = os.path.join(dir_corrida, f'proceso{i}_{p["host"]}.jsonl')
            salida = os.path.join(dir_corrida, f'proceso{i}_{p["host"]}.out')
            registro['logs']['procesos'][f'{i}:{p["host"]}'] = ruta
            cmd = comando(p['cmd'], ruta, corrida['semilla'])
            procesos.append(net.get(p['host']).popen(shlex.split(cmd), stdout=open(salida, 'w'),
                                                    stderr=subprocess.STDOUT))

        bloqueados, t_primer_bloqueo = {}, None
        while True:
            transcurrido = time.time() - t0
            try:
                for fila in ryu_get('/ryu/hosts/bloqueados', token):
                    bloqueados.setdefault(fila['ip'], fila)
            except Exception as e:
                log(f'  aviso: no se pudo leer /ryu/hosts/bloqueados ({e})')
            if bloqueados and t_primer_bloqueo is None:
                t_primer_bloqueo = time.time()
                log(f'  bloqueo: {sorted(bloqueados)} a los {transcurrido:.1f} s')
            if t_primer_bloqueo and time.time() - t_primer_bloqueo >= args.post_bloqueo:
                motivo = 'post_bloqueo'
                break
            if all(p.poll() is not None for p in procesos) and not t_primer_bloqueo:
                # deja pasar un ciclo de polling de M3 y la ventana de M1/M2 antes de cerrar
                time.sleep(args.asentamiento)
                if not ryu_get('/ryu/hosts/bloqueados', token):
                    motivo = 'procesos_terminados'
                    break
                continue
            if transcurrido >= escenario['duracion_max_s']:
                motivo = 'duracion_max'
                break
            time.sleep(0.25)

        registro['t_fin'] = ahora_iso()
        registro['motivo_fin'] = motivo
        registro['bloqueados'] = list(bloqueados.values())
        registro['drop_en_switches'] = {ip: drop_en_switches(net, ip) for ip in bloqueados}
    except Exception as e:
        registro['error'] = f'{type(e).__name__}: {e}'
        registro.setdefault('t_fin', ahora_iso())
        log(f'  ERROR: {registro["error"]}')
    finally:
        for p in procesos + victimas:
            detener(p, 2)
        if net is not None:
            net.stop()
        detener(ryu)
        ryu_salida.close()
        subprocess.call(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return registro


def puerto_ocupado(puerto):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', puerto)) == 0


def agente_disponible():
    try:
        with urllib.request.urlopen(AGENTE_SALUD, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def informe(manifiesto, con_agente):
    """Corre evaluar.py sobre la serie recién terminada: deja evaluacion.json, corridas.csv y resumen.md."""
    import evaluar
    log('Generando el informe de resultados')
    try:
        evaluar.main(['metricas', manifiesto] + ([] if con_agente else ['--sin-agente']))
    except Exception as e:   # las corridas ya quedaron; el informe se puede repetir a mano
        log(f'  ERROR al generar el informe ({type(e).__name__}: {e}); repítelo con: '
            f'python3 evaluacion/evaluar.py metricas {manifiesto} --sin-agente')


def ejecutar(argv=None):
    """Corre la serie y devuelve la ruta de su manifiesto (None en --dry-run)."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--escenarios', default=os.path.join(DIR_EVAL, 'escenarios_r4.json'))
    parser.add_argument('--solo', help='ids separados por coma, p. ej. A1,B3')
    parser.add_argument('--repeticiones', type=int, default=10)
    parser.add_argument('--semilla', type=int, default=20261028)
    parser.add_argument('--bloque', default='principal',
                        help='etiqueta libre de la serie (p. ej. llm o reglas) para comparar en evaluar.py')
    parser.add_argument('--salida', default=os.path.join(DIR_EVAL, 'resultados'))
    parser.add_argument('--ryu-cmd', default=RYU_CMD)
    parser.add_argument('--gracia', type=float, default=GRACIA_RYU_S + 5,
                        help='segundos desde que arranca Ryu hasta lanzar el escenario')
    parser.add_argument('--post-bloqueo', type=float, default=15,
                        help='segundos que la corrida sigue tras el primer bloqueo (contención y agente)')
    parser.add_argument('--asentamiento', type=float, default=15,
                        help='espera tras terminar los procesos sin bloqueo (polling de M3, ventanas)')
    parser.add_argument('--pausa', type=float, default=5, help='segundos entre corridas')
    parser.add_argument('--honeypot', action='store_true', help='levanta también el honeypot de la VLAN 999')
    parser.add_argument('--sin-informe', action='store_true', help='no correr evaluar.py al terminar')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)

    escenarios = {e['id']: e for e in cargar_escenarios(args.escenarios, args.solo)}
    plan = armar_plan(list(escenarios.values()), args.repeticiones, args.semilla)
    sello = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dir_serie = os.path.join(args.salida, f'{sello}_{args.bloque}')

    if args.dry_run:
        print(f'Plan ({len(plan)} corridas, semilla {args.semilla}) → {dir_serie}')
        for c in plan:
            e = escenarios[c['escenario']]
            print(f'  {c["orden"]:>3}. {c["escenario"]} rep {c["repeticion"]:>2}  [{e["etiqueta"]}] {e["nombre"]}')
            for p in e['procesos']:
                print(f'         {p["host"]}: {comando(p["cmd"], "<log>", c["semilla"])}')
        return None

    if os.geteuid() != 0:
        raise SystemExit('Mininet necesita root: sudo -E /usr/bin/python3 evaluacion/orquestador.py ...')
    ocupados = [p for p in (6633, 8080) if puerto_ocupado(p)]
    if ocupados:
        raise SystemExit(f'Los puertos {ocupados} ya están en uso: cierra Ryu o el mock de Ryu del agente; '
                         'este script arranca su propio Ryu en cada corrida')
    env = dict(os.environ)
    if not env.get('AGENT_TOKEN'):
        # sin agente: el token solo protege la API de Ryu durante la evaluación
        env['AGENT_TOKEN'] = secrets.token_hex(16)
    con_agente = agente_disponible()
    log('Agente en :8081: ' + ('sí, se evaluarán también sus incidentes' if con_agente
                               else 'no; se evalúa solo la detección y la contención de Ryu'))

    os.makedirs(dir_serie, exist_ok=True)
    with open(os.path.join(dir_serie, 'plan.json'), 'w', encoding='utf-8') as f:
        json.dump({'semilla': args.semilla, 'repeticiones': args.repeticiones, 'bloque': args.bloque,
                   'argumentos': vars(args), 'plan': plan}, f, indent=2, ensure_ascii=False)
    manifiesto = os.path.join(dir_serie, 'manifiesto.jsonl')
    log(f'{len(plan)} corridas → {manifiesto}')

    for c in plan:
        e = escenarios[c['escenario']]
        dir_corrida = os.path.join(dir_serie, f'{c["orden"]:03d}_{c["escenario"]}_r{c["repeticion"]:02d}')
        os.makedirs(dir_corrida, exist_ok=True)
        log(f'[{c["orden"]}/{len(plan)}] {c["escenario"]} rep {c["repeticion"]}: {e["nombre"]}')
        registro = ejecutar_corrida(c, e, args, dir_corrida, env)
        with open(manifiesto, 'a', encoding='utf-8') as f:
            f.write(json.dumps(registro, ensure_ascii=False) + '\n')
        time.sleep(args.pausa)

    if not args.sin_informe:
        informe(manifiesto, con_agente and bool(os.environ.get('OPERADOR_TOKEN')))
    if os.environ.get('SUDO_UID'):   # que el usuario pueda leer y borrar los resultados sin sudo
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        for raiz, dirs, archivos in os.walk(dir_serie):
            for nombre in [raiz] + [os.path.join(raiz, a) for a in archivos]:
                os.chown(nombre, uid, gid)
    log(f'Serie terminada: {manifiesto}')
    return manifiesto


def main(argv=None):
    ejecutar(argv)
    return 0


if __name__ == '__main__':
    sys.exit(main())
