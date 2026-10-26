#!/usr/bin/env python3
"""
=============================================================================
TOPOLOGÍA SDN — PROYECTO DE GRADO
Universidad Católica de Colombia
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  20 hosts divididos en 2 VLANs sobre Mininet con Open vSwitch.
  VLAN OPS  (ID 10): hosts h1–h10   → subred 10.0.10.1–10.0.10.10/24
  VLAN ADM  (ID 20): hosts h11–h20  → subred 10.0.20.1–10.0.20.10/24

  Justificación del tamaño (Ley 905/2004 — PyME colombiana):
    Una mediana empresa colombiana tiene entre 51 y 200 empleados.
    Un segmento de red típico concentra entre 10 y 20 estaciones de trabajo.
    OPS  = Área operativa/producción  (10 equipos)
    ADM  = Área administrativa/TI     (10 equipos)
    Total: 20 nodos → representa un piso de una sede PyME.

  Topología:
       [OPS h1-h10] ──s1──┐
                          s3──── Controlador Ryu (127.0.0.1:6633)
       [ADM h11-h20]──s2──┘

  Beneficio para M2:
    h1 (atacante OPS) puede alcanzar h2..h10 = 9 destinos únicos
    Umbral M2 = 8 → con un escaneo a los 9 hosts restantes M2 **sí dispara**

  Controlador: Ryu con OpenFlow 1.3
  Uso:
      sudo python3 topology_project.py
  Requiere:
      Mininet, Open vSwitch, Ryu corriendo en otra terminal:
      ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633
=============================================================================
"""

import sys as _sys

def _check_mininet():
    try:
        import mininet  # noqa
    except ImportError:
        print("\n[ERROR] Mininet no está en el PYTHONPATH de este intérprete.")
        print("        Mininet debe correrse con el Python del sistema, no de un venv.")
        print("\n  Soluciones:")
        print("  1. Usar el Python del sistema directamente:")
        print("       sudo /usr/bin/python3 topology_project.py")
        print("\n  2. O instalar mininet para Python:")
        print("       pip install mininet")
        print("       (si la versión del paquete es compatible)\n")
        _sys.exit(1)

_check_mininet()

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import re
import tempfile
import time
import subprocess

# ─── PARÁMETROS DE RED ───────────────────────────────────────────────────────
CONTROLLER_IP   = '127.0.0.1'
CONTROLLER_PORT = 6633
OPENFLOW_VER    = 'OpenFlow13'

VLAN_OPS = 10       # VLAN Operaciones    — hosts h1–h10
VLAN_ADM = 20       # VLAN Administración — hosts h11–h20

SUBNET_OPS = '10.0.10'   # .1 … .10
SUBNET_ADM = '10.0.20'   # .1 … .10

LINK_BW     = 100   # Mbps
LINK_DELAY  = '1ms'
LINK_LOSS   = 0

# ── Honeypot (VLAN 999) — ubicación que usará Ryu en R3c2 ────────────────────
VLAN_HONEYPOT    = 999
HONEYPOT_IP      = '10.0.99.1'
HONEYPOT_MAC     = '00:00:00:00:09:99'
HONEYPOT_S3_PORT = 3      # s3-eth3 → HONEYPOT_DPID=3, HONEYPOT_PUERTO=3
HONEYPOT_PORTS   = (22, 135, 139, 445, 3389, 5985)
REPO_DIR         = os.path.dirname(os.path.abspath(__file__))

# Filtro propio del honeypot: redirige a sí mismo los puertos críticos dirigidos
# a cualquier IP, solo acepta esos puertos y no inicia ninguna conexión.
NFT_HONEYPOT = '''
table ip honeypot {{
    chain pre {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname "honeypot-eth0" tcp dport {{ {puertos} }} redirect
    }}
    chain entrada {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "honeypot-eth0" tcp dport {{ {puertos} }} accept
    }}
    chain salida {{
        type filter hook output priority filter; policy drop;
        oifname "lo" accept
        ct state established,related accept
    }}
}}
'''

# ─── HELPERS ─────────────────────────────────────────────────────────────────
def set_vlan_port(switch, port, vlan_id, mode='access'):
    """
    Configura un puerto OVS como access (un host) o trunk (uplink entre switches).
    mode='access' : tráfico sin tag en el host, el switch añade el tag VLAN.
    mode='trunk'  : permite pasar múltiples VLANs entre switches.
    """
    sw_name = switch.name
    if mode == 'access':
        subprocess.call([
            'ovs-vsctl', 'set', 'port',
            f'{sw_name}-eth{port}',
            f'tag={vlan_id}'
        ])
        info(f'    [{sw_name}] eth{port} → VLAN {vlan_id} (access)\n')
    elif mode == 'trunk':
        subprocess.call([
            'ovs-vsctl', 'set', 'port',
            f'{sw_name}-eth{port}',
            f'trunks={VLAN_OPS},{VLAN_ADM}'
        ])
        info(f'    [{sw_name}] eth{port} → trunk (VLAN {VLAN_OPS},{VLAN_ADM})\n')


def assign_ip(host, ip, prefix=24, gw=None):
    """Asigna IP y gateway a un host."""
    host.cmd(f'ip addr flush dev {host.name}-eth0')
    host.cmd(f'ip addr add {ip}/{prefix} dev {host.name}-eth0')
    host.cmd(f'ip link set {host.name}-eth0 up')
    if gw:
        host.cmd(f'ip route add default via {gw}')


def configure_ovs_dpid(switch, dpid):
    """Fuerza el DPID del switch para identificación determinista en Ryu."""
    subprocess.call(['ovs-vsctl', 'set', 'bridge', switch.name,
                     f'other-config:datapath-id={dpid:016x}'])


def enable_stp(switch):
    """Habilita STP en el switch para evitar loops en la topología."""
    subprocess.call(['ovs-vsctl', 'set', 'bridge', switch.name,
                     'stp_enable=true'])


# ─── TOPOLOGÍA ───────────────────────────────────────────────────────────────
def build_topology():
    """
    Construye y levanta la red completa. Retorna el objeto Mininet.

    Diagrama lógico:
      h1  (OPS 10.0.10.1)  ──┐
      h2  (OPS 10.0.10.2)  ──┤
      ...                    ├──[s1, DPID=0x01]──eth11──[s3, DPID=0x03]──eth1──[s1]
      h10 (OPS 10.0.10.10) ──┘                           │
                                                   eth2──[s2, DPID=0x02]──eth1──[s2]
      h11 (ADM 10.0.20.1)  ──┐                           │
      h12 (ADM 10.0.20.2)  ──┤                   Controlador Ryu
      ...                    ├──[s2, DPID=0x02]──eth11──[s3]
      h20 (ADM 10.0.20.10) ──┘

    Con esta topología:
      - h1 es el host atacante simulado (IP 10.0.10.1)
      - h1 puede alcanzar h2..h10 = 9 destinos únicos en OPS
      - M2 umbral=8 → se dispara al escanear los 9 hosts restantes
    """
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
        waitConnected=True,
    )

    # ── Controlador remoto (Ryu) ─────────────────────────────────────────────
    info('\n*** Agregando controlador Ryu (RemoteController)\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    # ── Switches ─────────────────────────────────────────────────────────────
    info('*** Agregando switches OVS (OpenFlow 1.3)\n')
    sw_opts = dict(protocols=OPENFLOW_VER, failMode='secure')

    s1 = net.addSwitch('s1', dpid='0000000000000001', **sw_opts)  # Switch OPS
    s2 = net.addSwitch('s2', dpid='0000000000000002', **sw_opts)  # Switch ADM
    s3 = net.addSwitch('s3', dpid='0000000000000003', **sw_opts)  # Switch core

    # ── Hosts VLAN OPS (h1–h10, IPs 10.0.10.1–10.0.10.10) ──────────────────
    info('*** Agregando hosts VLAN OPS (10.0.10.0/24)\n')
    ops_hosts = []
    for i in range(1, 11):
        h = net.addHost(
            f'h{i}',
            ip=f'{SUBNET_OPS}.{i}/24',
            defaultRoute=f'via {SUBNET_OPS}.254',
            cls=None,
        )
        ops_hosts.append(h)
        info(f'    h{i} → {SUBNET_OPS}.{i}/24  [VLAN {VLAN_OPS}]\n')

    # ── Hosts VLAN ADM (h11–h20, IPs 10.0.20.1–10.0.20.10) ─────────────────
    info('*** Agregando hosts VLAN ADM (10.0.20.0/24)\n')
    adm_hosts = []
    for i in range(11, 21):
        h = net.addHost(
            f'h{i}',
            ip=f'{SUBNET_ADM}.{i-10}/24',
            defaultRoute=f'via {SUBNET_ADM}.254',
            cls=None,
        )
        adm_hosts.append(h)
        info(f'    h{i} → {SUBNET_ADM}.{i-10}/24  [VLAN {VLAN_ADM}]\n')

    # ── Enlaces host ↔ switch ─────────────────────────────────────────────────
    info('*** Creando enlaces host ↔ switch\n')
    link_params = dict(bw=LINK_BW, delay=LINK_DELAY, loss=LINK_LOSS)

    # OPS: h1-h10 → s1  (puertos 1–10 de s1)
    for h in ops_hosts:
        net.addLink(h, s1, **link_params)

    # ADM: h11-h20 → s2  (puertos 1–10 de s2)
    for h in adm_hosts:
        net.addLink(h, s2, **link_params)

    # ── Uplinks switch ↔ switch core ─────────────────────────────────────────
    info('*** Creando uplinks hacia switch core (s3)\n')
    net.addLink(s1, s3, **link_params)   # s1-eth11 ↔ s3-eth1
    net.addLink(s2, s3, **link_params)   # s2-eth11 ↔ s3-eth2

    # ── Honeypot en VLAN 999, colgado del core ───────────────────────────────
    info('*** Agregando honeypot (VLAN 999) en s3\n')
    honeypot = net.addHost('honeypot', ip=f'{HONEYPOT_IP}/24', mac=HONEYPOT_MAC)
    net.addLink(honeypot, s3, **link_params)   # honeypot-eth0 ↔ s3-eth3

    return net, c0, s1, s2, s3, ops_hosts, adm_hosts


def configure_vlans(s1, s2, s3, n_ops=10, n_adm=10):
    """
    Configura los puertos OVS con tags VLAN después de que Mininet
    haya creado las interfaces.

    s1 ports:  eth1-eth10 = access VLAN 10 (OPS hosts)
               eth11      = trunk hacia s3
    s2 ports:  eth1-eth10 = access VLAN 20 (ADM hosts)
               eth11      = trunk hacia s3
    s3 ports:  eth1       = trunk desde s1
               eth2       = trunk desde s2
    """
    info('\n*** Configurando VLANs en Open vSwitch\n')

    info(f'  [s1] Puertos 1-{n_ops} → VLAN {VLAN_OPS} access (OPS)\n')
    for port in range(1, n_ops + 1):
        set_vlan_port(s1, port, VLAN_OPS, mode='access')

    info(f'  [s1] Puerto {n_ops+1} → trunk\n')
    set_vlan_port(s1, n_ops + 1, None, mode='trunk')

    info(f'  [s2] Puertos 1-{n_adm} → VLAN {VLAN_ADM} access (ADM)\n')
    for port in range(1, n_adm + 1):
        set_vlan_port(s2, port, VLAN_ADM, mode='access')

    info(f'  [s2] Puerto {n_adm+1} → trunk\n')
    set_vlan_port(s2, n_adm + 1, None, mode='trunk')

    info(f'  [s3] Puertos 1-2 → trunk\n')
    set_vlan_port(s3, 1, None, mode='trunk')
    set_vlan_port(s3, 2, None, mode='trunk')


def setup_honeypot(net, s3):
    """
    Deja el honeypot en VLAN 999 con su filtro nft y arranca honeypot.py.
    Si nft falla, el honeypot queda apagado: nunca un honeypot sin su filtro.
    """
    hp = net.get('honeypot')
    info(f'\n*** Configurando honeypot ({HONEYPOT_IP}, VLAN {VLAN_HONEYPOT})\n')
    set_vlan_port(s3, HONEYPOT_S3_PORT, VLAN_HONEYPOT, mode='access')
    # Ruta on-link para responder a los hosts de OPS y ADM
    hp.cmd('ip route add 10.0.0.0/16 dev honeypot-eth0')

    reglas = NFT_HONEYPOT.format(puertos=', '.join(map(str, HONEYPOT_PORTS)))
    with tempfile.NamedTemporaryFile('w', suffix='.nft', delete=False) as f:
        f.write(reglas)
    salida = hp.cmd(f'nft -f {f.name} 2>&1; echo "rc=$?"')
    os.unlink(f.name)
    rc = re.search(r'rc=(\d+)\s*$', salida)
    if not rc or rc.group(1) != '0':
        hp.cmd('ip link set honeypot-eth0 down')
        info('\n' + '!' * 70 + '\n')
        info('  [ERROR] nft no pudo aplicar el filtro del honeypot:\n')
        info(f'  {salida.strip()}\n')
        info('  El honeypot queda APAGADO (honeypot-eth0 down) y honeypot.py NO se arranca.\n')
        info('!' * 70 + '\n')
        return False

    # logs/ del repo, con dueño el usuario que corrió sudo
    logs = os.path.join(REPO_DIR, 'logs')
    log = os.path.join(logs, 'honeypot.jsonl')
    out = os.path.join(logs, 'honeypot.out')
    os.makedirs(logs, exist_ok=True)
    open(log, 'a').close()
    open(out, 'a').close()
    if os.environ.get('SUDO_UID'):
        for p in (logs, log, out):
            os.chown(p, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
    hp.cmd(f'python3 {REPO_DIR}/honeypot.py --log {log} '
           f'> {out} 2>&1 &')
    info(f'    [OK] filtro nft aplicado; honeypot.py escuchando en {HONEYPOT_PORTS}\n')
    info(f'    [OK] log: {log}\n')
    return True


def verify_connectivity(net, ops_hosts, adm_hosts):
    """
    Prueba de conectividad intra-VLAN y verifica aislamiento inter-VLAN.
    """
    info('\n*** Verificación de conectividad intra-VLAN OPS\n')
    result = ops_hosts[0].cmd(f'ping -c2 -W1 {SUBNET_OPS}.2')
    if '2 received' in result or '1 received' in result:
        info('    [OK] h1 → h2 (OPS intra-VLAN): REACHABLE\n')
    else:
        info('    [WARN] h1 → h2: no responde aún (el controlador puede estar instalando flujos)\n')

    info('*** Verificación de aislamiento inter-VLAN (OPS → ADM)\n')
    result = ops_hosts[0].cmd(f'ping -c2 -W1 {SUBNET_ADM}.1')
    if '0 received' in result or 'unreachable' in result or '100%' in result:
        info('    [OK] h1 → h11 (OPS→ADM): BLOCKED (aislamiento correcto)\n')
    else:
        info('    [INFO] h1 → h11: respondió — revisar reglas VLAN en Ryu\n')


def print_summary(ops_hosts, adm_hosts):
    """Imprime tabla resumen de la topología levantada."""
    info('\n' + '='*70 + '\n')
    info('  TOPOLOGÍA LEVANTADA — RESUMEN (20 hosts / 2 VLANs)\n')
    info('='*70 + '\n')
    info(f'  {"Host":<8} {"IP":<18} {"VLAN":<10} {"Switch":<10} {"Propósito"}\n')
    info('-'*70 + '\n')
    for i in range(1, 11):
        role = 'Atacante simulado (h1)' if i == 1 else 'Workstation OPS'
        info(f'  h{i:<7} {SUBNET_OPS}.{i:<12} VLAN {VLAN_OPS}    s1          {role}\n')
    for i in range(1, 11):
        info(f'  h{i+10:<7} {SUBNET_ADM}.{i:<12} VLAN {VLAN_ADM}    s2          Workstation ADM\n')
    info(f'  {"honeypot":<8} {HONEYPOT_IP:<18} VLAN {VLAN_HONEYPOT}   s3-eth{HONEYPOT_S3_PORT}     '
         f'Honeypot (cuarentena VLAN)\n')
    info('-'*70 + '\n')
    info(f'  s1   → Switch OPS  (DPID: 0x0000000000000001)\n')
    info(f'  s2   → Switch ADM  (DPID: 0x0000000000000002)\n')
    info(f'  s3   → Switch Core (DPID: 0x0000000000000003)\n')
    info(f'  c0   → Controlador Ryu @ {CONTROLLER_IP}:{CONTROLLER_PORT}\n')
    info('='*70 + '\n')
    info('  Alcance de métricas desde h1 (10.0.10.1):\n')
    info('    M1: flujos hacia puertos críticos  (umbral=20 en 30s)\n')
    info('    M2: fan-out destinos únicos OPS     (umbral=8, alcanzable: 9 destinos h2..h10)\n')
    info('    M3: SMB breve+voluminoso            (polling OFPFlowStatsReply)\n')
    info('    M4: Packet-In flood                 (umbral=400/min)\n')
    info('    M5: flujos east-west inter-VLAN     (requiere tráfico h1→ADM)\n')
    info('='*70 + '\n')
    info('  Comandos útiles en la CLI de Mininet:\n')
    info('    pingall                        → prueba conectividad total\n')
    info('    h1 ping -c3 10.0.10.2         → ping intra-VLAN OPS\n')
    info('    h1 ping -c3 10.0.20.1         → ping inter-VLAN (debe fallar)\n')
    info('    h11 iperf -s &                → servidor iperf en ADM\n')
    info('    h1 iperf -c 10.0.20.1        → test ancho de banda\n')
    info('    dump                           → estado de todos los nodos\n')
    info('    links                          → estado de todos los enlaces\n')
    info('    sh ovs-vsctl show              → configuración OVS\n')
    info('    sh ovs-ofctl dump-flows s1 -O OpenFlow13  → flujos s1\n')
    info('='*70 + '\n\n')


# ─── MAIN ────────────────────────────────────────────────────────────────────
def run():
    setLogLevel('info')

    info('\n' + '='*70 + '\n')
    info('  INICIANDO TOPOLOGÍA SDN — PROYECTO DE GRADO\n')
    info('  Universidad Católica de Colombia — 2026\n')
    info('  20 hosts | 2 VLANs | 3 switches OVS | Controlador Ryu\n')
    info('='*70 + '\n')

    # 1. Construir la topología
    net, c0, s1, s2, s3, ops_hosts, adm_hosts = build_topology()

    # 2. Levantar la red
    info('\n*** Iniciando red Mininet\n')
    net.start()
    info('*** Red iniciada\n')

    # 3. Esperar que OVS registre los interfaces antes de configurar VLANs
    info('*** Esperando estabilización de Open vSwitch (3 s)...\n')
    time.sleep(3)

    # 4. Configurar VLANs en OVS
    configure_vlans(s1, s2, s3, n_ops=10, n_adm=10)
    setup_honeypot(net, s3)

    # 5. Esperar conexión de switches con el controlador Ryu
    info('\n*** Esperando conexión con el controlador Ryu (5 s)...\n')
    time.sleep(5)

    # 6. Resumen de topología
    print_summary(ops_hosts, adm_hosts)

    # 7. Verificación básica de conectividad
    verify_connectivity(net, ops_hosts, adm_hosts)

    # 8. Abrir CLI interactiva
    info('\n*** Abriendo CLI de Mininet — escribe "exit" para terminar\n\n')
    CLI(net)

    # 9. Limpiar al salir
    info('\n*** Deteniendo red y limpiando OVS\n')
    net.stop()
    subprocess.call(['mn', '--clean'])
    info('*** Limpieza completada\n')


if __name__ == '__main__':
    run()
