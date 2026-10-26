#!/usr/bin/env python3
"""
=============================================================================
CONTROLADOR RYU — PROYECTO DE GRADO
Universidad Católica de Colombia
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  Aplicación Ryu con OpenFlow 1.3 que implementa 3 capas de operación:

  CAPA 1 — NORMAL:
    • MAC learning con aislamiento VLAN (OPS=10 / ADM=20)
    • Monitoreo silencioso de las 5 métricas OpenFlow
    • Período de gracia de 30s al arrancar

  CAPA 2 — SOSPECHOSO (puntaje 30-59):
    • Rate-limiting en puertos críticos del host sospechoso
    • Tráfico forzado a pasar por el controlador (no se corta)
    • Log detallado del comportamiento

  CAPA 3 — CRÍTICO (puntaje ≥ 60):
    • OFPFlowMod DROP prioridad 100 → host aislado de la red
    • Construcción y envío de payload JSON al agente LLM
    • El agente LLM responde con pasos a ejecutar + alertas

  Sistema de puntuación ponderada (justificado por likelihood ratio):
    M5 flujos east-west   → peso 40 (especificidad ~99.9% vs tráfico benigno)
    M3 SMB breve+volum.   → peso 35 (especificidad ~99.7% vs tráfico benigno)
    M1 escaneo de flujos  → peso 25 (puede ocurrir en tráfico legítimo intenso)
    M2 fan-out destinos   → peso 20 (puede ocurrir en servidores de actualización)
    M4 flood Packet-In    → peso 15 (puede tener causas no maliciosas)
    Puntaje 0-29  → NORMAL      | 30-59 → SOSPECHOSO | ≥60 → CRÍTICO

  Métricas implementadas:
    M1 — Tasa de nuevos flujos hacia puertos críticos  (Packet-In, ventana 30s)
    M2 — Fan-out de destinos únicos                   (Packet-In, ventana 30s)
    M3 — Duración corta + volumen alto SMB            (OFPFlowStatsReply)
    M4 — Tasa de Packet-In por host                   (EventOFPPacketIn, tiempo real)
    M5 — Flujos east-west en puertos crit.            (monitor + umbral)

  CAMBIOS v2:
    - M1/M2 migrados de polling OFPFlowStats → Packet-In en tiempo real
      (OVS instala flujos L2, no L3, así que el polling no ve ipv4_src)
    - M4 con cooldown de 60s entre alertas del mismo host
    - Score se resetea cada SCORE_RESET_SEC para no acumular indefinidamente
    - Forwarding L2 sin VLAN tag (Mininet sin 802.1Q explícito en hosts)

Uso:
    ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633

Dependencias:
    pip install ryu
    (urllib de stdlib — sin requests, compatible con Python 3.8)
=============================================================================
"""

import ipaddress
import json
import os
import re
import time
import threading
import urllib.request
import urllib.error
import logging
from collections import defaultdict
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, vlan
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response

API_INSTANCE = 'ryu_ia_app'

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN — todos los parámetros ajustables están aquí
# ═══════════════════════════════════════════════════════════════════════════════

LOG_LEVEL        = logging.INFO
POLLING_INTERVAL = 10       # segundos entre ciclos de polling OFPFlowStats (M3)

# ── VLANs ─────────────────────────────────────────────────────────────────────
VLAN_OPS   = 10
VLAN_ADM   = 20
SUBNET_OPS = '10.0.10.'
SUBNET_ADM = '10.0.20.'

# ── Puertos críticos (movimiento lateral) ─────────────────────────────────────
CRITICAL_PORTS = {445, 135, 3389, 5985, 139}

# ── Umbrales de las 5 métricas ────────────────────────────────────────────────
THRESHOLD_M1_FLOWS_PER_30S = 20     # M1: nuevos flujos en 30s hacia puertos críticos
THRESHOLD_M2_UNIQUE_DSTS   = 8      # M2: destinos únicos en 30s
                                    # Justificación: red de 10 hosts/VLAN (PyME colombiana típica,
                                    # Ley 905/2004, BBVA Research 2024). Ryuk contacta 9/9 hosts;
                                    # umbral 8 detecta 89% del escaneo sin FP por tráfico legítimo.
THRESHOLD_M3_DURATION_SEC  = 5      # M3: duración máxima del flujo SMB (segundos)
THRESHOLD_M3_BYTES         = 512000 # M3: volumen mínimo del flujo SMB (~500 KB)
THRESHOLD_M4_PACKET_IN_MIN = 200    # M4: Packet-In por minuto desde un host
THRESHOLD_M5_COUNT         = 5      # M5: flujos W2W distintos en puertos críticos

# ── Ventanas temporales ───────────────────────────────────────────────────────
WINDOW_M1_M2_SEC = 30   # ventana deslizante para M1 y M2
WINDOW_M4_SEC    = 60   # ventana deslizante para M4

# ── Cooldowns ─────────────────────────────────────────────────────────────────
M4_ALERT_COOLDOWN_SEC = 60   # mínimo tiempo entre alertas M4 del mismo host
M1_ALERT_COOLDOWN_SEC = 10   # mínimo tiempo entre alertas M1 del mismo host
M2_ALERT_COOLDOWN_SEC = 10   # mínimo tiempo entre alertas M2 del mismo host
SCORE_RESET_SEC       = 300  # resetear score después de 5 min sin nueva métrica

# ── Sistema de puntuación ponderada ──────────────────────────────────────────
METRIC_WEIGHTS = {
    'M5': 40,
    'M3': 35,
    'M1': 25,
    'M2': 20,
    'M4': 15,
}

SCORE_NORMAL     = 0
SCORE_SUSPICIOUS = 30
SCORE_CRITICAL   = 60

# ── Período de gracia al arrancar ─────────────────────────────────────────────
STARTUP_GRACE_SEC = 30

# ── Destino del payload JSON (agente LLM) ─────────────────────────────────────
AGENT_URL     = 'http://localhost:8081/api/alertas'
AGENT_TIMEOUT = 5       # el agente responde en < 300 ms; el análisis ocurre después
AGENT_ENABLED = True    # True cuando el agente LLM esté corriendo
AGENT_TOKEN   = os.environ.get('AGENT_TOKEN', '')

# ── Rate-limit: parámetros de la Capa 2 ──────────────────────────────────────
RATE_LIMIT_IDLE_TIMEOUT = 60
RATE_LIMIT_HARD_TIMEOUT = 120

# ── Cuarentena (A6) ───────────────────────────────────────────────────────────
QUARANTINE_DROP_PORTS = (22, 135, 139, 445, 3389, 5985)  # TCP, DROP prioridad 110
QUARANTINE_ALLOW      = ((17, 53), (6, 53), (17, 67))    # DNS UDP/TCP y DHCP, prioridad 101

# ── Limitar tasa (A7) ─────────────────────────────────────────────────────────
LIMIT_PRIORITY     = 90      # por debajo del DROP 100: solo actúa cuando se quita
LIMIT_DEFAULT_KBPS = 1000
LIMIT_MAX_KBPS     = 0xFFFFFFFF   # rate del meter es uint32 en OpenFlow 1.3

# ── Cuarentena VLAN con honeypot (A8) ─────────────────────────────────────────
VLAN_CUARENTENA = 999
A8_PRIORITY     = 105     # sobre el DROP 100, que no se quita nunca en este modo
A8_COOKIE       = 0xA8    # marca las reglas cuyo packet-in se releva al honeypot


def _leer_honeypot():
    """Ubicación del honeypot (R3c1) desde el entorno; None si falta o es inválida."""
    def entero(valor):
        valor = valor.strip().lower()
        return int(valor, 16) if valor.startswith('0x') else int(valor)
    try:
        dpid   = entero(os.environ['HONEYPOT_DPID'])
        puerto = entero(os.environ['HONEYPOT_PUERTO'])
        mac    = os.environ['HONEYPOT_MAC'].strip().lower()
    except (KeyError, ValueError):
        return None
    if dpid <= 0 or puerto <= 0 or not re.fullmatch(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
        return None
    return {'dpid': dpid, 'puerto': puerto, 'mac': mac}


HONEYPOT = _leer_honeypot()   # sin honeypot no hay A8

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
logger = logging.getLogger('RyuSDN')


# ═══════════════════════════════════════════════════════════════════════════════
class SDNRansomwareDetector(app_manager.RyuApp):
    """
    Controlador SDN con detección de movimiento lateral en 3 capas.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tabla de MACs: {dpid: {mac: puerto}}
        self.mac_to_port = defaultdict(dict)

        # Datapaths registrados: {dpid: datapath}
        self.datapaths = {}

        # IPs de workstations conocidas
        self.workstation_ips = set()

        # Bitácora de tráfico por host
        # flows: lista de (ip_dst, timestamp, tp_dst) — para M1/M2
        # packet_in_times: timestamps de Packet-In — para M4
        # east_west: set de (ip_dst, tp_dst) W2W — para M5
        self.host_flow_log = defaultdict(lambda: {
            'flows':            [],
            'packet_in_times':  [],
            'east_west':        set(),
        })

        # Estado de alerta por host
        self.host_alert_state = defaultdict(lambda: {
            'level':             'NORMAL',
            'metrics_triggered': set(),
            'score':             0,
            'last_alert':        0,      # timestamp última alerta (cooldown M4)
            'last_metric_time':  0,      # para reset de score
        })

        # Snapshot de valores numéricos al momento del disparo
        self.metric_snapshot = defaultdict(dict)

        # Hosts con DROP instalado
        self.blocked_hosts = {}   # {ip: {'dpids': [int, ...], 'desde': 'ISO-8601Z'}}

        # Umbrales editables en tiempo de ejecución (mismos valores por defecto)
        self.umbrales = {
            'M1': THRESHOLD_M1_FLOWS_PER_30S,            # 20
            'M2': THRESHOLD_M2_UNIQUE_DSTS,              # 8
            'M3_DURACION_S': THRESHOLD_M3_DURATION_SEC,  # 5
            'M3_BYTES': THRESHOLD_M3_BYTES,              # 512000
            'M4': THRESHOLD_M4_PACKET_IN_MIN,            # 200
            'M5': THRESHOLD_M5_COUNT,                    # 5
            'SCORE_SOSPECHOSO': SCORE_SUSPICIOUS,        # 30
            'SCORE_CRITICO': SCORE_CRITICAL,             # 60
        }

        # Tiempo de arranque
        self._start_time = time.time()

        # Hilo de polling (solo para M3 ahora)
        self._polling_thread = hub.spawn(self._polling_loop)

        logger.info('=' * 60)
        logger.info('  Controlador SDN — 3 capas de detección activas  v2')
        logger.info(f'  Período de gracia: {STARTUP_GRACE_SEC}s')
        logger.info(f'  Puntaje SOSPECHOSO: >={self.umbrales["SCORE_SOSPECHOSO"]} puntos (rate-limit)')
        logger.info(f'  Puntaje CRITICO:    >={self.umbrales["SCORE_CRITICO"]} puntos (DROP + LLM)')
        logger.info(f'  Pesos: M5={METRIC_WEIGHTS["M5"]} M3={METRIC_WEIGHTS["M3"]} '
                    f'M1={METRIC_WEIGHTS["M1"]} M2={METRIC_WEIGHTS["M2"]} M4={METRIC_WEIGHTS["M4"]}')
        logger.info(f'  M1/M2: Packet-In en tiempo real (ventana {WINDOW_M1_M2_SEC}s)')
        logger.info(f'  M4 cooldown: {M4_ALERT_COOLDOWN_SEC}s entre alertas')
        logger.info(f'  Agente LLM: {"HABILITADO" if AGENT_ENABLED else "DESHABILITADO (modo log)"}')
        logger.info('=' * 60)
        if AGENT_ENABLED and not AGENT_TOKEN:
            logger.error('[AGENTE] AGENT_TOKEN vacío: el agente rechazará las alertas (401)')
        if HONEYPOT:
            logger.info(f'[A8] Honeypot en DPID={HONEYPOT["dpid"]:#018x} '
                        f'puerto {HONEYPOT["puerto"]} MAC {HONEYPOT["mac"]}')
        elif any(os.environ.get(v) for v in ('HONEYPOT_DPID', 'HONEYPOT_PUERTO', 'HONEYPOT_MAC')):
            logger.error('[A8] Variables HONEYPOT_* incompletas o inválidas: '
                         'cuarentena_vlan deshabilitada')

        kwargs['wsgi'].register(RyuIAApi, {API_INSTANCE: self})

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA BASE — CONEXIÓN DE SWITCHES
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.datapaths[dpid] = datapath
        logger.info(f'[SWITCH] Conectado: DPID={dpid:#018x}')

        # Regla table-miss (prioridad 0): todo sube al controlador
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        # Reglas de monitoreo M5
        self._install_m5_monitor_rules(datapath)

        # A8: el honeypot no alcanza a nadie por IPv4 salvo a hosts en vlan_cuarentena
        if HONEYPOT and dpid == HONEYPOT['dpid']:
            match = parser.OFPMatch(in_port=HONEYPOT['puerto'], eth_type=0x0800)
            self._add_flow(datapath, priority=100, match=match, actions=[])
            logger.info(f'[A8] DROP IPv4 desde el puerto del honeypot '
                        f'({HONEYPOT["puerto"]}) en DPID={dpid:#018x}')

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 1 — PROCESAMIENTO NORMAL (Packet-In)
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        # A8: lo que sube por las reglas de cuarentena VLAN solo se releva
        if msg.cookie == A8_COOKIE:
            self._relevo_honeypot(msg)
            return

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # Ignorar LLDP y STP
        if eth_pkt.ethertype in (0x88cc, 0x8942):
            return

        dst_mac  = eth_pkt.dst
        src_mac  = eth_pkt.src
        vlan_pkt = pkt.get_protocol(vlan.vlan)
        vlan_id  = vlan_pkt.vid if vlan_pkt else None
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        src_ip = ip_pkt.src if ip_pkt else None
        dst_ip = ip_pkt.dst if ip_pkt else None
        tp_dst = (tcp_pkt.dst_port if tcp_pkt else
                  udp_pkt.dst_port if udp_pkt else None)

        # ── MAC learning ──────────────────────────────────────────────────────
        self.mac_to_port[dpid][src_mac] = in_port

        # ── Registrar IP de workstation ───────────────────────────────────────
        if src_ip and (src_ip.startswith(SUBNET_OPS) or
                       src_ip.startswith(SUBNET_ADM)):
            self.workstation_ips.add(src_ip)

        # ── Período de gracia ─────────────────────────────────────────────────
        in_grace = (time.time() - self._start_time) < STARTUP_GRACE_SEC

        if src_ip and not in_grace and src_ip not in self.blocked_hosts:

            now = time.time()

            # ── M4: contar Packet-In por host ─────────────────────────────────
            self.host_flow_log[src_ip]['packet_in_times'].append(now)
            self._evaluate_m4(src_ip, datapath)

            # ── M1/M2: registrar flujos hacia puertos críticos ────────────────
            if dst_ip and tp_dst and tp_dst in CRITICAL_PORTS:
                self.host_flow_log[src_ip]['flows'].append(
                    (dst_ip, now, tp_dst)
                )
                self._evaluate_m1_m2(src_ip, datapath)

            # ── M5: flujos east-west ──────────────────────────────────────────
            if (dst_ip and tp_dst
                    and src_ip in self.workstation_ips
                    and dst_ip in self.workstation_ips
                    and tp_dst in CRITICAL_PORTS):

                ew_log = self.host_flow_log[src_ip]['east_west']
                ew_log.add((dst_ip, tp_dst))
                ew_count = len(ew_log)

                logger.debug(f'[M5] {src_ip}->{dst_ip}:{tp_dst} '
                             f'W2W acumulados: {ew_count}/{self.umbrales["M5"]}')

                if ew_count >= self.umbrales['M5']:
                    self._trigger_metric(
                        src_ip, 'M5', datapath, in_port,
                        msg=f'M5: {ew_count} flujos W2W en puertos criticos '
                            f'>= umbral {self.umbrales["M5"]}'
                    )

        # ── Aislamiento inter-VLAN ────────────────────────────────────────────
        if src_ip and dst_ip:
            src_ops = src_ip.startswith(SUBNET_OPS)
            dst_ops = dst_ip.startswith(SUBNET_OPS)
            if src_ops != dst_ops:
                logger.debug(f'[VLAN] Bloqueado inter-VLAN: {src_ip}->{dst_ip}')
                return

        # ── Forwarding L2 ─────────────────────────────────────────────────────
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Instalar flujo L2 si conocemos el puerto destino
        if (out_port != ofproto.OFPP_FLOOD
                and (src_ip is None or src_ip not in self.blocked_hosts)):
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(datapath, priority=1, match=match,
                           actions=actions,
                           idle_timeout=30, hard_timeout=60)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        datapath.send_msg(out)

    # ═══════════════════════════════════════════════════════════════════════════
    # EVALUACIÓN M1 / M2 — ventana deslizante en Packet-In
    # ═══════════════════════════════════════════════════════════════════════════
    def _evaluate_m1_m2(self, src_ip, datapath):
        """
        Evalúa M1 y M2 usando el log de flujos registrado en Packet-In.
        Solo cuenta flujos hacia CRITICAL_PORTS en los últimos WINDOW_M1_M2_SEC.
        """
        now    = time.time()
        cutoff = now - WINDOW_M1_M2_SEC

        # Limpiar entradas antiguas
        flows = self.host_flow_log[src_ip]['flows']
        flows[:] = [f for f in flows if f[1] > cutoff]

        m1_val = len(flows)
        m2_val = len({f[0] for f in flows})

        if m1_val > 0:
            logger.debug(f'[M1/M2] {src_ip} — flujos={m1_val} dsts={m2_val} '
                         f'en ventana {WINDOW_M1_M2_SEC}s')

        now   = time.time()
        state = self.host_alert_state[src_ip]

        if m1_val > self.umbrales['M1']:
            last_m1 = state.get('last_m1_alert', 0)
            if now - last_m1 >= M1_ALERT_COOLDOWN_SEC:
                state['last_m1_alert'] = now
                self._trigger_metric(
                    src_ip, 'M1', datapath, None,
                    msg=f'M1: {m1_val} flujos nuevos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {self.umbrales["M1"]}'
                )
        if m2_val > self.umbrales['M2']:
            last_m2 = state.get('last_m2_alert', 0)
            if now - last_m2 >= M2_ALERT_COOLDOWN_SEC:
                state['last_m2_alert'] = now
                self._trigger_metric(
                    src_ip, 'M2', datapath, None,
                    msg=f'M2: {m2_val} destinos unicos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {self.umbrales["M2"]}'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # EVALUACIÓN M4 — con cooldown
    # ═══════════════════════════════════════════════════════════════════════════
    def _evaluate_m4(self, src_ip, datapath):
        """Evalúa M4 con ventana deslizante y cooldown entre alertas."""
        now    = time.time()
        cutoff = now - WINDOW_M4_SEC

        log = self.host_flow_log[src_ip]
        log['packet_in_times'] = [t for t in log['packet_in_times'] if t > cutoff]
        rate = len(log['packet_in_times']) * (60 / WINDOW_M4_SEC)

        if rate > self.umbrales['M4']:
            state = self.host_alert_state[src_ip]
            last  = state.get('last_alert', 0)

            if now - last >= M4_ALERT_COOLDOWN_SEC:
                state['last_alert'] = now
                self._trigger_metric(
                    src_ip, 'M4', datapath, None,
                    msg=f'M4: {rate:.0f} Packet-In/min '
                        f'> umbral {self.umbrales["M4"]}'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # POLLING — solo M3 (requiere byte_count de OFPFlowStatsReply)
    # ═══════════════════════════════════════════════════════════════════════════
    def _polling_loop(self):
        hub.sleep(STARTUP_GRACE_SEC + 5)
        logger.info(f'[POLLING] Iniciado cada {POLLING_INTERVAL}s (solo M3)')
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                self._request_flow_stats(datapath)
            hub.sleep(POLLING_INTERVAL)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(
            datapath, flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0, cookie_mask=0,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Evalúa solo M3 (SMB breve y voluminoso) con datos de OVS."""
        body     = ev.msg.body
        datapath = ev.msg.datapath

        flows_by_src = defaultdict(list)
        for stat in body:
            m      = stat.match
            src_ip = m.get('ipv4_src')
            dst_ip = m.get('ipv4_dst')
            tp_dst = m.get('tcp_dst') or m.get('udp_dst')
            if src_ip and dst_ip:
                flows_by_src[src_ip].append({
                    'dst_ip':   dst_ip,
                    'tp_dst':   tp_dst,
                    'duration': stat.duration_sec,
                    'bytes':    stat.byte_count,
                })

        for src_ip, flows in flows_by_src.items():
            if src_ip in self.blocked_hosts:
                continue

            # M3: flujo SMB breve y voluminoso
            m3_flow = next((
                f for f in flows
                if f['tp_dst'] == 445
                and f['duration'] < self.umbrales['M3_DURACION_S']
                and f['bytes']    > self.umbrales['M3_BYTES']
            ), None)

            if m3_flow:
                self.metric_snapshot[src_ip]['M3_duration'] = m3_flow['duration']
                self.metric_snapshot[src_ip]['M3_bytes']    = m3_flow['bytes']
                self._trigger_metric(
                    src_ip, 'M3', datapath, None,
                    msg=f'M3: flujo SMB <{self.umbrales["M3_DURACION_S"]}s '
                        f'y >{self.umbrales["M3_BYTES"]}B detectado '
                        f'({m3_flow["bytes"]}B en {m3_flow["duration"]}s)'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # MOTOR DE ALERTAS — decide la capa de respuesta
    # ═══════════════════════════════════════════════════════════════════════════
    def _trigger_metric(self, src_ip, metric_id, datapath, in_port, msg=''):
        """
        Sistema de puntuación ponderada.
        Cada métrica nueva suma su peso. El score se resetea si pasan
        SCORE_RESET_SEC sin que se dispare ninguna métrica nueva.
        """
        elapsed = time.time() - self._start_time
        if elapsed < STARTUP_GRACE_SEC:
            remaining = int(STARTUP_GRACE_SEC - elapsed)
            logger.debug(f'[GRACIA] {src_ip}/{metric_id} ignorada '
                         f'({remaining}s restantes)')
            return

        state = self.host_alert_state[src_ip]
        now   = time.time()

        # Reset de score si pasó mucho tiempo sin nuevas métricas
        if (state['last_metric_time'] > 0
                and now - state['last_metric_time'] > SCORE_RESET_SEC
                and state['level'] == 'NORMAL'):
            logger.info(f'[SCORE] {src_ip} — score reseteado '
                        f'(>{SCORE_RESET_SEC}s sin actividad)')
            state['metrics_triggered'] = set()
            state['score']             = 0

        state['last_metric_time'] = now
        peso = METRIC_WEIGHTS.get(metric_id, 0)

        # Solo sumar peso si es la primera vez que se dispara esta métrica
        es_nueva = metric_id not in state['metrics_triggered']
        if es_nueva:
            state['metrics_triggered'].add(metric_id)
            state['score'] += peso

        score = state['score']

        # Guardar valor numérico para el JSON (el texto después de "Mx:")
        cuerpo = msg.split(':', 1)[1] if ':' in msg else msg
        nums = re.findall(r'\d+\.?\d*', cuerpo)
        if nums:
            self.metric_snapshot[src_ip][metric_id] = float(nums[0])

        logger.warning(
            f'[{metric_id}] {src_ip} — {msg} '
            f'| peso={peso} | puntaje={score} '
            f'| metricas={sorted(state["metrics_triggered"])}'
        )

        prev_level = state['level']

        # ── CAPA 2: SOSPECHOSO ────────────────────────────────────────────────
        if self.umbrales['SCORE_SOSPECHOSO'] <= score < self.umbrales['SCORE_CRITICO']:
            if prev_level == 'NORMAL':
                state['level'] = 'SOSPECHOSO'
                logger.warning(
                    f'[CAPA 2] {src_ip} -> SOSPECHOSO '
                    f'(puntaje={score}, '
                    f'metricas={sorted(state["metrics_triggered"])}) '
                    f'— aplicando rate-limit'
                )
                dp = datapath or next(iter(self.datapaths.values()), None)
                if dp:
                    self._apply_rate_limit(dp, src_ip)

        # ── CAPA 3: CRITICO ───────────────────────────────────────────────────
        elif score >= self.umbrales['SCORE_CRITICO']:
            state['level'] = 'CRITICO'
            if src_ip not in self.blocked_hosts:
                logger.critical(
                    f'[CAPA 3] {src_ip} -> CRITICO '
                    f'(puntaje={score}, '
                    f'metricas={sorted(state["metrics_triggered"])}) '
                    f'— DROP + escalando al agente LLM'
                )
                dp = datapath or next(iter(self.datapaths.values()), None)
                if dp:
                    self._block_host(dp, src_ip)
                self._send_json_alert(src_ip, state, dp)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 2 — RATE-LIMIT
    # ═══════════════════════════════════════════════════════════════════════════
    def _apply_rate_limit(self, datapath, src_ip):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instaladas = 0
        for port in CRITICAL_PORTS:
            try:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ip_proto=6,
                    tcp_dst=port,
                )
                actions = [parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                )]
                self._add_flow(
                    datapath, priority=20, match=match, actions=actions,
                    idle_timeout=RATE_LIMIT_IDLE_TIMEOUT,
                    hard_timeout=RATE_LIMIT_HARD_TIMEOUT,
                )
                instaladas += 1
            except Exception as e:
                logger.debug(f'[RATE-LIMIT] Error en puerto {port}: {e}')

        logger.warning(f'[CAPA 2] Rate-limit aplicado a {src_ip} '
                       f'en {instaladas} puertos criticos '
                       f'(expira en {RATE_LIMIT_IDLE_TIMEOUT}s)')

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 3 — DROP + JSON AL AGENTE LLM
    # ═══════════════════════════════════════════════════════════════════════════
    def _block_host(self, datapath, src_ip):
        """DROP prioridad 100 en TODOS los switches conectados."""
        dpids = []
        for dpid, dp in list(self.datapaths.items()):
            parser = dp.ofproto_parser
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self._add_flow(dp, priority=100, match=match, actions=[],
                           idle_timeout=0, hard_timeout=0)
            dpids.append(dpid)
        self.blocked_hosts[src_ip] = {
            'dpids': dpids,
            'desde': datetime.utcnow().isoformat() + 'Z',
            'modo': 'drop_total',
        }
        logger.critical(f'[CAPA 3] {src_ip} — DROP en {len(dpids)} switch(es)')

    def _send_json_alert(self, src_ip, state, datapath):
        snap      = self.metric_snapshot.get(src_ip, {})
        log       = self.host_flow_log.get(src_ip, {})
        now       = time.time()
        cutoff    = now - WINDOW_M1_M2_SEC
        triggered = sorted(state['metrics_triggered'])

        recent_flows = [f for f in log.get('flows', []) if f[1] > cutoff]
        m1_val = snap.get('M1', len(recent_flows))
        m2_val = snap.get('M2', len({f[0] for f in recent_flows}))
        pkt_times = [t for t in log.get('packet_in_times', [])
                     if t > now - WINDOW_M4_SEC]
        m4_val = snap.get('M4', round(len(pkt_times) * (60 / WINDOW_M4_SEC), 1))

        payload = {
            'timestamp':           datetime.utcnow().isoformat() + 'Z',
            'alerta_nivel':        'CRITICO',
            'host_origen':         src_ip,
            'dpid_switch':         f'{datapath.id:#018x}' if datapath else 'unknown',
            'contexto_topologico': self._get_topology_context(src_ip),
            'metricas': {
                'M1_nuevos_flujos_por_30s':   m1_val,
                'M2_destinos_unicos_por_30s': m2_val,
                'M3_smb_anomalo':             'M3' in triggered,
                'M3_duracion_seg':            snap.get('M3_duration', None),
                'M3_bytes':                   snap.get('M3_bytes', None),
                'M4_packet_in_por_min':       m4_val,
                'M5_flujos_east_west':        'M5' in triggered,
                'M5_count':                   snap.get('M5', len(log.get('east_west', set()))),
            },
            'puntaje_total':       state['score'],
            'puntaje_maximo':      sum(METRIC_WEIGHTS.values()),
            'pesos_metricas':      {m: METRIC_WEIGHTS[m]
                                    for m in triggered if m in METRIC_WEIGHTS},
            'umbrales_superados':  triggered,
            'ioc_activados':       self._map_ioc(triggered),
            'accion_ryu_previa':   f'OFPFlowMod DROP prioridad 100 — {src_ip} aislado',
            'solicitud_al_agente': (
                'Analiza el incidente. Responde SOLO con un JSON con estos campos: '
                'veredicto (confirmado/falso_positivo/indeterminado/ya_contenido), '
                'severidad (critica/alta/media), '
                'confianza (0-100), '
                'nivel_autonomia (1/2/3), '
                'acciones_automaticas (lista), '
                'acciones_pendientes_aprobacion (lista), '
                'hosts_en_riesgo (lista de IPs), '
                'mensaje_telegram (texto para el operador SOC), '
                'recomendaciones_forenses (lista), '
                'actualizar_estado_red ({nivel_alerta_red: NORMAL|MEDIO|ALTO|CRITICO}).'
            ),
        }

        logger.info(f'[CAPA 3] Payload JSON para {src_ip}:\n'
                    f'{json.dumps(payload, indent=2, ensure_ascii=False)}')

        if AGENT_ENABLED:
            thread = threading.Thread(
                target=self._post_to_agent,
                args=(payload,),
                daemon=True,
            )
            thread.start()
        else:
            logger.info('[AGENTE] AGENT_ENABLED=False — '
                        'JSON registrado en log, no enviado al agente.')

    def _post_to_agent(self, payload):
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req  = urllib.request.Request(
            AGENT_URL,
            data=data,
            headers={'Content-Type': 'application/json',
                     'X-Agent-Token': AGENT_TOKEN},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
                body   = resp.read().decode('utf-8')
                status = resp.status
                logger.info(f'[AGENTE] HTTP {status} — respuesta recibida')
                try:
                    respuesta = json.loads(body)
                    self._ejecutar_respuesta_agente(payload['host_origen'], respuesta)
                except json.JSONDecodeError:
                    logger.warning(f'[AGENTE] Respuesta no JSON: {body[:200]}')
        except urllib.error.URLError:
            logger.warning(f'[AGENTE] No disponible en {AGENT_URL} '
                           '— JSON quedó en log')
        except Exception as e:
            logger.error(f'[AGENTE] Error inesperado: {e}')

    def _ejecutar_respuesta_agente(self, src_ip, respuesta):
        veredicto = respuesta.get('veredicto', 'indeterminado')
        confianza = respuesta.get('confianza', 0)
        nivel     = respuesta.get('nivel_autonomia', 1)
        acciones_a = respuesta.get('acciones_automaticas', [])
        acciones_p = respuesta.get('acciones_pendientes_aprobacion', [])
        forenses   = respuesta.get('recomendaciones_forenses', [])
        nivel_red  = respuesta.get('actualizar_estado_red', {}).get('nivel_alerta_red', '')

        logger.info(f'[AGENTE] Veredicto:  {veredicto} ({confianza}% confianza)')
        logger.info(f'[AGENTE] Nivel HITL: {nivel}')
        logger.info(f'[AGENTE] Auto:       {acciones_a}')
        logger.info(f'[AGENTE] Pendientes: {acciones_p}')
        if nivel_red:
            logger.info(f'[AGENTE] Nivel red:  {nivel_red}')
        if forenses:
            logger.info(f'[AGENTE] Forenses:   {forenses}')

        if veredicto in ('confirmado', 'ya_contenido'):
            logger.info(f'[AGENTE] Ataque {veredicto} — DROP mantenido para {src_ip}')
        elif veredicto == 'indeterminado':
            logger.warning(f'[AGENTE] Indeterminado para {src_ip} '
                           '— DROP mantenido hasta revision manual')
        else:
            logger.warning(f'[AGENTE] Veredicto desconocido: {veredicto}')

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITOR M5 — reglas de observación east-west
    # ═══════════════════════════════════════════════════════════════════════════
    def _install_m5_monitor_rules(self, datapath):
        """
        Instala reglas de monitoreo W2W en puertos críticos.
        Prioridad 10 — el paquete sube al controlador Y se reenvía normalmente.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid    = datapath.id
        count   = 0

        for tp_dst in CRITICAL_PORTS:
            for subred in (SUBNET_OPS, SUBNET_ADM):
                for src_s in range(1, 6):
                    for dst_s in range(1, 6):
                        if src_s == dst_s:
                            continue
                        try:
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ipv4_src=f'{subred}{src_s}',
                                ipv4_dst=f'{subred}{dst_s}',
                                ip_proto=6,
                                tcp_dst=tp_dst,
                            )
                            actions = [
                                parser.OFPActionOutput(
                                    ofproto.OFPP_CONTROLLER,
                                    ofproto.OFPCML_NO_BUFFER
                                ),
                                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                            ]
                            self._add_flow(
                                datapath, priority=10,
                                match=match, actions=actions,
                                idle_timeout=0, hard_timeout=0,
                            )
                            count += 1
                        except Exception:
                            pass

        logger.info(f'[M5] {count} reglas de monitoreo W2W instaladas '
                    f'en DPID={dpid:#018x}')

    # ═══════════════════════════════════════════════════════════════════════════
    # UTILIDADES
    # ═══════════════════════════════════════════════════════════════════════════
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, table_id=0, cookie=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = (
            [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            if actions else
            [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        )
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id,
            cookie=cookie,
        )
        return datapath.send_msg(mod)

    def _map_ioc(self, triggered):
        t = set(triggered)
        iocs = []
        if {'M1', 'M2'}.issubset(t): iocs.append('IOC-01')
        if 'M3' in t:                iocs.append('IOC-02')
        if 'M4' in t:                iocs.append('IOC-03')
        if 'M5' in t:                iocs.append('IOC-04')
        if {'M5', 'M1'}.issubset(t): iocs.append('IOC-07')
        score = sum(METRIC_WEIGHTS.get(m, 0) for m in t)
        if score >= self.umbrales['SCORE_CRITICO']:  iocs.append('IOC-05')
        return sorted(set(iocs))

    def _get_topology_context(self, src_ip):
        if src_ip.startswith(SUBNET_OPS):
            return f'VLAN OPS (ID={VLAN_OPS}), subred {SUBNET_OPS}0/24'
        if src_ip.startswith(SUBNET_ADM):
            return f'VLAN ADM (ID={VLAN_ADM}), subred {SUBNET_ADM}0/24'
        return 'subred desconocida'

    def desbloquear_host(self, ip):
        info = self.blocked_hosts.pop(ip, None)
        if info is None:
            return None
        borradas = 0
        for dpid in info['dpids']:
            dp = self.datapaths.get(dpid)
            if not dp:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=100,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(eth_type=0x0800, ipv4_src=ip),
            )
            dp.send_msg(mod)
            # Se borra SIEMPRE todo lo que pudo quedar del host (aunque una
            # transacción haya fallado a medias); el conteo sigue el modo actual
            modo = info.get('modo')
            if modo != 'limitado':   # en limitado el DROP 100 ya no existe
                borradas += 1
            for prio, match, _ in self._reglas_cuarentena(dp, ip):
                self._borrar_regla(dp, prio, match)
                if modo == 'cuarentena':
                    borradas += 1
            if 'meter_id' in info:
                self._quitar_limite(dp, ip, info['meter_id'])
            else:
                self._borrar_regla(dp, LIMIT_PRIORITY,
                                   parser.OFPMatch(eth_type=0x0800, ipv4_src=ip))
            if modo == 'limitado':
                borradas += 1
            for prio, match, _ in self._reglas_vlan_ida(dp, ip):
                self._borrar_regla(dp, prio, match)
                if modo == 'vlan_cuarentena':
                    borradas += 1
        hp_dp = self.datapaths.get(HONEYPOT['dpid']) if HONEYPOT else None
        if hp_dp:
            for prio, match, _ in self._reglas_vlan_vuelta(hp_dp, ip):
                self._borrar_regla(hp_dp, prio, match)
                if modo == 'vlan_cuarentena':
                    borradas += 1
        # Limpiar TODO el estado del host para que no se vuelva a bloquear de inmediato
        self.host_alert_state.pop(ip, None)
        self.metric_snapshot.pop(ip, None)
        self.host_flow_log.pop(ip, None)
        logger.warning(f'[API] {ip} desbloqueado por el operador ({borradas} regla(s))')
        return borradas

    def _reglas_cuarentena(self, dp, ip):
        """(prioridad, match, actions) de las reglas propias de la cuarentena.
        El DROP de prioridad 100 (solo IPv4, así que ARP pasa) es el mismo del bloqueo total."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        reglas = []
        for port in QUARANTINE_DROP_PORTS:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip,
                                    ip_proto=6, tcp_dst=port)
            reglas.append((110, match, []))
        for proto, port in QUARANTINE_ALLOW:
            campo = {'tcp_dst': port} if proto == 6 else {'udp_dst': port}
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip,
                                    ip_proto=proto, **campo)
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
            reglas.append((101, match, actions))
        return reglas

    def _borrar_regla(self, dp, priority, match):
        ofp = dp.ofproto
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=priority,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match,
        )
        return dp.send_msg(mod)

    def _instalar_limite(self, dp, ip, meter_id, kbps, existe):
        """Meter OF1.3 (banda DROP a kbps) + regla LIMIT_PRIORITY que reenvía con NORMAL."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        meter = parser.OFPMeterMod(
            dp, command=ofp.OFPMC_MODIFY if existe else ofp.OFPMC_ADD,
            flags=ofp.OFPMF_KBPS, meter_id=meter_id,
            bands=[parser.OFPMeterBandDrop(rate=kbps, burst_size=0)],
        )
        inst = [parser.OFPInstructionMeter(meter_id),
                parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=LIMIT_PRIORITY, instructions=inst,
            match=parser.OFPMatch(eth_type=0x0800, ipv4_src=ip),
        )
        return dp.send_msg(meter) and dp.send_msg(mod)

    def _quitar_limite(self, dp, ip, meter_id):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ok = self._borrar_regla(dp, LIMIT_PRIORITY,
                                parser.OFPMatch(eth_type=0x0800, ipv4_src=ip))
        meter = parser.OFPMeterMod(dp, command=ofp.OFPMC_DELETE, meter_id=meter_id)
        return dp.send_msg(meter) and ok

    def _reglas_vlan_ida(self, dp, ip):
        """A8, en los switches del host: TCP a puertos críticos -> controlador (relevo)."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        return [(A8_PRIORITY,
                 parser.OFPMatch(eth_type=0x0800, ipv4_src=ip, ip_proto=6, tcp_dst=port),
                 actions)
                for port in QUARANTINE_DROP_PORTS]

    def _reglas_vlan_vuelta(self, dp, ip):
        """A8, en el switch del honeypot: sus respuestas TCP al host -> controlador."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        return [(A8_PRIORITY,
                 parser.OFPMatch(in_port=HONEYPOT['puerto'], eth_type=0x0800,
                                 ipv4_dst=ip, ip_proto=6, tcp_src=port),
                 actions)
                for port in QUARANTINE_DROP_PORTS]

    def _relevo_honeypot(self, msg):
        """
        A8: entrega al honeypot lo que el host en vlan_cuarentena envía a un
        puerto crítico (con la MAC del honeypot) y le devuelve al host las
        respuestas del honeypot, por la ubicación aprendida en la ida.
        Nunca inunda: si no hay a dónde enviarlo, se descarta.
        """
        dp      = msg.datapath
        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if not (HONEYPOT and eth_pkt and ip_pkt and tcp_pkt):
            return
        in_port = msg.match['in_port']

        if dp.id == HONEYPOT['dpid'] and in_port == HONEYPOT['puerto']:
            # Vuelta: honeypot -> host
            info = self.blocked_hosts.get(ip_pkt.dst)
            ubicacion = (info.get('ubicacion')
                         if info and info.get('modo') == 'vlan_cuarentena' else None)
            if not ubicacion:
                logger.warning(f'[A8] Respuesta del honeypot a {ip_pkt.dst} descartada: '
                               f'ubicación del host desconocida')
                return
            destino_dpid, puerto, mac = ubicacion
        else:
            # Ida: host -> honeypot
            info = self.blocked_hosts.get(ip_pkt.src)
            if not info or info.get('modo') != 'vlan_cuarentena':
                return
            info['ubicacion'] = (dp.id, in_port, eth_pkt.src)
            destino_dpid, puerto, mac = HONEYPOT['dpid'], HONEYPOT['puerto'], HONEYPOT['mac']
            if tcp_pkt.bits & tcp.TCP_SYN and not tcp_pkt.bits & tcp.TCP_ACK:
                logger.warning(f'[A8] {ip_pkt.src}:{tcp_pkt.src_port} -> '
                               f'{ip_pkt.dst}:{tcp_pkt.dst_port} relevado al honeypot')

        destino = self.datapaths.get(destino_dpid)
        if destino is None:
            logger.warning(f'[A8] Paquete descartado: DPID={destino_dpid:#018x} no conectado')
            return
        parser, ofp = destino.ofproto_parser, destino.ofproto
        destino.send_msg(parser.OFPPacketOut(
            datapath=destino, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionSetField(eth_dst=mac), parser.OFPActionOutput(puerto)],
            data=msg.data,
        ))

    def cambiar_modo(self, ip, modo, kbps=None):
        """
        Pasa un host bloqueado a 'cuarentena', 'limitado' o 'drop_total'
        (A6/A7, notas C2). El modo nuevo se instala antes de quitar el DROP
        total; en cuarentena el DROP de 100 no se quita nunca, en limitado se
        quita al final. El modo de origen lo valida la API (409). Devuelve None
        si el host no está bloqueado, True si quedó en el modo pedido y False
        si falló en algún switch (en ese caso queda en drop_total).
        """
        info = self.blocked_hosts.get(ip)
        if info is None:
            return None
        dps = [self.datapaths.get(dpid) for dpid in info['dpids']]
        actual = info.get('modo', 'drop_total')
        ok = True

        if modo in ('cuarentena', 'limitado', 'vlan_cuarentena'):
            if modo == 'limitado' and 'meter_id' not in info:
                usados = {i.get('meter_id') for i in self.blocked_hosts.values()}
                info['meter_id'] = next(n for n in range(1, len(usados) + 2)
                                        if n not in usados)
            hp_dp = None
            if modo == 'vlan_cuarentena':
                # Primero la vuelta en el switch del honeypot, luego la ida
                hp_dp = self.datapaths.get(HONEYPOT['dpid']) if HONEYPOT else None
                ok = hp_dp is not None and all([
                    self._add_flow(hp_dp, prio, match, actions, cookie=A8_COOKIE)
                    for prio, match, actions in self._reglas_vlan_vuelta(hp_dp, ip)])
            alcanzados = []
            for dp in (dps if ok else []):
                if dp is None:
                    ok = False
                    break
                alcanzados.append(dp)
                if modo == 'cuarentena':
                    enviados = all([self._add_flow(dp, prio, match, actions)
                                    for prio, match, actions in self._reglas_cuarentena(dp, ip)])
                elif modo == 'vlan_cuarentena':
                    enviados = all([self._add_flow(dp, prio, match, actions, cookie=A8_COOKIE)
                                    for prio, match, actions in self._reglas_vlan_ida(dp, ip)])
                else:
                    enviados = self._instalar_limite(dp, ip, info['meter_id'], kbps,
                                                     existe=(actual == 'limitado'))
                if not enviados:
                    ok = False
                    break
            if ok and modo == 'limitado':
                # Recién ahora se quita el DROP total: el host sale por la regla con meter
                for dp in dps:
                    match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                    ok = self._borrar_regla(dp, 100, match) and ok
            if ok:
                info['modo'] = modo
                if modo == 'limitado':
                    info['kbps'] = kbps
                    logger.warning(f'[API] {ip} -> limitado a {kbps} kbps '
                                   f'en {len(dps)} switch(es)')
                elif modo == 'vlan_cuarentena':
                    logger.warning(f'[API] {ip} -> vlan_cuarentena (VLAN {VLAN_CUARENTENA}, '
                                   f'honeypot) en {len(dps)} switch(es)')
                else:
                    logger.warning(f'[API] {ip} -> cuarentena en {len(dps)} switch(es)')
                return True
            # Reversión: DROP total de vuelta y borrar lo instalado
            if modo == 'cuarentena':
                for dp in alcanzados:
                    for prio, match, _ in self._reglas_cuarentena(dp, ip):
                        self._borrar_regla(dp, prio, match)
            elif modo == 'vlan_cuarentena':
                if hp_dp:
                    for prio, match, _ in self._reglas_vlan_vuelta(hp_dp, ip):
                        self._borrar_regla(hp_dp, prio, match)
                for dp in alcanzados:
                    for prio, match, _ in self._reglas_vlan_ida(dp, ip):
                        self._borrar_regla(dp, prio, match)
            else:
                destinos = [dp for dp in dps if dp] if actual == 'limitado' else alcanzados
                for dp in [dp for dp in dps if dp]:
                    match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                    self._add_flow(dp, 100, match, [])
                for dp in destinos:
                    self._quitar_limite(dp, ip, info['meter_id'])
        else:
            for dp in dps:
                if dp is None:
                    ok = False
                    continue
                match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                ok = self._add_flow(dp, 100, match, []) and ok
                for prio, match, _ in self._reglas_cuarentena(dp, ip):
                    ok = self._borrar_regla(dp, prio, match) and ok
                if actual == 'limitado':
                    ok = self._quitar_limite(dp, ip, info['meter_id']) and ok
                if actual == 'vlan_cuarentena':
                    for prio, match, _ in self._reglas_vlan_ida(dp, ip):
                        ok = self._borrar_regla(dp, prio, match) and ok
            if actual == 'vlan_cuarentena':
                hp_dp = self.datapaths.get(HONEYPOT['dpid']) if HONEYPOT else None
                if hp_dp is None:
                    ok = False
                else:
                    for prio, match, _ in self._reglas_vlan_vuelta(hp_dp, ip):
                        ok = self._borrar_regla(hp_dp, prio, match) and ok

        info['modo'] = 'drop_total'
        info.pop('kbps', None)
        info.pop('ubicacion', None)
        if ok:
            logger.warning(f'[API] {ip} -> drop_total en {len(dps)} switch(es)')
        else:
            logger.error(f'[API] {ip} — fallo al pasar a {modo}: queda en drop_total')
        return ok


# ═══════════════════════════════════════════════════════════════════════════════
# API REST (A5) — puerto 8080, todas las rutas exigen X-Agent-Token
# ═══════════════════════════════════════════════════════════════════════════════
def _json(cuerpo, status=200):
    return Response(status=status, content_type='application/json',
                    charset='utf-8', body=json.dumps(cuerpo).encode('utf-8'))


class RyuIAApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[API_INSTANCE]

    def _autorizado(self, req):
        import hmac
        token = req.headers.get('X-Agent-Token', '')
        # En bytes: compare_digest no acepta texto con caracteres no ASCII
        return bool(AGENT_TOKEN) and hmac.compare_digest(
            token.encode('utf-8'), AGENT_TOKEN.encode('utf-8'))

    @route('ryu_ia', '/ryu/estado', methods=['GET'])
    def estado(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        return _json({
            'switches': [f'{d:#018x}' for d in self.app.datapaths],
            'hosts_bloqueados': len(self.app.blocked_hosts),
            'umbrales': self.app.umbrales,
            'version': '2.0',
            'pesos': METRIC_WEIGHTS,
            'capacidades': ['cuarentena', 'limitar_tasa']
                           + (['cuarentena_vlan'] if HONEYPOT else []),
        })

    @route('ryu_ia', '/ryu/hosts/bloqueados', methods=['GET'])
    def bloqueados(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        filas = []
        for ip, info in self.app.blocked_hosts.items():
            fila = {'ip': ip,
                    'dpid': f'{info["dpids"][0]:#018x}' if info['dpids'] else None,
                    'desde': info['desde'], 'modo': info.get('modo', 'drop_total')}
            if fila['modo'] == 'limitado':
                fila['kbps'] = info['kbps']
            if fila['modo'] == 'vlan_cuarentena':
                fila['vlan'] = VLAN_CUARENTENA
            filas.append(fila)
        return _json(filas)

    @route('ryu_ia', '/ryu/hosts/{ip}/desbloquear', methods=['POST'])
    def desbloquear(self, req, ip, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return _json({'error': 'ip inválida'}, 422)
        borradas = self.app.desbloquear_host(ip)
        if borradas is None:
            return _json({'error': 'host no bloqueado'}, 404)
        return _json({'ok': True, 'ip': ip, 'reglas_borradas': borradas})

    @route('ryu_ia', '/ryu/hosts/{ip}/cuarentena', methods=['POST'])
    def cuarentena(self, req, ip, **kwargs):
        return self._cambiar_modo(req, ip, 'cuarentena')

    @route('ryu_ia', '/ryu/hosts/{ip}/bloqueo_total', methods=['POST'])
    def bloqueo_total(self, req, ip, **kwargs):
        return self._cambiar_modo(req, ip, 'drop_total')

    @route('ryu_ia', '/ryu/hosts/{ip}/limitar_tasa', methods=['POST'])
    def limitar_tasa(self, req, ip, **kwargs):
        return self._cambiar_modo(req, ip, 'limitado')

    @route('ryu_ia', '/ryu/hosts/{ip}/cuarentena_vlan', methods=['POST'])
    def cuarentena_vlan(self, req, ip, **kwargs):
        if HONEYPOT is None:   # sin las variables HONEYPOT_* no hay A8
            if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
            return _json({'error': 'cuarentena_vlan no disponible (sin honeypot)'}, 404)
        return self._cambiar_modo(req, ip, 'vlan_cuarentena')

    def _cambiar_modo(self, req, ip, modo):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return _json({'error': 'ip inválida'}, 422)
        kbps = None
        if modo == 'limitado':
            try:
                cuerpo = json.loads(req.body or b'{}')
            except ValueError:
                return _json({'error': 'json inválido'}, 422)
            if not isinstance(cuerpo, dict):
                return _json({'error': 'el cuerpo debe ser un objeto JSON'}, 422)
            kbps = cuerpo.get('kbps', LIMIT_DEFAULT_KBPS)
            # bool es subclase de int en Python: se rechaza aparte
            if (isinstance(kbps, bool) or not isinstance(kbps, int)
                    or not 0 < kbps <= LIMIT_MAX_KBPS):
                return _json({'error': 'kbps inválido'}, 422)
        info = self.app.blocked_hosts.get(ip)
        if info is None:
            return _json({'error': 'host no bloqueado'}, 404)
        # Nota C2 (origen): solo desde DROP total (o repitiendo el mismo modo)
        actual = info.get('modo', 'drop_total')
        if modo != 'drop_total' and actual not in ('drop_total', modo):
            return _json({'ok': False, 'modo': actual}, 409)
        ok = self.app.cambiar_modo(ip, modo, kbps=kbps)
        if not ok:
            return _json({'ok': False, 'modo': 'drop_total'}, 500)
        if modo == 'limitado':
            return _json({'ok': True, 'ip': ip, 'modo': modo, 'kbps': kbps})
        if modo == 'vlan_cuarentena':
            return _json({'ok': True, 'ip': ip, 'modo': modo, 'vlan': VLAN_CUARENTENA})
        return _json({'ok': True, 'ip': ip, 'modo': modo})

    @route('ryu_ia', '/ryu/umbrales', methods=['GET'])
    def leer_umbrales(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        return _json(self.app.umbrales)

    @route('ryu_ia', '/ryu/umbrales', methods=['PUT'])
    def cambiar_umbrales(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        try:
            cambios = json.loads(req.body or b'{}')
        except ValueError:
            return _json({'error': 'json inválido'}, 422)
        if not isinstance(cambios, dict):
            return _json({'error': 'el cuerpo debe ser un objeto JSON'}, 422)
        for k, v in cambios.items():
            # bool es subclase de int en Python: se rechaza aparte
            if (k not in self.app.umbrales or isinstance(v, bool)
                    or not isinstance(v, int) or v <= 0):
                return _json({'error': f'valor inválido para {k}'}, 422)
        self.app.umbrales.update(cambios)
        logger.warning(f'[API] Umbrales actualizados: {cambios}')
        return _json(self.app.umbrales)
