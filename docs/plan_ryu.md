# PLAN.md - Controlador RYU_IA

Regla de oro: una fase = una sesión de Claude Code = un commit que apruebo yo. No se empieza la siguiente fase si la prueba de aceptación no pasó a mano.

## Estado

| Fase | Entrega | Necesita sudo | Estado |
|---|---|---|---|
| R0 | Entorno: Python 3.9 con uv, ryu 4.34, eventlet 0.30.2, Mininet y OVS; prueba de humo | Sí (apt, mn) | ✅ e41e819 |
| R1a | A0 a A4 en ryu_controller.py | Sí (prueba en Mininet) | en curso |
| R1b | A5: API REST en el puerto 8080 según C2 | Sí (parte 2 de la prueba) | pendiente |
| R2 | Integración real: Ryu, Mininet y el agente (202, panel, correo, desbloqueo desde el panel) | Sí | pendiente |
| R3a | A6: cuarentena por puertos y bloqueo_total, con el campo modo | Sí | pendiente |
| R3b | A7: limitar_tasa | Sí | pendiente |
| R3c | A8: cuarentena_vlan (VLAN 999) con host honeypot | Sí | pendiente |
| R4 | Evaluación final con tráfico real | Sí | pendiente |

## Cómo se trabaja cada fase (igual que en el agente)

1. Pego el prompt de la fase. Claude Code solo lee y valida, y propone en máximo 5 líneas qué archivos toca y cuáles no. Espera.
2. Yo apruebo o corrijo.
3. Claude Code implementa y corre solo las pruebas que no necesitan sudo.
4. Claude Code responde con el formato de entrega de abajo. Nada más.
5. Yo corro la prueba de aceptación de este archivo, un comando a la vez.
6. Si pasa, apruebo el commit.

Formato de entrega (obligatorio, máximo 15 líneas sin contar el diff):

```
CAMBIOS: máximo 5 líneas.
PRUEBAS SIN SUDO: qué se corrió y resultado.
DIFERENCIAS CON LOS DOCUMENTOS: máximo 3 líneas, o "ninguna".
COMMIT PROPUESTO: una línea de título y los archivos.
```

Los comandos de aceptación ya están en este archivo: Claude Code no los vuelve a escribir.

## Preparación común para las pruebas

Terminal 1 (Ryu, sin sudo):
```
cd ~/Desktop/RYU_IA
export AGENT_TOKEN=prueba-local
.venv/bin/ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633 --wsapi-port 8080
```
En R2 el valor de AGENT_TOKEN debe ser el mismo que usa el agente en su .env para X-Agent-Token.

Terminal 2 (Mininet, con sudo):
```
sudo mn -c
cd ~/Desktop/RYU_IA && sudo /usr/bin/python3 topology_project.py
```
Esperar 30 s desde que arrancó Ryu (período de gracia). Luego, en mininet>, una línea por host, de h2 a h10:
```
h2 python3 /home/alejandro/Desktop/RYU_IA/ataque_completo.py > /dev/null 2>&1 &
```
Y el ataque:
```
h1 python3 /home/alejandro/Desktop/RYU_IA/ataque_completo.py
```
Cortar con Ctrl+C cuando la terminal 1 muestre "DROP en 3 switch(es)".

Terminal 3 (curls): `export AGENT_TOKEN=prueba-local`

Antes de R1b y R2: el mock de Ryu del agente (tests/mock_ryu.py) no puede estar corriendo, porque también usa el puerto 8080.

---

## R1a - A0 a A4

Prompt: ya se ejecutó.

Prueba de aceptación:
1. Con la preparación común, en la terminal 1: el bloque "[CAPA 3] Payload JSON" muestra M1_nuevos_flujos_por_30s mayor que 20 y M2_destinos_unicos_por_30s mayor que 8. ✅ (21.0 y 9.0)
2. En mininet>:
```
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=100
sh ovs-ofctl -O OpenFlow13 dump-flows s3 | grep priority=100
```
Esperado: en los tres, una regla priority=100,ip,nw_src=10.0.10.1 con actions=clear_actions (es el DROP en OpenFlow 1.3). En s1 n_packets sube; en s2 y s3 puede quedar en 0.

Hallazgo para la tesis (no se corrige aquí): el anexo de ajustes.md dice que ataque_completo.py termina en M1+M2+M4 = 60. En la corrida real se dispararon M1, M2 y M5, con 85 puntos (M4 midió 120 y el umbral es 200). Se decide en R4.

---

## R1b - A5: API REST

Prompt:

```
Fase R1b - A5 (API REST). Lee CLAUDE.md, docs/PLAN.md (sección R1b), docs/ajustes.md (A5) y docs/contratos.md (C2).

Alcance: solo A5 en ryu_controller.py, con el esqueleto de ajustes.md y estos puntos de C2:
- 422 si la ip no es una IPv4 válida.
- GET /ryu/estado incluye "capacidades": [] (lista vacía; A6, A7 y A8 aún no existen).
- PUT /ryu/umbrales: 422 si el cuerpo no es un objeto JSON, si una clave no existe o si un valor no es entero mayor que 0 (los bool no cuentan como entero).
- Todas las rutas exigen X-Agent-Token; 401 si falta o no coincide.
Si ajustes.md y contratos.md no coinciden, gana contratos.md.

No toques la detección, los pesos, los cortes 30/60 ni los campos de la alerta.

Paso 1: valida y propón en máximo 5 líneas qué cambias. Espera mi aprobación.
Paso 2: implementa. Arranca .venv/bin/ryu-manager con AGENT_TOKEN=prueba-local y --wsapi-port 8080, sin Mininet, y corre la parte 1 de la prueba de aceptación de PLAN.md.
Paso 3: responde con el formato de entrega de PLAN.md. No hagas git add ni commit.
```

Prueba de aceptación, parte 1 (sin Mininet, solo Ryu corriendo):
```
curl -s localhost:8080/ryu/estado -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: 200, "switches": [], "capacidades": [], version "2.0", umbrales y pesos.
```
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/ryu/estado
```
Esperado: 401.
```
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/ryu/estado -H "X-Agent-Token: otro"
```
Esperado: 401.
```
curl -s localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: M1 20, M2 8, M3_DURACION_S 5, M3_BYTES 512000, M4 200, M5 5, SCORE_SOSPECHOSO 30, SCORE_CRITICO 60.
```
curl -s -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": 10}'
```
Esperado: 200 con M2 10.
```
curl -s -o /dev/null -w "%{http_code}\n" -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M9": 1}'
curl -s -o /dev/null -w "%{http_code}\n" -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '[1]'
curl -s -o /dev/null -w "%{http_code}\n" -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": true}'
curl -s -o /dev/null -w "%{http_code}\n" -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": 0}'
```
Esperado: 422 en los cuatro.
```
curl -s -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": 8}'
```
Esperado: M2 vuelve a 8.
```
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/abc/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.99/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: 422 y 404.

Prueba de aceptación, parte 2 (con la preparación común: Mininet y ataque):
```
curl -s localhost:8080/ryu/estado -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: tres switches.
```
curl -s localhost:8080/ryu/hosts/bloqueados -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: [{"ip": "10.0.10.1", "dpid": "0x...", "desde": "..."}].
```
curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: {"ok": true, "ip": "10.0.10.1", "reglas_borradas": 3}.

En mininet>: los tres dump-flows de R1a ya no muestran la regla de 10.0.10.1, y `h1 ping -c 2 h2` responde.
```
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.1/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
```
Esperado: 404.

Al cerrar: copiar el JSON real de "[CAPA 3] Payload JSON" a un archivo, para usarlo en el agente como prueba fija de compatibilidad.

---

## R2 - Integración real con el agente

Sin cambios de código previstos en este repo. Si algo falla, Claude Code solo diagnostica y propone.

Prueba de aceptación:
1. El agente arrancado como siempre (puerto 8081), con el mock de Ryu apagado.
2. Ryu con el mismo AGENT_TOKEN del agente.
3. Ataque. En la terminal de Ryu: "[AGENTE] HTTP 202" y mantener_bloqueo.
4. En el panel: el incidente, la explicación y la recomendación. Llega el correo.
5. En el panel, GET /api/ryu/estado muestra Ryu conectado y sin capacidades.
6. Desbloqueo desde el panel: la regla desaparece de s1, s2 y s3 y el ping vuelve.

Prompt: se escribe al llegar.

---

## R3a, R3b, R3c y R4

Prompts: se escriben al llegar. Cada uno empieza con una fase de validación sin cambios (por ejemplo, en R3b confirmar si el OVS instalado soporta meters de OpenFlow 1.3 antes de proponer cómo limitar la tasa).