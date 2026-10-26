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
| R3b | A7: limitar_tasa | Sí | pendiente | ✅
| R3c | A8: cuarentena_vlan (VLAN 999) con host honeypot | Sí | pendiente |
| R3c1 | Honeypot: host nuevo en la topologia y script que acepta y registra conexiones | Sí | pendiente |
| R3c2 | A8: cuarentena_vlan (VLAN 999) que desvia al host hacia el honeypot | Sí | pendiente |
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


## R3a - A6: cuarentena por puertos y bloqueo_total

Prompt:

    Fase R3a - A6. Lee CLAUDE.md, docs/PLAN.md (seccion R3a), docs/ajustes.md (A6) y docs/contratos.md (C2, incluidas las dos notas).

    Alcance, solo en ryu_controller.py:
    - POST /ryu/hosts/{ip}/cuarentena: reemplaza el DROP total por DROP de prioridad 110 en TCP 22, 135, 139, 445, 3389 y 5985 desde esa ip, mas DROP de prioridad 100 de todo lo demas, excepto ARP, DNS (UDP y TCP 53) y DHCP.
    - POST /ryu/hosts/{ip}/bloqueo_total: vuelve al DROP total desde cualquier modo.
    - Las dos son idempotentes (repetirlas no duplica reglas), 404 si el host no esta bloqueado, 422 si la ip es invalida, y quedan en el log.
    - Transaccionales segun la nota de C2: se instalan las reglas del modo nuevo ANTES de quitar el DROP total, en todos los switches del host. Si falla en alguno, se borra lo instalado, queda el DROP total y se responde 500 con {"ok": false, "modo": "drop_total"}.
    - blocked_hosts guarda el modo; GET /ryu/hosts/bloqueados agrega "modo": "drop_total" o "cuarentena".
    - GET /ryu/estado: "capacidades": ["cuarentena"].
    - desbloquear funciona desde cualquier modo y borra TODAS las reglas del host (las de 100 y las de 110).
    - El host sigue en blocked_hosts mientras este en cuarentena (no se vuelve a evaluar).

    No toques la deteccion, los pesos, los cortes 30/60, la alerta ni las rutas de A5.

    Paso 1: valida y propone en maximo 5 lineas, incluido como haras las excepciones de ARP, DNS y DHCP y como pruebas la reversion transaccional sin sudo. Espera mi aprobacion.
    Paso 2: implementa y corre la parte 1 de la prueba de aceptacion. No hagas git add ni commit.
    Paso 3: responde con el formato de entrega.

Prueba de aceptacion, parte 1 (solo Ryu, sin Mininet):

    curl -s localhost:8080/ryu/estado -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: "capacidades": ["cuarentena"].

    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.99/cuarentena -H "X-Agent-Token: $AGENT_TOKEN"
    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/abc/cuarentena -H "X-Agent-Token: $AGENT_TOKEN"
    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.99/bloqueo_total -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: 404, 422 y 404.

Prueba de aceptacion, parte 2 (preparacion comun, con h1 bloqueado):

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/cuarentena -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: {"ok": true, "ip": "10.0.10.1", "modo": "cuarentena"}.

    curl -s localhost:8080/ryu/hosts/bloqueados -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: 10.0.10.1 con "modo": "cuarentena".

En mininet>:
    sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E "priority=(100|110)"
Esperado: reglas de 110 para los 6 puertos TCP y las reglas de 100 con sus excepciones. Repetir en s2 y s3.
    h1 ping -c 2 h2
Esperado: 100% de perdida.

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/cuarentena -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: ok de nuevo, y el dump-flows de s1 muestra la misma cantidad de reglas (sin duplicados).

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/bloqueo_total -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: "modo": "drop_total"; en s1 ya no hay reglas de 110, solo el DROP de 100.

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/cuarentena -H "X-Agent-Token: $AGENT_TOKEN"
    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: desbloqueado desde cuarentena; ni reglas de 100 ni de 110 para 10.0.10.1 en s1, s2 y s3, y h1 ping -c 2 h2 responde.

Parte 3 (con el agente, como en R2): el panel ofrece la cuarentena solo cuando la recomienda; al aprobarla, Ryu queda en "modo": "cuarentena" y el agente lo verifica.

Hallazgo R3a: con ataque_completo.py el LLM da "indeterminado" (0.45) porque M1, M2 y M5 apenas superan el umbral y no hay M3. La escalera queda en mantener_drop. Para evaluar la escalera completa con trafico real hace falta un escenario fuerte (con transferencia SMB para M3) y uno benigno.

## R3b - A7: limitar tasa

Prompt:

    Fase R3b - A7. Lee CLAUDE.md, docs/PLAN.md (seccion R3b) y docs/contratos.md (C2 y sus dos notas).

    Que significa "limitado" (contrato C7): el host recupera la red completa, sin DROP de puertos, pero a maximo kbps. Se usa cuando el agente cree que fue falsa alarma.

    Alcance, solo en ryu_controller.py:
    - POST /ryu/hosts/{ip}/limitar_tasa con cuerpo opcional {"kbps": entero > 0}; por defecto 1000. Respuesta {"ok": true, "ip", "modo": "limitado", "kbps"}.
    - 404 si el host no esta bloqueado, 422 si la ip o kbps son invalidos (los bool no cuentan como entero, y tampoco un cuerpo que no es objeto).
    - Solo desde DROP total, igual que la cuarentena. Idempotente y transaccional segun la nota de C2: si falla en algun switch, se borra lo instalado, queda el DROP total y se responde 500 con {"ok": false, "modo": "drop_total"}.
    - GET /ryu/hosts/bloqueados agrega "kbps" cuando el modo es limitado.
    - bloqueo_total vuelve a DROP total desde limitado; desbloquear funciona desde limitado y borra todo lo del host (reglas y meter).
    - GET /ryu/estado: "capacidades": ["cuarentena", "limitar_tasa"].
    - El host sigue en blocked_hosts mientras este limitado (no se vuelve a evaluar).

    No toques la deteccion, los pesos, los cortes 30/60, la alerta, A5 ni A6.

    Paso 1: valida y propone en maximo 5 lineas: como limitaras la tasa (meter de OpenFlow 1.3 u otra forma, y por que), como se reenvia el trafico del host limitado y como pruebas la reversion sin sudo. Si necesitas saber si el OVS soporta meters, dame el comando exacto con sudo y espera mi resultado. Espera mi aprobacion.
    Paso 2: implementa y corre la parte 1 de la prueba de aceptacion mas tu prueba de reversion en el scratchpad. No hagas git add ni commit.
    Paso 3: responde con el formato de entrega.

Prueba de aceptacion, parte 1 (solo Ryu):

    curl -s localhost:8080/ryu/estado -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: "capacidades": ["cuarentena", "limitar_tasa"].

    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.99/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN"
    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/abc/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: 404 y 422.

Prueba de aceptacion, parte 2 (preparacion comun, con h1 bloqueado):

    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.1/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN" -d '{"kbps": 0}'
    curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/ryu/hosts/10.0.10.1/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN" -d '{"kbps": true}'
Esperado: 422 y 422.

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN" -d '{"kbps": 1000}'
Esperado: {"ok": true, "ip": "10.0.10.1", "modo": "limitado", "kbps": 1000}.

    curl -s localhost:8080/ryu/hosts/bloqueados -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: 10.0.10.1 con "modo": "limitado" y "kbps": 1000.

En mininet>:
    h1 ping -c 2 h2
Esperado: responde (ya no hay DROP).
    iperf h1 h2
Esperado: alrededor de 1 Mbits/sec o menos.
    iperf h3 h2
Esperado: mucho mas alto (h3 no esta limitado).

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN" -d '{"kbps": 1000}'
Esperado: ok otra vez, sin reglas ni meters duplicados.

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/bloqueo_total -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: "modo": "drop_total"; h1 ping -c 2 h2 vuelve a dar 100% de perdida.

    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/limitar_tasa -H "X-Agent-Token: $AGENT_TOKEN"
    curl -s -X POST localhost:8080/ryu/hosts/10.0.10.1/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
Esperado: desbloqueado desde limitado; iperf h1 h2 vuelve a la velocidad normal y no queda nada de 10.0.10.1 en s1, s2 y s3.

Parte 3 (con el agente): en el panel, "Acciones" de 10.0.10.1 ofrece "Limitar tasa"; al aplicarla, la fila muestra "Tasa limitada (1000 kbps)".

## R3c - A8: cuarentena en VLAN 999 con honeypot

Decisiones (25-oct-2026): el host en cuarentena VLAN queda en una red donde solo existe un honeypot. El honeypot solo acepta conexiones en los puertos criticos y registra cada intento (hora, ip de origen, ip y puerto que el atacante intento alcanzar). La evidencia queda en un log; no se envia al agente (trabajo futuro). No cambia C1.

Objetivo que se debe poder demostrar: con h1 en vlan_cuarentena, cuando h1 intenta conectarse a un puerto critico de cualquier victima, la conexion la completa el honeypot (no la victima real), queda registrada con el destino que h1 intento, y ninguna victima real recibe nada de h1.

## R3c1 - Honeypot (sin tocar ryu_controller.py)

Prompt:

    Fase R3c1. Lee CLAUDE.md, docs/PLAN.md (secciones R3c y R3c1) y topology_project.py.

    Alcance:
    1. honeypot.py nuevo, solo libreria estandar: escucha TCP en 22, 135, 139, 445, 3389 y 5985, acepta cada conexion, la cierra y escribe una linea JSON por intento en un log (ts en UTC ISO-8601, ip_origen, puerto_origen, ip_destino, puerto_destino). Termina limpio con Ctrl+C.
    2. topology_project.py: un host honeypot nuevo, en la VLAN 999, conectado donde sea mas simple de alcanzar desde los hosts de OPS y de ADM. No cambies nada de los hosts, las VLAN 10 y 20 ni los switches existentes.
    3. El honeypot debe poder recibir conexiones dirigidas a las ip de las victimas (para que la del atacante se complete). Propon como (por ejemplo, alias de ip en el honeypot) y por que no choca con las victimas reales (la VLAN 999 no comparte ARP con la 10 ni la 20).

    No toques ryu_controller.py, los pesos, la deteccion ni la alerta.

    Paso 1: valida y propone en maximo 5 lineas: donde conectas el honeypot (switch y puerto), como recibe las ip de las victimas y que datos de ubicacion necesitara Ryu en R3c2 (por ejemplo HONEYPOT_DPID y HONEYPOT_PUERTO). Espera mi aprobacion.
    Paso 2: implementa. Prueba sin sudo: honeypot.py en localhost con puertos altos de prueba y un cliente que se conecte; muestra las lineas del log. No hagas git add ni commit.
    Paso 3: responde con el formato de entrega.

Prueba de aceptacion (con sudo, Ryu como siempre):
1. La topologia arranca sin errores y muestra el honeypot en la VLAN 999.
2. En mininet>, h1 ping -c 2 h2 sigue respondiendo (la topologia de siempre no cambio).
3. En mininet>, el honeypot no alcanza a h2 ni h2 al honeypot (estan en VLAN distintas).
4. Con honeypot.py corriendo en el honeypot, desde el mismo honeypot una conexion a su propia ip en el puerto 445 queda registrada en el log.

## R3c2 - A8 en Ryu: cuarentena_vlan

Prompt:

    Fase R3c2 - A8. Lee CLAUDE.md, docs/PLAN.md (secciones R3c y R3c2), docs/contratos.md (C2 y sus tres notas) y lo que quedo de R3c1 (honeypot y su ubicacion).

    Alcance, solo en ryu_controller.py:
    - POST /ryu/hosts/{ip}/cuarentena_vlan: {"ok": true, "ip", "modo": "vlan_cuarentena", "vlan": 999}. 404 si el host no esta bloqueado, 422 ip invalida, 409 si no esta en DROP total (nota de origen).
    - Efecto: el trafico TCP de ese host hacia los puertos criticos de cualquier destino se entrega al honeypot (y la respuesta del honeypot vuelve al host); todo lo demas del host sigue en DROP. Ninguna victima real recibe nada del host.
    - Ryu impide que el honeypot alcance a cualquier host que no este en vlan_cuarentena (solo vuelven al host en cuarentena las respuestas del honeypot).
    - Transaccional segun la nota de C2: las reglas nuevas se instalan antes de quitar nada; si falla en algun switch, se borra lo instalado, queda el DROP total y se responde 500.
    - La ubicacion del honeypot se lee de variables de entorno (las que acordamos en R3c1). Si no estan definidas, no hay A8: la ruta responde 404 y "cuarentena_vlan" no aparece en capacidades.
    - GET /ryu/hosts/bloqueados agrega "vlan": 999 en ese modo; capacidades ["cuarentena", "limitar_tasa", "cuarentena_vlan"] cuando hay honeypot.
    - bloqueo_total vuelve a DROP total desde este modo; desbloquear borra siempre todo lo del host, incluidas las reglas de este modo.

    No toques la deteccion, los pesos, los cortes 30/60, la alerta, A5, A6 ni A7.

    Paso 1: valida y propone en maximo 5 lineas: que reglas instalas en que switches (ida y vuelta), como lo pruebas sin sudo y como queda la reversion. Espera mi aprobacion.
    Paso 2: implementa y corre la parte 1 de la prueba de aceptacion mas tu prueba de reversion, y la regresion de R3a y R3b. No hagas git add ni commit.
    Paso 3: responde con el formato de entrega.

Prueba de aceptacion, parte 1 (solo Ryu):
- Sin las variables del honeypot: "cuarentena_vlan" no esta en capacidades y la ruta da 404.
- Con las variables: esta en capacidades; 10.0.10.99 da 404 y abc da 422.

Prueba de aceptacion, parte 2 (preparacion comun, honeypot.py corriendo en el honeypot, h1 bloqueado):
1. POST cuarentena_vlan de 10.0.10.1: "modo": "vlan_cuarentena", "vlan": 999.
2. En una victima, por ejemplo h2, dejar un servidor de prueba en 445 que anote lo que recibe.
3. En mininet>: h1 timeout 5 bash -c "echo > /dev/tcp/10.0.10.2/445" && echo conectado
   Esperado: "conectado"; el log del honeypot tiene una linea con ip_origen 10.0.10.1 e ip_destino 10.0.10.2, puerto 445; el servidor de h2 no recibio nada.
4. En mininet>: h1 ping -c 2 h2. Esperado: 100% de perdida (lo que no es puerto critico sigue en DROP).
5. POST cuarentena_vlan otra vez: ok, sin reglas duplicadas.
6. POST cuarentena de 10.0.10.1: 409 con "modo": "vlan_cuarentena".
7. POST bloqueo_total: "modo": "drop_total", y la conexion del paso 3 ya no se completa.
8. POST cuarentena_vlan y luego desbloquear: no queda nada de 10.0.10.1 en s1, s2 y s3, y h1 ping -c 2 h2 responde.

Parte 3 (con el agente): en "Acciones" de 10.0.10.1 aparece "Cuarentena en VLAN"; al aplicarla, la fila muestra "VLAN de cuarentena (VLAN 999)".