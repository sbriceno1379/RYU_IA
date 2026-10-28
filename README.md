# RYU_IA

Controlador SDN que detecta y contiene el movimiento lateral de ransomware en una red de PyME simulada en Mininet. Es la mitad de red de la tesis de grado de Alejandro Salas Jurado y Sebastián Briceño Restrepo (Universidad Católica de Colombia, 2026). La otra mitad es el agente [sdn-agent-v2](https://github.com/alejandrosj9/sdn-agent-v2), que explica cada incidente, lo notifica y deja que un operador humano decida.

```
Ryu detecta y BLOQUEA (DROP en s1, s2 y s3)
   →  POST de la alerta al agente (:8081/api/alertas, X-Agent-Token)
   →  el agente responde 202 {"acciones_ryu":["mantener_bloqueo"]}, explica y notifica
   →  solo si el operador aprueba en el panel, el agente llama a la API REST de Ryu (:8080)
```

Ryu nunca espera al agente para bloquear y nunca desbloquea por su cuenta.

## Contenido

| Archivo | Qué es |
|---|---|
| `ryu_controller.py` | La aplicación Ryu (OpenFlow 1.3): aprendizaje MAC con VLAN, las 5 métricas, el puntaje, el bloqueo, el envío de la alerta y la API REST |
| `topology_project.py` | La topología de Mininet: 20 hosts en 2 VLAN, 3 switches y el honeypot |
| `run_mininet.py` | Verifica el entorno (Ryu escuchando, OVS) y levanta la topología |
| `arranque_ryu.py` | Verifica `ryu-manager` y lo arranca en el puerto 6633 |
| `ataque_completo.py` | Simulación de ataque: h1 barre y abre conexiones en puertos críticos; h2 a h10 hacen de víctimas |
| `iniciar_victimas.py` | Genera los comandos para levantar servidores TCP en h2 a h10 |
| `honeypot.py` | Honeypot de la VLAN 999: acepta y registra cada conexión en JSON |
| `servidor_json.py` | Receptor de prueba en :8081 que imprime la alerta (sustituto del agente) |
| `evaluacion/` | Evaluación del objetivo 3: escenarios, orquestador y resumen estadístico ([evaluacion/README.md](evaluacion/README.md)) |
| `docs/` | `PLAN.md` (fases y pruebas de aceptación), `ajustes.md` (cambios A0 a A8), `contratos.md` (C1 alerta y C2 API), `ideas.md` |
| `requirements-ryu.txt` | Versiones exactas del entorno de Ryu |

## Topología

```
   [OPS h1-h10]  ──s1──┐
                       s3 ──── Ryu (127.0.0.1:6633)
   [ADM h11-h20] ──s2──┘
                       └── honeypot (VLAN 999)
```

| Segmento | Hosts | Direcciones | Switch |
|---|---|---|---|
| OPS, VLAN 10 | h1 a h10 | 10.0.10.1 a 10.0.10.10 | s1 |
| ADM, VLAN 20 | h11 a h20 | 10.0.20.1 a 10.0.20.10 | s2 |
| Cuarentena, VLAN 999 | honeypot | 10.0.99.1 (MAC 00:00:00:00:09:99) | s3, puerto 3 |

El tamaño representa un piso de una mediana empresa colombiana (Ley 905 de 2004).

## Detección

Puertos críticos vigilados: 135, 139, 445, 3389 y 5985. Las métricas se observan por Packet-In y por estadísticas de flujo:

| Métrica | Qué mide | Disparo | Peso |
|---|---|---|---|
| M5 | Flujos este-oeste distintos en puertos críticos | ≥ 5 pares | 40 |
| M3 | Flujo SMB corto y voluminoso | > 512 000 B en < 5 s | 35 |
| M1 | Nuevos flujos hacia puertos críticos | > 20 en 30 s | 25 |
| M2 | Destinos únicos (fan-out) | > 8 en 30 s | 20 |
| M4 | Packet-In por host | > 200 por minuto | 15 |

El puntaje de un host es la suma de los pesos de las métricas disparadas (máximo 135) y se reinicia tras 5 minutos sin métricas nuevas:

- 0 a 29, **normal**.
- 30 a 59, **sospechoso**: límite de tasa en los puertos críticos del host, sin cortar el tráfico.
- 60 o más, **crítico**: DROP de prioridad 100 en todos los switches y alerta al agente.

Los primeros 30 s tras arrancar Ryu son período de gracia (no se evalúa). Los umbrales de las métricas y los cortes de puntaje (`SCORE_SOSPECHOSO`, `SCORE_CRITICO`) se pueden leer y cambiar en caliente por la API (`/ryu/umbrales`); los pesos son fijos. Los valores de la tabla son los de la tesis.

## Alerta al agente

Cuando un host pasa a crítico, Ryu bloquea y luego envía un `POST` a `http://localhost:8081/api/alertas` con el encabezado `X-Agent-Token`. El cuerpo sigue el contrato C1 de [docs/contratos.md](docs/contratos.md): host, puntaje, métricas disparadas con sus valores, umbrales, indicadores de compromiso, contexto de topología y marca de tiempo. Hay un ejemplo real en [docs/alerta_real_r1b.json](docs/alerta_real_r1b.json). Si el agente no responde, el bloqueo se mantiene igual.

## API REST (puerto 8080)

Todas las rutas exigen `X-Agent-Token` con el valor de la variable de entorno `AGENT_TOKEN` (401 si falta o no coincide). Contrato completo en C2 de [docs/contratos.md](docs/contratos.md).

| Método y ruta | Qué hace |
|---|---|
| `GET /ryu/estado` | Switches conectados, número de bloqueados, umbrales, pesos y capacidades |
| `GET /ryu/hosts/bloqueados` | Hosts aislados con su modo (`drop_total`, `cuarentena`, `limitado`, `vlan_cuarentena`) y desde cuándo |
| `POST /ryu/hosts/{ip}/desbloquear` | Quita el aislamiento (solo cuando el operador lo aprueba en el panel del agente) |
| `POST /ryu/hosts/{ip}/bloqueo_total` | Vuelve a DROP total |
| `POST /ryu/hosts/{ip}/cuarentena` | A6: deja pasar DNS y DHCP y corta los puertos críticos y SSH |
| `POST /ryu/hosts/{ip}/limitar_tasa` | A7: límite con meter de OpenFlow, cuerpo opcional `{"kbps": 1000}` |
| `POST /ryu/hosts/{ip}/cuarentena_vlan` | A8: desvía las conexiones del host al honeypot de la VLAN 999 |
| `GET` / `PUT /ryu/umbrales` | Lee o cambia los umbrales de las métricas (enteros positivos) |

Las acciones de la escalera solo se aplican a un host que está en DROP total (409 si está en otro modo) y, si fallan, el host queda en DROP total.

Ejemplo:

```
curl -s -H "X-Agent-Token: $AGENT_TOKEN" http://localhost:8080/ryu/hosts/bloqueados
```

## Instalación

Probado en Debian/Ubuntu con Python 3.9 para Ryu (ryu 4.34 no instala con versiones recientes de setuptools):

```
sudo apt install mininet openvswitch-switch
cd ~/Desktop/RYU_IA
uv python install 3.9 && uv venv -p 3.9 --seed .venv
.venv/bin/pip install setuptools==57.5.0 wheel pbr
PBR_VERSION=4.34 .venv/bin/pip install --no-build-isolation -r requirements-ryu.txt
```

Los scripts de Mininet y de evaluación corren con el Python del sistema (`/usr/bin/python3`) y solo usan la librería estándar.

## Uso manual

Terminal 1, Ryu (sin sudo). `AGENT_TOKEN` debe ser el mismo que tiene el agente en su `.env`. Las variables `HONEYPOT_*` habilitan la cuarentena VLAN (A8); sin ellas Ryu funciona igual pero no ofrece `cuarentena_vlan`.

```
cd ~/Desktop/RYU_IA
export AGENT_TOKEN=<token del agente>
export HONEYPOT_DPID=3 HONEYPOT_PUERTO=3 HONEYPOT_MAC=00:00:00:00:09:99
.venv/bin/ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633 --wsapi-port 8080
```

Terminal 2, Mininet:

```
sudo mn -c
cd ~/Desktop/RYU_IA && sudo /usr/bin/python3 topology_project.py
```

`sudo mn -c` también mata `ryu-manager`: córrelo antes de arrancar Ryu o vuelve a arrancar Ryu después.

Espera los 30 s de gracia y lanza el ataque desde la CLI de Mininet: primero las víctimas (`h2 python3 ataque_completo.py &` y así hasta h10) y luego `h1 python3 ataque_completo.py`. Ryu debería registrar M1, M2 y M5, bloquear 10.0.10.1 en los tres switches y enviar la alerta. Para ver la alerta sin el agente, corre `python3 servidor_json.py` en otra terminal.

## Evaluación (objetivo 3)

`evaluacion/` prueba el controlador y el agente a la vez con tráfico y ataques reales en Mininet: 10 escenarios (6 de ataque basados en MITRE ATT&CK y 4 benignos, dos de ellos casos difíciles por diseño), 10 repeticiones en orden aleatorio, con el LLM activo y con el respaldo por reglas. Arranca su propio Ryu en cada corrida y lo reinicia si se cae al levantar la topología.

```
python3 evaluacion/correr_evaluacion.py --dry-run                                     # verificaciones, sin sudo
sudo /usr/bin/python3 evaluacion/correr_evaluacion.py --solo A6,B1 --repeticiones 1   # prueba de humo
sudo /usr/bin/python3 evaluacion/correr_evaluacion.py                                 # evaluación completa
```

El resultado queda en `evaluacion/resultados/<fecha>_objetivo3/`: plan de acción, resumen estadístico (precisión, exhaustividad, F1 y MCC con intervalos de Wilson, tiempos por etapa, contención, calidad de la explicación y de la recomendación, LLM frente a reglas) y la planilla para la calificación humana a ciegas. Detalles en [evaluacion/README.md](evaluacion/README.md).

Pruebas sin Mininet: `python3 -m unittest evaluacion/test_evaluacion.py`.

## Limitaciones conocidas

- M3 en la práctica no se dispara: solo se evalúa sobre las reglas de monitoreo de M5, que son permanentes y superan los 5 s de duración. La evaluación lo mide.
- M5 cuenta pares sin ventana de tiempo, así que un ataque muy lento también la acumula.
- M1 y M4 cuentan Packet-In, no conexiones.

Están anotadas en [docs/ideas.md](docs/ideas.md); la lógica de detección no se cambia en esta tesis.

## Seguridad

- El token se lee de `AGENT_TOKEN`; ningún secreto va en el código.
- Toda la API exige el token.
- El desbloqueo y la escalera de acciones solo ocurren por la API, cuando el operador lo aprueba en el agente.
