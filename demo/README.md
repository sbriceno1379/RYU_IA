# Demo corta para el video

`demo_video.py` muestra el sistema completo en unos 2 o 3 minutos, con salidas claras en pantalla. No reemplaza la evaluación del objetivo 3: es un solo intento por incidente, sin repeticiones ni estadísticas.

Qué se ve, en orden:

1. Arranque de Ryu (OpenFlow 1.3, puerto 6633, API en 8080) y de la topología (s1 OPS, s2 ADM, s3 core y honeypot VLAN 999).
2. Tráfico normal: `h1 → h2` y `h11 → h12` responden al ping. Cuenta atrás del período de gracia de 30 s.
3. **Incidente 1**: h1 (10.0.10.1) propaga por SMB (445) con carga a h2 a h10, al estilo WannaCry/PsExec.
4. **Incidente 2**: h11 (10.0.20.1) se mueve por RDP y WinRM (3389, 5985) en la VLAN ADM.
5. En cada incidente: Ryu bloquea (regla DROP prioridad 100 en s1, s2 y s3, y el ping falla), se imprime la alerta JSON que Ryu envía al agente, el agente responde 202 `mantener_bloqueo`, explica (LLM o reglas de respaldo) y deja una recomendación.
6. El operador decide. Solo si aprueba, el agente llama a la API de Ryu y el host cambia de modo (por ejemplo de `drop_total` a `cuarentena`).

## Antes de grabar

Terminal 1, el agente con su `.env` (el mismo `AGENT_TOKEN` que usará Ryu):

```
cd ~/Desktop/sdn-agent-v2 && .venv/bin/uvicorn app.main:app --port 8081
```

Cierra cualquier Ryu o el mock de Ryu del agente: la demo arranca su propio Ryu y necesita los puertos 6633 y 8080 libres.

Terminal 2, verificación sin sudo:

```
cd ~/Desktop/RYU_IA
python3 demo/demo_video.py --dry-run
```

Los tokens se leen de `AGENT_TOKEN` y `OPERADOR_TOKEN` si están exportados; si no, del `.env` del agente (`~/Desktop/sdn-agent-v2/.env`, se cambia con `--env-agente`).

## Grabar

```
sudo -E /usr/bin/python3 demo/demo_video.py
```

Opciones útiles:

| Opción | Para qué |
|---|---|
| `--pausas` | Espera Enter entre pasos, para narrar con calma |
| `--incidentes 1` | Solo el incidente SMB (más corto) |
| `--aprobar preguntar` | Por defecto: pregunta en pantalla `s` (aprobar aquí), `p` (lo apruebo en el panel) o `n` (no aprobar) |
| `--aprobar panel` | Espera a que apruebes en el panel `http://localhost:8081` y muestra el cambio en Ryu |
| `--aprobar auto` | Aprueba solo, para ensayar sin intervenir |
| `--sin-agente` | Solo Ryu: detección, bloqueo y alerta JSON |

Al final la demo queda esperando un Enter, así puedes mostrar el panel del agente antes de apagar todo. Los logs (incluido `ryu.log`) quedan en `logs/demo_<fecha>/`.

## Resultado de referencia

Corrida de prueba con el LLM apagado (respaldo por reglas) y Open vSwitch en espacio de usuario:

- Incidente 1: bloqueo de 10.0.10.1 a los 10,6 s (M2 y M5, 60 puntos), DROP en s1, s2 y s3; el agente recomendó `cuarentena_puertos` (confianza 0,72) y, aprobada, Ryu pasó el host a `cuarentena`.
- Incidente 2: bloqueo de 10.0.20.1 a los 7,5 s (M1 y M5, 65 puntos); `cuarentena_puertos` (0,74), aprobada.
- Duración total: unos 2 minutos.

Con el LLM activo la explicación tarda más (hasta `LLM_TIMEOUT`) y la acción recomendada puede cambiar.
