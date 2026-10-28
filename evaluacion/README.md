# Evaluación R4 (objetivo 3)

Scripts para medir el prototipo (controlador Ryu y agente a la vez) con tráfico y ataques reales en Mininet. Solo usan la librería estándar de Python; no tocan `ryu_controller.py` ni el agente.

| Archivo | Qué hace | ¿sudo? |
|---|---|---|
| `escenarios_r4.json` | 10 escenarios etiquetados: 6 de ataque (A1–A6) y 4 benignos (B1–B4) | — |
| `trafico.py` | Generador que corre dentro de cada host: `victima` (servidores que registran cada conexión) y `conexiones` (ataque o tráfico normal según parámetros) | no |
| `correr_evaluacion.py` | El comando único: verificaciones y plan de acción, agente, serie con LLM y serie con reglas, informe estadístico y planilla de calificación | sí (Mininet) |
| `orquestador.py` | Una serie: N repeticiones de cada escenario en orden aleatorio, con Ryu y Mininet nuevos en cada corrida | sí (Mininet) |
| `evaluar.py` | Cruza el manifiesto con los incidentes del agente y calcula las métricas; también arma la planilla de calificación humana a ciegas | no |
| `test_evaluacion.py` | Pruebas sin Mininet (`python3 -m unittest evaluacion/test_evaluacion.py`) | no |

## Escenarios

| Id | Etiqueta | Qué simula | Métricas previstas (lectura del código) |
|---|---|---|---|
| A1 | ataque | `ataque_completo.py` (barrido + ráfaga) | M1, M2, M5 (lo observado en R1a) |
| A2 | ataque | Conexiones pausadas a 5 pares (equipo, puerto) en 3 equipos | M1, M5 (bloqueo con solo 2 métricas, 65 puntos) |
| A3 | ataque | 600 KB por SMB a los 9 equipos de OPS | M1, M2, M4, M5 (M3 teórica) |
| A4 * | ataque | Una conexión cada 12 s (low-and-slow) | M5 sola: se espera un falso negativo |
| A5 | ataque | RDP/WinRM a los 9 equipos de ADM desde h11 | M1, M2, M4, M5 |
| A6 | ataque | Ransomware completo: barrido rápido + copias de 1 MB por SMB en paralelo | M1, M2, M4, M5 (M3 teórica): busca las 5 |
| B1 | benigno | HTTP 8080 desde 3 equipos a 6 servidores | ninguna |
| B2 | benigno | 3 clientes copian 2 MB por SMB a un único servidor | M1, M4 (40 puntos, sospechoso sin bloqueo) |
| B3 * | benigno | Administrador de TI: 3 servidores × RDP y WinRM | M1, M4, M5: se espera un falso positivo |
| B4 | benigno | 3 × 50 MB por TCP 5001 entre dos equipos | ninguna |

\* Caso difícil por diseño. Se reportan en el total y aparte (`sin_casos_dificiles`).

M1 y M4 cuentan Packet-In, no conexiones: hacia los hosts .1 a .5 de cada VLAN en puertos críticos, cada paquete sube al controlador por las reglas de monitoreo de M5.

**Hallazgo a confirmar con las corridas:** M3 solo se evalúa sobre reglas con `ipv4_src`, `ipv4_dst` y `tcp_dst=445`. Hoy esas reglas son las de monitoreo de M5, que son permanentes (su `duration` pasa de 5 s al poco de instalarse), así que M3 no debería dispararse nunca. A3 y A6 lo comprueban.

## Cómo correrlo

Un solo comando prueba el controlador y el agente a la vez. No hace falta arrancar nada a mano: el script arranca su propio Ryu en cada corrida y usa el agente que esté en :8081 o lo arranca desde `~/Desktop/sdn-agent-v2` con su `.env` (de ahí toma los tokens).

```
cd ~/Desktop/RYU_IA
python3 evaluacion/correr_evaluacion.py --dry-run                                     # verificaciones y plan de acción, sin sudo
sudo /usr/bin/python3 evaluacion/correr_evaluacion.py --solo A6,B1 --repeticiones 1   # prueba de humo (~15 min)
sudo /usr/bin/python3 evaluacion/correr_evaluacion.py                                 # evaluación completa
```

La evaluación completa son 10 escenarios × 10 repeticiones × 2 series (LLM activo y LLM apagado con respaldo por reglas): 200 corridas, unas 9 a 10 horas. Para acortar: `--repeticiones 5` o `--bloques llm`. Antes de empezar, el mock de Ryu del agente debe estar apagado (usa el puerto 8080).

Al terminar queda todo en `evaluacion/resultados/<fecha>_objetivo3/`:

- `plan_de_accion.md`: las verificaciones previas y lo que se ejecutó.
- `informe/resumen.md`: el resumen estadístico, empezando por la tabla de cumplimiento del objetivo 3 (precisión, tasas de FP y FN, calidad de las recomendaciones, tiempos), y luego detección por escenario, métricas M1 a M5 disparadas, contención, tiempos por etapa, explicación y la comparación LLM frente a reglas (Fisher y Mann-Whitney).
- `informe/corridas.csv` (una fila por corrida, para gráficas) e `informe/evaluacion.json` (todo con intervalos de confianza).
- `calificacion/plantilla_calificacion.csv`: las explicaciones barajadas y sin la fuente, para que cada evaluador las califique de 1 a 5. Después: `python3 evaluacion/evaluar.py calificaciones --clave calificacion/clave_calificacion.csv eval1.csv eval2.csv`.
- Una carpeta por serie y por corrida con el log de Ryu y las bitácoras de víctimas y tráfico, y `agente.log` si el script arrancó el agente.

Durante la evaluación nadie aprueba acciones: el agente explica y recomienda, pero todo host aislado sigue en DROP. El script pone `CONTEXTO_HABILITADO=false` para que una corrida no influya en la siguiente y al final restaura la configuración del agente.

`orquestador.py` es la pieza de bajo nivel (una serie, con o sin agente) y `evaluar.py` repite el informe sin volver a correr: `python3 evaluacion/evaluar.py metricas <manifiestos...> --salida <carpeta>`.

## Cómo se calcula cada métrica

**Unidad de análisis:** la corrida. Positiva si el escenario es de ataque. En un ataque, la corrida es VP si se bloquea el host atacante (`sospechosos`); en un benigno, cualquier bloqueo es FP. Los bloqueos de otros hosts durante un ataque se cuentan como colaterales.

- Precisión = VP/(VP+FP); exhaustividad (recall) = VP/(VP+FN); tasa FP = FP/(FP+VN); tasa FN = FN/(FN+VP); F1, exactitud y MCC. Las proporciones llevan intervalo de Wilson al 95 %.
- Tiempo de detección y bloqueo = `desde` de Ryu (hora del DROP) − `t_inicio` del escenario. Todos los relojes son el de la misma máquina.
- Tiempos del agente con sus marcas: alerta `t_recibido − t_ryu`, explicación `t_explicado − t_recibido`, notificación `t_notificado − t_explicado`, total hasta el operador `t_notificado − t_inicio`, decisión del operador `t_desbloqueado − t_notificado` (solo si alguien desbloqueó). Se reportan n, media, desviación, mediana, p25, p75, p95, mínimo y máximo.
- Contención: DROP de prioridad 100 presente en s1, s2 y s3; conexiones del atacante aceptadas por las víctimas después del DROP (debe ser 0); equipos alcanzados antes del DROP.
- Explicación: concordancia del veredicto final con la etiqueta (ataque → confirmado, benigno → falso_positivo), sin y con las abstenciones (indeterminado); fuente (LLM o reglas) y motivo del respaldo; porcentaje verificado por el verificador numérico del agente; cobertura = métricas disparadas mencionadas en el texto / métricas disparadas (búsqueda por patrones, heurística); bloques del lenguaje sencillo reemplazados por plantilla.
- Recomendación: en un ataque se prefieren `cuarentena_puertos` o `cuarentena_vlan`, se acepta `mantener_drop` y `limitar_tasa` es insegura; en un benigno se prefiere `limitar_tasa` y se acepta `mantener_drop`.
- LLM frente a reglas: mismas corridas con el LLM activo y apagado; proporciones con la prueba exacta de Fisher y tiempos con U de Mann-Whitney y delta de Cliff.
- Calificación humana: 4 criterios en escala 1–5 (comprensible, fiel a los datos, completa, accionable), a ciegas de la fuente; acuerdo entre evaluadores con alfa de Krippendorff ordinal.
