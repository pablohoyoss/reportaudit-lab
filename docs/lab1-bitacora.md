# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** JOSE PABLO HOYOS DEL REY
- **Repositorio:** https://github.com/pablohoyoss/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04 LTS (WSL2), Python 3.12

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)


| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 42 | Inyección SQL: el nombre del cliente se concatena directamente en la consulta con `+`, sin parametrizar | Parámetro `cliente` (servicio.py, función `reportes`) | `cursor.execute(query)` |
| 2 | `convertir_a_pdf` | 51 | Inyección de comandos: el nombre de archivo se concatena en un comando de shell ejecutado con `os.system` | Parámetro `archivo` (servicio.py, función `convertir`) | `os.system(comando)` |
| 3 | `cargar_configuracion` | 26 | Deserialización insegura de YAML: usa `yaml.Loader` (cargador completo) en vez de `safe_load` | Contenido de `config.yaml` | `yaml.load(f, Loader=yaml.Loader)` |
| 4 | `hash_password_legacy` | 57 | Hash débil: MD5 sin salt, vulnerable a fuerza bruta y tablas precalculadas | Parámetro `password` de la función | `hashlib.md5(password.encode()).hexdigest()` |
| 5 | Constantes iniciales `NOTIFICATION_API_KEY` / `SMTP_PASSWORD` | 15-16 | Secretos expuestos: credenciales reales escritas en el código, ya en el historial de Git | — | Variables globales usadas en `notificar_cliente` |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).
una inyección SQL permitiría leer o alterar los
reportes de auditoría de cualquier cliente (H1). Una inyección de comandos
daría control sobre el servidor donde corre ReportAudit (H2). Un YAML
malicioso podría ejecutar código arbitrario si un atacante controlara
`config.yaml` (H3). El hash MD5 dejaría las contraseñas de clientes
expuestas ante una fuga de la base de datos (H4). Las credenciales escritas
en el código permitirían a cualquiera con acceso al repositorio suplantar
el servicio de notificaciones y enviar correos en su nombre (H5).

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ |  |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ |  |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ |  |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ (python:S4790) |  |  |  |  | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ |  |  |  |  |  |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ (python:S2068) |  |  |  |  |  |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) |  |
| Componentes Python en el SBOM |  |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen |  |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) |  |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` |  |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM |  |  |
| Alertas abiertas de Dependabot |  |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.

## Integración de SAST Automático (GitHub Actions & CodeQL / SonarQube)

- **SonarQube Cloud**: Integración exitosa mediante secreto `SONAR_TOKEN` y configuración en `sonar-project.properties`.
- **GitHub CodeQL**: Análisis automático ejecutado en rama `main`.
- **Alertas detectadas por CodeQL**:
  1. **Critical** (`app/reporte_auditoria.py:51`): *Uncontrolled command line* (Inyección de Comandos).
  2. **High** (`app/reporte_auditoria.py:42`): *SQL query built from user-controlled sources* (Inyección SQL).
  3. **High** (`app/reporte_auditoria.py:57`): *Use of a broken or weak cryptographic hashing algorithm* (MD5).
  4. **High** (`app/reporte_auditoria.py:62`): *Clear-text logging of sensitive information* (Fuga de logs).

- **Prueba PR**: Verificación de triggers automáticos en Pull Request.
---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 (tras sustituir las constantes en `app/reporte_auditoria.py` por `os.environ.get(...)`) | — (código limpio en árbol de trabajo) |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key` en `app/reporte_auditoria.py:21`) | `be586678` |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`generic-api-key` en L21 y `reportaudit-smtp-password` en L22) | `be586678` |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 (fingerprints históricos aceptados tras rotación) | — (ignorados explícitamente) |

- **¿Por qué el código actual está limpio y el historial no?** Porque Git almacena cada commit como un objeto inmutable; eliminar una credencial en un commit posterior modifica únicamente la foto actual (`HEAD`), pero los objetos del commit inicial (`be586678`) permanecen íntegros y accesibles mediante `git log -p` o herramientas de escaneo de historial.
- **¿Qué medida de la Parte M cierra el riesgo y cuál no lo cierra?**
  - **Cierra el riesgo:** Revocar y rotar inmediatamente las credenciales expuestas (`NOTIFICATION_API_KEY` y `SMTP_PASSWORD`) en sus respectivos servicios externos e inyectarlas mediante variables de entorno/secretos del entorno de ejecución, junto con el escaneo preventivo de Gitleaks en CI/PR para bloquear futuras fugas.
  - **No cierra el riesgo por sí sola:** Limitarse a borrar los secretos del código fuente en un nuevo commit o añadir sus hashes a `.gitleaksignore` sin rotarlas (ya que los valores antiguos siguen visibles en el historial Git y continúan siendo válidos si no se invalidan en origen).

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | | |
| SAST - CodeQL | | |
| SCA - pip-audit | | |
| Secretos - Gitleaks | | |

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub):
- Identificador del borrador de aviso (GHSA-…):
- Severidad y vector CVSS:
- CWE:
- Versiones afectadas / versión corregida:

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo …` | |
| SBOM atestado | `gh attestation verify … --predicate-type https://cyclonedx.org/bom` | |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo …` | |

### S. Madurez (OpenSSF Scorecard)

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | | |
| | | |
| | | |
| | | |

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`. Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora existe de verdad, y cuál sigue sin existir?

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | | |
| Historial, reglas por defecto | `gitleaks git .` | | |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | | |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | | |

¿Por qué el código actual está limpio y el historial no? ¿Qué medida de la Parte M cierra el riesgo y cuál no lo cierra?

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | | |
| SAST - CodeQL | | |
| SCA - pip-audit | | |
| Secretos - Gitleaks | | |

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub):
- Identificador del borrador de aviso (GHSA-…):
- Severidad y vector CVSS:
- CWE:
- Versiones afectadas / versión corregida:

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo …` | |
| SBOM atestado | `gh attestation verify … --predicate-type https://cyclonedx.org/bom` | |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo …` | |

### S. Madurez (OpenSSF Scorecard)

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | | |
| | | |
| | | |
| | | |

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`. Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora existe de verdad, y cuál sigue sin existir?
