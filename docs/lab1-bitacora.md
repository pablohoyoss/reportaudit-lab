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
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ | ✓ (pythonsecurity:S3649) | ✓ (pythonsecurity:S3649) | ✓ (py/sql-injection) | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ | ✓ (pythonsecurity:S2076) | ✓ (pythonsecurity:S2076) | ✓ (py/command-line-injection) | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ (avoid-pyyaml-load) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ (python:S4790) | ✓ (python:S4790) | ✓ (python:S4790, hotspot) | ✓ (py/weak-sensitive-data-hashing) | ✓ (insecure-hash-algorithm-md5, md5-used-as-password) | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ | ✓ (secrets:S7552) | ✓ (secrets:S7552) | ✗ | ✗ | ✗ |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ (python:S2068) | ✓ (python:S2068) | ✓ (python:S2068) | ✗ | ✗ | ✗ |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

> Ninguna herramienta lo detectó todo. CodeQL y SonarQube Cloud encontraron las inyecciones (siguen el flujo del dato), Semgrep el YAML y el MD5 (patrones), SonarQube las credenciales, y Trivy ninguna credencial porque no siguen el formato de ningún proveedor. CodeQL encontró además un hallazgo que la auditoría manual no tenía: la clave de API impresa en el log (py/clear-text-logging-sensitive-data). Depender de una sola herramienta habría dejado huecos: se combinan por capas.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 4 |
| Componentes Python en el SBOM | 9 (4 directas + 5 transitivas que no aparecen en `requirements.in`) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 1: `/tmp/reportaudit-antes/requirements.txt` (tipo `file`), el manifiesto del que Syft leyó las dependencias; no es un paquete de PyPI |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | CycloneDX 1.7 |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-2g68-c3qc-8985 | High | 3.0.3 | No: requiere el depurador de Werkzeug (`debug=True`); el servicio arranca sin él (ver VEX) | Actualizar + VEX |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-q34m-jh98-gwm2 | Medium | 3.0.6 | Posible: DoS al procesar `multipart/form-data` si un endpoint lee formularios | Actualizar |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-f9vj-2wh5-fj8j | Medium | 3.0.6 | No: `safe_join` solo vulnerable en Windows; el servicio corre en Linux | Actualizar |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-29vq-49wr-vm6x | Medium | 3.1.6 | No: nombres de dispositivo de Windows; el servicio corre en Linux | Actualizar |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-hgf8-39gv-g3f2 | Medium | 3.1.4 | No: nombres de dispositivo de Windows; el servicio corre en Linux | Actualizar |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-87hc-h4r5-73f7 | Medium | 3.1.5 | No: nombres de dispositivo de Windows; el servicio corre en Linux | Actualizar |
| werkzeug | 3.0.1 | Transitiva (via flask) | GHSA-g6x2-hccm-hh4m | Medium | 3.1.9 | No: `safe_join` con dispositivos de Windows; el servicio corre en Linux | Actualizar |
| jinja2 | 3.1.2 | Transitiva (via flask) | GHSA-h75v-3vvj-5mfj | Medium | 3.1.4 | No: XSS en el filtro `xmlattr`; ReportAudit responde con `jsonify` y no renderiza plantillas | Actualizar |
| jinja2 | 3.1.2 | Transitiva (via flask) | GHSA-h5c8-rqwp-cp95 | Medium | 3.1.3 | No: XSS en el filtro `xmlattr`; no se renderizan plantillas | Actualizar |
| jinja2 | 3.1.2 | Transitiva (via flask) | GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No: escape del sandbox de Jinja, que ReportAudit no usa | Actualizar |
| jinja2 | 3.1.2 | Transitiva (via flask) | GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: exige controlar el nombre y el contenido de una plantilla | Actualizar |
| jinja2 | 3.1.2 | Transitiva (via flask) | GHSA-cpwx-vrp4-4pq7 | Medium | 3.1.6 | No: escape del sandbox mediante el filtro `attr`; no se usa el sandbox | Actualizar |
| flask | 3.0.0 | Directa (`requirements.in`) | GHSA-68rp-wp8r-4726 | Low | 3.1.3 | No: fuga de sesión mediante cachés intermedias; ReportAudit no usa `session` | Actualizar |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

> Coinciden en los paquetes afectados (werkzeug, jinja2 y flask), porque Grype y Dependabot consultan las mismas bases de avisos (GitHub Advisory Database). Las diferencias son de uso, no de datos: Grype analiza el SBOM en local y añade EPSS para priorizar; Dependabot vigila el repositorio de forma continua y abre el PR con la corrección.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (YAML inseguro y 2 de MD5) | 0 (Passed) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 (inyección SQL, inyección de comandos, hash débil, clave en el log) | 0 (todas *Fixed*) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 5 (S3649, S2076, S2068, S7552, S4502) | 1 (S4502: no aplica, solo endpoints GET sin cookies ni sesión; pendiente de aceptar) |
| Security Hotspots por revisar en SonarQube Cloud | 1 (S4790, MD5) | 0 |
| Vulnerabilidades de Grype sobre el SBOM | 13 (1 High, 11 Medium, 1 Low) | 0 |
| Alertas abiertas de Dependabot | N | 0 |

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
## 7. Preguntas de comprobación

**1.** En Windows solo vive la interfaz de VS Code (con la extensión WSL) y el navegador. En Ubuntu (WSL2) vive todo lo que se ejecuta: el clon del repositorio, el venv con Python 3.12, Git, pre-commit, las extensiones de análisis y las herramientas de tools/ (Syft, Grype, Trivy, Gitleaks). En GitHub viven el repositorio remoto, los Issues y PRs, el pipeline de Actions y los paneles de Security (CodeQL, Dependabot, secret scanning); SonarQube Cloud está conectado a él. Se trabaja en Ubuntu porque es el mismo sistema que usa el pipeline (ubuntu-latest): lo que funciona en local funciona en la nube, sin diferencias de rutas ni de finales de línea.

**2.** Una dependencia directa es la que declaro yo; una transitiva llega porque la necesita otra. En requirements.txt, flask aparece con `# via -r requirements.in` (directa), mientras que werkzeug y jinja2 aparecen con `# via flask` (transitivas). El SBOM lo confirma: declaro 4 dependencias en requirements.in, pero sbom.cyclonedx.json contiene 9 componentes de PyPI. Ese es el iceberg: la mayoría de las vulnerabilidades de Grype (12 de 13) estaban en paquetes que yo no había escrito.

**3.** El source es el punto por donde entra un dato controlado por el usuario; el sink, la operación peligrosa donde acaba. Ejemplo: el parámetro `cliente` de la ruta `/reportes` en app/servicio.py (source) llega sin filtrar a `cursor.execute` en `buscar_reportes_cliente` de app/reporte_auditoria.py, línea 42 (sink). Lo mismo con `archivo` en `/convertir`, que acababa en `os.system` (línea 51).

**4.** La consulta se construía concatenando el texto: `... WHERE cliente = '` + nombre + `'`. El apóstrofo de o'brien_ltd cerraba la cadena antes de tiempo y el SQL quedaba mal formado, de ahí el error 500. Eso demuestra que el dato se interpretaba como parte de la orden SQL y no como un valor: un atacante podría escribir SQL a propósito (por ejemplo `' OR '1'='1`) y leer los reportes de todos los clientes. Con la consulta parametrizada (`?`) el apóstrofo es solo un carácter más.

**5.** El hook de Semgrep actúa en mi equipo antes de crear el commit: el código inseguro no llega ni al historial ni a GitHub, y la respuesta es inmediata. SonarQube Cloud y CodeQL actúan después, en el PR. Pero el hook solo no basta: se puede saltar (--no-verify o no tenerlo instalado), solo protege a quien lo instala y sus reglas son limitadas. Sobre el código original encontró 3 hallazgos (YAML inseguro y dos de MD5), pero no detectó la inyección SQL ni la de comandos. Hace falta una puerta obligatoria en el servidor.

**6.** No es un error: cada herramienta usa una técnica distinta. Según mi matriz, CodeQL y SonarQube Cloud detectaron las inyecciones SQL y de comandos porque siguen el flujo del dato (taint analysis); Semgrep detectó el YAML inseguro y el MD5 por patrones, pero no las inyecciones; SonarQube Cloud detectó las credenciales (S2068, S7552) y Trivy no, porque no siguen el formato de ningún proveedor. Ninguna lo detectó todo: por eso se combinan (defensa en profundidad).

**7.** Porque son problemas de categorías distintas y cada alerta se cierra cuando su propio análisis deja de encontrarla. CodeQL analiza mi código fuente: se cierra cuando corrijo el código (PR #20 y #27). Dependabot analiza las versiones de requirements.txt: solo se cierra cuando cambian esas versiones (PR de dependencias). Un PR de código no toca las versiones y un PR de dependencias no cambia mi código.

**8.** Borrar el secreto del código crea un commit nuevo, pero el valor sigue en el historial: Gitleaks lo encontró en el commit de importación be58667 (líneas 21 y 22), y cualquiera con un clon o un fork lo tiene. Corregirlo de verdad significa rotar la credencial en el proveedor para que el valor expuesto deje de servir, leerla de variables de entorno (REPORTAUDIT_NOTIFICATION_API_KEY, REPORTAUDIT_SMTP_PASSWORD) e impedir que vuelva a entrar (regla propia de Gitleaks como check obligatorio).

**9.** Ignorar una alerta no deja rastro: nadie sabe quién la descartó, cuándo ni por qué, y vuelve a aparecer. Un VEX es un documento estándar y legible por máquinas que registra la decisión con autor, fecha, componente exacto, estado y justificación, y que cualquiera puede revisar. Mi VEX declara CVE-2024-34069 (pkg:pypi/werkzeug@3.0.1) como not_affected con la justificación vulnerable_code_not_in_execute_path: la vulnerabilidad necesita el depurador interactivo de Werkzeug y ReportAudit arranca con debug=False (app/servicio.py, línea 64). Aun así, la dependencia se actualizó.

**10.** El instalador fija una versión concreta, descarga el binario y la lista oficial de huellas, y comprueba con sha256sum que coinciden antes de ejecutar nada. Eso garantiza integridad: el archivo es exactamente el publicado, sin corrupción ni manipulación en la descarga. No garantiza que lo publicado sea legítimo: en marzo de 2026 TeamPCP comprometió el propio Trivy y reescribió 76 de sus 77 etiquetas para que apuntaran a código malicioso. Si el atacante controla la publicación, la huella coincidirá igualmente. Por eso también importan la procedencia firmada (Parte R) y fijar versiones conocidas.

**11.** `gitleaks dir app` analiza los archivos tal como están ahora, y el código lee las credenciales con os.environ.get: no hay nada que encontrar. `gitleaks git .` recorre los 24 commits, y en be58667 las dos credenciales siguen escritas: con mi regla propia aparecen 2 hallazgos. El riesgo lo cierra la rotación: el valor antiguo ya no sirve. Registrarlas en .gitleaksignore no cierra nada por sí solo; solo evita que un hallazgo ya resuelto bloquee cada análisis.

**12.** Porque en la Parte G las dependencias todavía eran vulnerables (Grype encontró 13 vulnerabilidades). Si pip-audit hubiera sido obligatorio entonces, ningún PR se habría podido fusionar, ni siquiera los que las corregían. El ratchet (trinquete) es primero llevar el sistema al nivel deseado y después prohibir retroceder: en mi repositorio, primero actualicé las dependencias (PR #21) hasta dejar Grype en 0, y después convertí pip-audit en check obligatorio de main, de modo que una dependencia vulnerable ya no puede volver a entrar.

**13.** Una alerta de Dependabot es un aviso (y, a veces, un PR con la corrección), pero no impide nada: se puede fusionar un PR con una dependencia vulnerable. SCA - pip-audit es un check obligatorio de main: si el PR introduce una dependencia con una vulnerabilidad conocida, el check falla y el PR no puede entrar. Lo comprobé con el PR de prueba test/puerta-sca (werkzeug 3.0.1), que quedó en rojo y se cerró sin fusionar.

**15.** Un Issue es público: publicaría la vulnerabilidad y cómo explotarla antes de que exista el parche, y cualquier atacante podría usarla contra quien tenga la versión afectada. El canal privado (private vulnerability reporting) permite que solo el responsable y el investigador vean el informe mientras se prepara la corrección. SECURITY.md declara públicamente ese canal, los plazos de respuesta (3 y 10 días hábiles, divulgación en 90 días), el período de soporte (hasta 2031-10-31, 5 años como exige la CRA) y la garantía de no emprender acciones legales contra investigadores de buena fe.


---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 (tras sustituir las constantes en `app/reporte_auditoria.py` por `os.environ.get(...)`) | — (código limpio en árbol de trabajo) |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key` en `app/reporte_auditoria.py:21`) | `be586678` |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`reportaudit-hardcoded-credential` en L21 y L22) | `be586678` |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 (fingerprints históricos aceptados tras rotación) | — (ignorados explícitamente) |

- **¿Por qué el código actual está limpio y el historial no?** Porque Git almacena cada commit como un objeto inmutable; eliminar una credencial en un commit posterior modifica únicamente la foto actual (`HEAD`), pero los objetos del commit inicial (`be586678`) permanecen íntegros y accesibles mediante `git log -p` o herramientas de escaneo de historial.
- **¿Qué medida de la Parte M cierra el riesgo y cuál no lo cierra?**
  - **Cierra el riesgo:** Revocar y rotar inmediatamente las credenciales expuestas (`NOTIFICATION_API_KEY` y `SMTP_PASSWORD`) en sus respectivos servicios externos e inyectarlas mediante variables de entorno/secretos del entorno de ejecución, junto con el escaneo preventivo de Gitleaks en CI/PR para bloquear futuras fugas.
  - **No cierra el riesgo por sí sola:** Limitarse a borrar los secretos del código fuente en un nuevo commit o registrar sus fingerprints en `.gitleaksignore` sin rotarlas (ya que los valores antiguos siguen visibles en el historial Git y continúan siendo válidos si no se invalidan en origen).

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí | ✓ pass |
| SAST - CodeQL | Sí | ✓ pass |
| SCA - pip-audit | Sí | ✗ fail: werkzeug 3.0.1 vulnerable (PR de prueba cerrado sin fusionar) |
| Secretos - Gitleaks | Sí | ✓ pass |

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

