# Expediente de evidencias — ReportAudit 1.0.0

- Repositorio: https://github.com/pablohoyoss/reportaudit-lab
- Versión: v1.0.0
- Fecha: 2026-11-26
- Responsable: Jose Pablo Hoyos del Rey

> Índice de evidencias frente a la Cyber Resilience Act (Reglamento (UE) 2024/2847).
> No es una declaración de conformidad: dice qué está demostrado y cómo comprobarlo.

| # | Requisito | Referencia | Evidencia en ReportAudit | Enlace | Cómo lo verifica un tercero |
|---|---|---|---|---|---|
| 1 | Sin vulnerabilidades explotables conocidas al publicar | Anexo I, Parte I, 2.a | Checks SAST y SCA en verde en el commit de v1.0.0; Grype y Trivy «después»; VEX | https://github.com/pablohoyoss/reportaudit-lab/blob/v1.0.0/docs/evidencias/grype-despues.txt | `gh run list --commit $(git rev-list -n1 v1.0.0)` y abrir `grype-despues.txt` («No vulnerabilities found») |
| 2 | Configuración segura por defecto | Anexo I, Parte I, 2.b | PRs de auditoría #20 y #27 (yaml.safe_load, consulta parametrizada, secretos fuera del código) | https://github.com/pablohoyoss/reportaudit-lab/pull/27 | `grep -n "safe_load\|os.environ\|?" app/reporte_auditoria.py` en v1.0.0 |
| 3 | Protección frente a accesos no autorizados | Anexo I, Parte I, 2.d | Credenciales en variables de entorno; regla propia de Gitleaks; push protection | https://github.com/pablohoyoss/reportaudit-lab/blob/v1.0.0/.gitleaks.toml | `gitleaks git . -c .gitleaks.toml` responde «no leaks found» |
| 4 | Identificar y documentar los componentes (SBOM) | Anexo I, Parte II, 1 | SBOM CycloneDX atestado en la Release v1.0.0 | https://github.com/pablohoyoss/reportaudit-lab/releases/tag/v1.0.0 | `gh attestation verify reportaudit-1.0.0.tar.gz --repo pablohoyoss/reportaudit-lab --predicate-type https://cyclonedx.org/bom` |
| 5 | Corregir las vulnerabilidades sin demora | Anexo I, Parte II, 2 | Dependabot activo; PR de dependencias #21; puerta SCA obligatoria | https://github.com/pablohoyoss/reportaudit-lab/pull/21 | `gh api repos/pablohoyoss/reportaudit-lab/branches/main/protection --jq '.required_status_checks.contexts'` incluye «SCA - pip-audit» |
| 6 | Pruebas y revisiones periódicas | Anexo I, Parte II, 3 | Pipeline en cada PR; Scorecard semanal (7.1) | https://scorecard.dev/viewer/?uri=github.com/pablohoyoss/reportaudit-lab | Abrir el visor de Scorecard y la pestaña Actions del repositorio |
| 7 | Información sobre vulnerabilidades corregidas | Anexo I, Parte II, 4 | Borrador de aviso del simulacro (en un caso real, se publicaría con la versión corregida) | https://github.com/pablohoyoss/reportaudit-lab/security/advisories (visible solo para colaboradores) | Security → Advisories: borrador con CVSS, CWE-89 y créditos |
| 8 | Política de divulgación coordinada | Anexo I, Parte II, 5 | SECURITY.md y canal privado activado | https://github.com/pablohoyoss/reportaudit-lab/security/policy | Pestaña Security → Policy, y botón «Report a vulnerability» visible |
| 9 | Dirección de contacto para vulnerabilidades | Anexo I, Parte II, 6 | SECURITY.md → Report a vulnerability | https://github.com/pablohoyoss/reportaudit-lab/security/advisories/new | Abrir el enlace sin sesión: pide iniciar sesión para informar en privado |
| 10 | Distribución segura de las actualizaciones | Anexo I, Parte II, 7 | Release firmada: SHA256SUMS y procedencia Sigstore | https://github.com/pablohoyoss/reportaudit-lab/releases/tag/v1.0.0 | `sha256sum -c SHA256SUMS` y `gh attestation verify reportaudit-1.0.0.tar.gz --repo pablohoyoss/reportaudit-lab` |
| 11 | Período de soporte declarado | Art. 13.8 | SECURITY.md → Supported versions (1.x hasta 2031-10-31) | https://github.com/pablohoyoss/reportaudit-lab/blob/v1.0.0/SECURITY.md | Leer la tabla Supported versions: al menos 5 años desde 1.0.0 |
| 12 | Trazabilidad: cada cambio nace de un Issue y entra por un PR revisado | Buena práctica (no es un requisito literal) | Milestone «Lab 1 - Secure supply chain» con sus Issues cerrados; PRs aprobados; protección de main | https://github.com/pablohoyoss/reportaudit-lab/milestones?state=closed | `gh pr list --state merged --json number,reviewDecision` |

## Lo que este expediente todavía no incluye
La evaluación de riesgos documentada, la documentación técnica completa del Anexo VII, la declaración UE de conformidad y el marcado CE. Los estudiaste en la Práctica 2.
