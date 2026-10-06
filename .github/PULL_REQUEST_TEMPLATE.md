Linked issue

<!--
Primero el contexto.
Closes #N cierra el Issue al fusionar en main.
Si el PR no lo termina, usa Refs #N.
Sin Issue: N/A y el motivo.
-->

Closes #

Summary

<!--
Qué problema resuelve y por qué, en 2-3 frases y en inglés.
-->

Type of change

<!--
Debe coincidir con el prefijo Conventional Commits del título.
-->

- [ ] fix: bug fix
- [ ] feat: new feature
- [ ] refactor: internal change, same behaviour
- [ ] perf: performance improvement
- [ ] test: tests added or changed
- [ ] docs: documentation only
- [ ] build: dependencies, pipeline or configuration
- [ ] ci: continuous integration or automation
- [ ] BREAKING CHANGE: breaks compatibility; explain the migration

What changed

<!--
Los cambios técnicos importantes, uno por línea.
-->

-

Security / supply-chain impact

<!--
Obligatorio. Si una casilla no aplica, marca N/A.
-->

- [ ] No new dependencies, or each one is justified below: name, exact version, licence, why.
- [ ] All required checks are green: SAST, SCA, secrets and no new code-scanning alerts.
- [ ] No secrets, tokens or personal data in the code, the commits or the logs.
- [ ] If dependencies changed, the SBOM will be regenerated in the next release.

Findings addressed

<!--
Una fila por hallazgo. Borra la tabla si no corrige ninguno.
-->

| ID | Detected by | Rule / CVE | File:line | Category | Severity | Resolution |
|---|---|---|---|---|---|---|
| | | | | | | |

Accepted risks

<!--
Enlace al VEX de lo que NO se corrige y quién asume el riesgo.
-->

Credentials to rotate

<!--
Toda credencial que estuvo en el historial está comprometida.
-->

Design decisions

<!--
Lo que el revisor no puede deducir leyendo el diff.
-->

- Approach and why:
- Alternatives discarded:

How to review

<!--
Orden de lectura recomendado y en qué debe fijarse el revisor.
-->

1. Review the changed files and the linked Issue.
2. Check the security and supply-chain impact.
3. Verify the testing evidence.
4. Confirm the risks and rollback plan.

Testing evidence

- [ ] Tested locally: the service starts and the affected endpoints behave as expected.
- [ ] `pre-commit run --all-files` passes.
- [ ] Evidence attached: terminal output, screenshots or reports in `docs/evidencias/`.

Risks / rollback

<!--
Qué puede salir mal y cómo se deshace.
-->

- Risk:
- Rollback plan:

Author checklist

- [ ] I self-reviewed the diff on GitHub before requesting review.
- [ ] The PR is small, ideally about 400 changed lines or fewer, and covers a single topic.
- [ ] The PR title follows Conventional Commits.
- [ ] Comments explain why, not what.
- [ ] If an AI assistant was used, I reviewed and understand every line I submit.
