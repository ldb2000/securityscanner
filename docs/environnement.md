# Variables d'environnement

| Variable | Défaut | Effet |
|---|---|---|
| `SEC_SCAN_HARNESS` | `none` | harness par défaut (`claude-code`/`codex`/`none`) si `--harness` absent |
| `SEC_SCAN_CLAUDE_CMD` | `claude …` | surcharge la commande du harness Claude Code (tests/wrappers) |
| `SEC_SCAN_CODEX_CMD` | `codex …` | surcharge la commande du harness Codex |
| `SEC_SCAN_BIN_DIR` | `$HOME/.local/bin` | dossier d'installation de `scripts/install-tools.sh` |
| `SEC_SCAN_AUDIT_LOG` | `.sec-scan-audit.log` | chemin du journal d'audit (scans actifs, `fix --apply`) |
| `SEC_SCAN_DAST_RATE_LIMIT` | `50` | requêtes/seconde max des adaptateurs actifs (nuclei) |
| `SEC_SCAN_DAST_TIMEOUT_MS` | `300000` | time-box (ms) des adaptateurs actifs (nuclei, zap) |
| `SEC_SCAN_FINDINGS_DATA` | — | marqueur interne : délimite les findings passés au harness **comme données** |

`SEC_SCAN_FINDINGS_DATA` n'est pas destiné à être défini par l'utilisateur :
c'est le nom du bloc fencé qui isole les findings dans le prompt du harness pour
empêcher toute injection.
