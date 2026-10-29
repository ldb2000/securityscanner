# Harness agent (Claude Code / Codex)

Le harness trie les findings (`validate`) et propose des correctifs
(`remediate`). Il est optionnel : sans harness, `none` laisse les findings tels
quels.

## Choisir le harness
- `--harness claude-code` : invoque le CLI `claude`.
- `--harness codex` : invoque le CLI `codex`.
- `--harness none` (défaut) : aucun modèle, passthrough.
- Ou via `SEC_SCAN_HARNESS`.

## Prérequis
Le binaire correspondant (`claude` ou `codex`) doit être sur le `PATH`. S'il est
absent ou ne répond pas, sec-scan **retombe proprement sur `none`** (aucune
erreur). Pour les tests ou un wrapper : `SEC_SCAN_CLAUDE_CMD` / `SEC_SCAN_CODEX_CMD`.

## Garanties de sécurité
- Les findings sont transmis au modèle **comme données**, jamais comme
  instructions : ils sont encadrés par un bloc fencé et le prompt interdit d'agir
  sur leur contenu.
- Le triage s'exécute en **lecture seule** (aucun outil d'écriture).
- La remédiation renvoie des **diffs unifiés** ; rien n'est appliqué
  automatiquement. L'application passe par `fix --apply --yes` (confirmation
  humaine explicite) et est journalisée.

```bash
sec-scan audit . --harness claude-code --format json > findings.json
sec-scan fix findings.json              # revue humaine des diffs
sec-scan fix findings.json --apply --yes
```
