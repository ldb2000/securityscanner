# Configuration (`.sec-scan.json`)

Placez un `.sec-scan.json` à la racine (ou passez `--config <file>`) pour des
runs reproductibles sans flag. Auto-découvert dans le dossier cible puis le cwd.

```json
{
  "categories": ["sast", "sca", "secrets", "iac", "sbom"],
  "profile": "standard",
  "harness": "none",
  "baseline": "baseline.json",
  "rules": {
    "semgrep": { "disable": ["some.rule.id"] },
    "trivy":   { "enable": ["CVE-2024-0001"] }
  }
}
```

| Champ | Valeurs | Rôle |
|---|---|---|
| `categories` | sous-ensemble de sast,sca,secrets,iac,container,sbom,dast | catégories par défaut |
| `profile` | `strict` \| `standard` \| `permissive` | mappe le seuil `ci` |
| `failOn` | critical\|high\|medium\|low\|info | seuil `ci` explicite (prioritaire sur `profile`) |
| `harness` | claude-code\|codex\|none | harness par défaut |
| `baseline` | chemin | fichier de suppressions par défaut |
| `rules` | objet par outil | `disable` (retirer des ruleId) / `enable` (ne garder que ceux-ci) |

## Profils → seuil `ci`
- `strict` → `medium`
- `standard` → `high`
- `permissive` → `critical`

## Précédence
**flag CLI > `.sec-scan.json` > défaut intégré.** Exemple : `--fail-on` surcharge
`failOn`, qui surcharge le seuil dérivé de `profile`.

## Erreurs
Une configuration invalide (catégorie inconnue, profil hors liste, `rules` mal
formé, JSON invalide) est rejetée avec un message clair et un **code de sortie 2**.
