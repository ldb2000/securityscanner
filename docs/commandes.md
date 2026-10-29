# Référence des commandes

Alignée sur `cli/src/index.ts`. Précédence des options : **flag CLI > `.sec-scan.json` > défaut**.

## `scan <path>`
Scan statique (et DAST si demandé et autorisé).

| Option | Défaut | Description |
|---|---|---|
| `--only <categories>` | sast,sca,secrets,iac,container,sbom (pas dast) | catégories, liste séparée par virgules |
| `--format <fmt>` | `sarif` | `sarif` \| `json` \| `md` |
| `--scope <file>` | — | fichier d'autorisation (requis pour `dast`) |
| `--out <file>` | stdout | écrit le rapport dans un fichier |
| `--baseline <file>` | — | supprime les findings connus |
| `--harness <name>` | `none` | `claude-code` \| `codex` \| `none` |
| `--config <file>` | auto-découvert | charge `.sec-scan.json` |

```bash
sec-scan scan . --only sast,secrets --format md
```

## `audit <path>`
`scan → validate → remediate` de bout en bout. Mêmes options que `scan` plus `--format` (défaut `md`).

```bash
sec-scan audit . --harness claude-code --format json > findings.json
```

## `fix <findings.json>`
Affiche les diffs de remédiation ; n'applique qu'avec confirmation.

| Option | Défaut | Description |
|---|---|---|
| `--apply` | off | applique les diffs (exige `--yes`) |
| `--yes` | off | confirmation non-interactive |

```bash
sec-scan fix findings.json              # affichage seul
sec-scan fix findings.json --apply --yes
```

## `report <findings.json>`
Re-rend un fichier de findings JSON.

| Option | Défaut | Description |
|---|---|---|
| `--format <fmt>` | `md` | `sarif` \| `json` \| `md` |

```bash
sec-scan report findings.json --format sarif
```

## `ci <path>`
Scan non-interactif ; code de sortie piloté par seuil.

| Option | Défaut | Description |
|---|---|---|
| `--only <categories>` | défaut de `scan` | catégories |
| `--baseline <file>` | — | suppression |
| `--config <file>` | auto-découvert | charge `.sec-scan.json` |
| `--fail-on <severity>` | `high` (ou profil de la config) | `critical` \| `high` \| `medium` \| `low` |

Codes de sortie : `0` propre, `1` au-dessus du seuil, `2` erreur d'usage.

```bash
sec-scan ci . --only sast,sca,secrets --fail-on high
```

## `baseline <findings.json>`
Génère un fichier de suppressions à partir d'un JSON de findings.

| Option | Défaut | Description |
|---|---|---|
| `--reason <text>` | `baselined` | motif sur chaque suppression |
| `--out <file>` | stdout | écrit la baseline dans un fichier |

```bash
sec-scan baseline findings.json --out baseline.json
```

## `scope <file>`
Inspecte/valide un fichier d'autorisation (aucune option).

```bash
sec-scan scope scope.json
```

## `login`
Placeholder : rappelle de configurer le harness (voir [harness.md](harness.md)). N'enregistre pas de secret.

## Écarts avec SPEC.md §3
- **Pas de commande `validate` autonome** : le triage (`validate`) et la remédiation (`remediate`) sont réalisés par `audit` (puis `fix`), pas via une sous-commande dédiée.
- **`login` est un placeholder** : il n'enregistre aucune donnée d'identification ; la sélection du harness se fait via `--harness` ou `SEC_SCAN_HARNESS`.
- Les drapeaux `--only dast` et le gating de scope sont conformes au §5 du SPEC.
