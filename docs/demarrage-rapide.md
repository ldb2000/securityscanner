# Démarrage rapide

## 1. Premier scan statique

```bash
sec-scan scan . --only sast,sca,secrets --format md
```

Le rapport Markdown affiche un en-tête (cible, harness, catégories), une
**synthèse par sévérité** et **par catégorie**, les durées par scanner, puis la
liste des findings. Sans scanner installé, chaque catégorie est ignorée avec un
message d'installation (sortie toujours valide).

## 2. Produire un rapport exploitable

```bash
sec-scan scan . --only sast,sca,secrets --format json --out findings.json
sec-scan report findings.json --format md    # re-rendu
```

## 3. Audit avec triage par l'agent, puis correctifs

```bash
sec-scan audit . --harness claude-code --format json > findings.json
sec-scan fix findings.json                    # affiche les diffs proposés
sec-scan fix findings.json --apply --yes      # applique après confirmation
```

`fix` sans `--apply` n'écrit rien. `--apply` exige `--yes` ; chaque patch
appliqué est journalisé (voir [DAST et autorisation](dast-et-autorisation.md)).
