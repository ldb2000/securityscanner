# Formats de sortie

`--format` accepte `sarif` (défaut de `scan`), `json`, `md` (défaut de `audit`/`report`).

## SARIF 2.1.0
Format canonique, exploitable par le code scanning des forges. Exclut les faux
positifs. Le manifeste de run est placé dans `properties`.

```bash
sec-scan scan . --only sast --format sarif --out sec-scan.sarif
```

## JSON
Export stable `{ manifest, findings }` : idéal pour l'archivage et le re-rendu.

```bash
sec-scan scan . --format json --out findings.json
sec-scan report findings.json --format md
```

## Markdown
En-tête + **synthèse par sévérité** + **synthèse par catégorie** + **durées par
scanner** + **delta vs baseline** (nouveaux / résolus) + tableau des findings.

## SBOM (CycloneDX)
La catégorie `sbom` (Syft) produit un SBOM CycloneDX ; le chemin du fichier
généré est indiqué dans le finding informatif correspondant.

```bash
sec-scan scan . --only sbom
```

## Manifeste de run
Présent dans chaque sortie : `startedAt`/`finishedAt`, `target`, `categories`,
`harness`, `toolVersions` (versions exactes), `durations` (ms par scanner),
`scopeRef` et `delta` le cas échéant.

## Exemple de rapport Markdown (extrait)
```
# sec-scan report
- **Target:** `.`
- **Findings:** 2 (after false-positive filtering)
## Summary by severity
| Severity | Count |
|---|---|
| high | 1 |
| medium | 1 |
```
