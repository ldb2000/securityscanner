# Intégration CI/CD

## GitHub Actions (action composite)
```yaml
name: security
on: [pull_request]
jobs:
  sec-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # requis pour l'upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: ldb2000/securityscanner@v1
        with:
          path: .
          categories: sast,sca,secrets,iac,sbom
          fail-on: high
          upload-sarif: "true"
```

L'action installe les scanners, **upload le SARIF vers code scanning** et
applique le gate `sec-scan ci --fail-on`. Exemple complet :
[`examples/github-actions.yml`](../examples/github-actions.yml).

## Gate manuel
```bash
sec-scan scan . --only sast,sca,secrets --format sarif --out sec-scan.sarif
sec-scan ci . --only sast,sca,secrets --fail-on high
```

## Codes de sortie
- `0` : rien au seuil ou au-dessus.
- `1` : au moins un finding **au-dessus ou égal** au seuil → **le job échoue**.
- `2` : erreur d'usage (scope/baseline/config invalide).

## GitLab CI
Voir [`examples/gitlab-ci.yml`](../examples/gitlab-ci.yml) (artefact
`reports:sast`).
