# Installation

Prérequis : **Node.js ≥ 20**.

## Via npm / npx (sans toolchain locale)

```bash
npx @ldb2000/sec-scan scan . --only sast,sca,secrets
# ou installation globale
npm i -g @ldb2000/sec-scan && sec-scan --help
```

## Image conteneur (scanners préinstallés et épinglés)

```bash
docker run --rm -v "$PWD:/src" ghcr.io/ldb2000/securityscanner scan /src --only sast,sca,secrets
```

## Depuis les sources

```bash
git clone https://github.com/ldb2000/securityscanner && cd securityscanner
npm install
npm run build
node dist/cli/src/index.js --help
```

## Bundle autonome (fichier unique)

```bash
npm run bundle          # produit dist/sec-scan.cjs
./dist/sec-scan.cjs --help
```

## Installer les scanners externes

Les adaptateurs appellent les binaires réels et se neutralisent proprement s'ils
sont absents. Pour les installer et vérifier les versions épinglées :

```bash
scripts/install-tools.sh            # installe tout, puis vérifie
scripts/install-tools.sh verify     # liste ce qui est présent
scripts/install-tools.sh trivy syft # outils ciblés
scripts/verify-tools.sh             # assert versions == versions épinglées
```

`SEC_SCAN_BIN_DIR` (défaut `$HOME/.local/bin`) choisit le dossier d'installation.
