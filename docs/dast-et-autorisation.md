# DAST et autorisation

> **Usage autorisé uniquement.** N'exécutez des scans actifs que contre des
> systèmes que vous possédez ou êtes explicitement autorisé à tester. Cette page
> ne contient aucun contenu offensif : sec-scan ne fournit ni exploit, ni
> payload, ni automatisation d'attaque — seulement des scans passifs/baseline
> encadrés.

Les catégories actives (`dast` : `nuclei`, `zap` en mode baseline passif) sont
**refusées** tant qu'un périmètre d'autorisation n'est pas fourni.

## Fichier de scope (`scope.json`)
```json
{
  "authorizedBy": "equipe-secu",
  "authorizedAt": "2026-10-29T00:00:00Z",
  "note": "staging uniquement",
  "targets": ["staging.example.com", "*.staging.example.com", "10.0.0.0/24"]
}
```

L'allow-list accepte des **hôtes exacts**, des **wildcards** `*.exemple.com` (un
seul label) et des **plages CIDR IPv4**.

```bash
sec-scan scope scope.json                                   # valide et affiche l'attestation
sec-scan scan https://staging.example.com --only dast --scope scope.json
```

## Rejet hors périmètre
Toute cible absente de l'allow-list est **rejetée avant tout trafic réseau**
(aucune requête n'est émise). Sans `--scope`, les adaptateurs actifs sont ignorés.

## Limites de débit et durée
Les adaptateurs actifs sont **rate-limités** et **time-boxés** :
- `SEC_SCAN_DAST_RATE_LIMIT` (défaut `50` req/s)
- `SEC_SCAN_DAST_TIMEOUT_MS` (défaut `300000` ms)

## Journal d'audit
Chaque run actif qui franchit la garde écrit une entrée horodatée incluant
**qui** (`authorizedBy`), **quand** (`authorizedAt`) et le **périmètre**
(`targets`) dans `.sec-scan-audit.log` (ou `SEC_SCAN_AUDIT_LOG`). Les
applications de correctifs (`fix --apply`) y sont aussi consignées.
