# Baseline et suppressions

Une baseline masque des findings connus/acceptés. Fichier versionnable :

```json
{
  "suppressions": [
    { "fingerprint": "ab12cd34ef56…", "reason": "risque accepté", "expires": "2026-12-31" }
  ]
}
```

## Générer
```bash
sec-scan scan . --only sast,sca,secrets --format json --out findings.json
sec-scan baseline findings.json --reason "triage initial" --out baseline.json
```

## Utiliser
```bash
sec-scan scan . --baseline baseline.json          # findings connus masqués
sec-scan ci . --baseline baseline.json --fail-on high
```

## Expiration
Un finding est masqué tant qu'une suppression correspond à son empreinte et
n'est pas expirée. Sans `expires`, la suppression est permanente ; une
suppression **expirée est ignorée** et le finding **réapparaît**.

## Stabilité des empreintes
L'empreinte (`id`) est un hash stable de `tool|ruleId|fichier|ligne`, normalisé
via une seule voie d'ingestion SARIF 2.1.0. Elle reste donc **identique entre
deux runs** sur un code inchangé, ce qui rend les suppressions fiables. Le
rapport affiche aussi le **delta** (nouveaux / résolus) vis-à-vis de la baseline.
