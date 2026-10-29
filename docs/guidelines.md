# Guidelines d'usage

## Périmètre et autorisation
- Usage **défensif** uniquement : code et systèmes possédés ou explicitement
  autorisés.
- Les scans actifs (DAST) exigent un `scope.json` attesté ; hors périmètre =
  rejet avant tout trafic. Voir [DAST et autorisation](dast-et-autorisation.md).

## Revue humaine des correctifs
- Les remédiations sont des **diffs** à relire. N'appliquez qu'après lecture
  (`fix --apply --yes`) ; vérifiez ensuite avec `git diff` avant de committer.
- Ne faites jamais confiance aveuglément à un diff généré : il est traité comme
  une proposition, pas une vérité.

## Gestion des secrets trouvés
- Un secret détecté doit être considéré comme **compromis** : révoquez/rotez-le,
  purgez-le de l'historique si nécessaire, puis ajoutez une suppression de
  baseline **datée** seulement si le finding est un faux positif avéré.
- Ne committez jamais de vrais secrets dans les fixtures ou la config.

## Reproductibilité
- Préférez un `.sec-scan.json` versionné pour aligner postes et CI.
- Épinglez les versions d'outils (`scripts/verify-tools.sh`) ; régénérez la
  baseline lors d'une montée de version d'outil.

## Contribution
- `npm run build` puis `npm test` (et `npm run test:coverage`) doivent passer.
- Chaque PR passe par la CI (gate `build-test`) sur une branche ; `master` est
  protégé. Mettez à jour `CHANGELOG.md` et la doc avec tout changement de CLI.
