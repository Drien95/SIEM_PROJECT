# Writeup 17 : effacement du journal Security (T1070.001)

> **Statut : EN COURS, à rédiger par l'auteur.** Squelette de structure uniquement : chaque
> section indique la preuve à citer.

## 1. Contexte (MITRE T1070.001, Defense Evasion)

*Preuve : fiche MITRE ATT&CK https://attack.mitre.org/techniques/T1070/001/*

## 2. Télémétrie

*Preuve : audit Windows activé (famille 03, [writeup 13](13-durcissement-cis-automatise.md)) ; canal Security collecté par l'agent*

## 3. Test joué

*Preuve : commande lancée sur la VM et événement 1102 observé (2026-10-28 21:27)*

## 4. Détection native (règle 63103, niveau 5)

*Preuve : alerte 63103 dans `alerts.json` ; ruleset v4.14.0, `0610-win-ms_logs_rules.xml`*

## 5. Règle locale (100250, niveau 12)

*Preuve : [`local_rules.xml`](../../configs/manager/local_rules.xml), commit `f81d568` ; alerte 100250 du 2026-10-28 21:27:32*

## 6. Valeur du SIEM

*Preuve : alertes antérieures (100240, 4624, 5140) toujours présentes dans `alerts.json` du manager après l'effacement local*

## 7. Conclusion et lien SOC

*À rédiger.*
