# Writeup 15 : détection d'un accès aux identifiants (LSASS)

> **Statut : EN COURS, à rédiger par l'auteur.** Squelette de structure uniquement : chaque
> section indique la preuve à citer.

## 1. Contexte (MITRE T1003.001)

*Preuve : lien vers la fiche MITRE ATT&CK https://attack.mitre.org/techniques/T1003/001/*

## 2. Télémétrie mise en place (Sysmon v15.22 sur SIEM-Win11, intégration agent Wazuh)

*Preuve : configuration Sysmon [`sysmon-lab.xml`](../../configs/agent-windows/sysmon-lab.xml), commit `3ce6db9`*

## 3. Observation (champs clés de l'événement dans le dashboard)

*Preuve : capture d'alerte ; `archives.json` (logall) si besoin*

## 4. Règle de détection (règle locale 100220, niveau 12)

*Preuve : extrait de [`local_rules.xml`](../../configs/manager/local_rules.xml), commit `3ce6db9`*

## 5. Faux positif (cas `wazuh-agent.exe`)

*Preuve : observation en lab*

## 6. Mitigation (protection LSA / PPL active par défaut)

*Preuve : événement System 12 Wininit « niveau : 4 » ; [writeup 13, § 3.1](13-durcissement-cis-automatise.md#31-au-passage--la-protection-lsa-était-déjà-là)*

## 7. Conclusion et lien SOC

*À rédiger.*
