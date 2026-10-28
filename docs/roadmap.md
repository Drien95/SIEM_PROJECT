# Roadmap : un parcours d'analyste SOC sur Wazuh

Ce lab sert à **évaluer Wazuh** et, en le faisant, à pratiquer le métier d'analyste SOC. La
roadmap est organisée en trois phases :

1. **Largeur** : un mini-scénario par capacité de Wazuh.
2. **Profondeur** : le travail quotidien d'un SOC sur ces détections.
3. **Livrable** : le rapport d'évaluation et la présentation du projet.

Chaque ligne renvoie au document qui la prouve.

Statuts : ✅ fait · 🔄 en cours · ⏳ à venir. Mis à jour le 2026-10-25.

## Phase 0 : socle du lab ✅

| Étape | Compétence SOC visée | Statut | Preuve |
|---|---|---|---|
| Homelab VMware : pfSense, Wazuh 4.14.9 (OVA), Windows 11 | comprendre une architecture de supervision | ✅ | [writeup 01](writeup/01-homelab.md), [architecture](architecture.md) |
| Journaux pfSense en syslog, décodeur et règles locales | intégrer une source de journaux réseau | ✅ | [writeup 02](writeup/02-syslog-pfsense.md) |
| SSH par clé, mot de passe interdit | durcir les outils de l'analyste | ✅ | [writeup 03](writeup/03-durcissement-ssh.md) |
| Agent Windows et Sysmon en configuration centralisée | déployer et superviser un agent EDR/XDR | ✅ | [writeup 04](writeup/04-agent-windows-sysmon.md) |
| Réseau d'attaque séparé (VMnet11) derrière pfSense | segmenter, matrice de flux au moindre privilège | ✅ | [writeup 05](writeup/05-segment-attaque-kali.md), [matrice des flux](diagrams/flux-lab.png) |

## Phase 1 : largeur, une capacité Wazuh = un scénario

| # | Scénario et capacité | MITRE ATT&CK | Compétence SOC visée | Statut | Preuve |
|---|---|---|---|---|---|
| 1 | Brute force SMB sur Windows 11 : journaux Windows, corrélation 60204, **réponse active** (blocage 180 s), règle locale **100400** « succès après rafale » | T1110, T1110.001, T1078 | lire un 4625, distinguer tentative et compromission, automatiser une réponse | ✅ | [fiche](scenarios/brute-force-smb.md), [writeup 06](writeup/06-scenario-brute-force-smb.md), [writeup 07](writeup/07-regles-et-reponse-active.md) |
| 2 | Scan nmap à travers pfSense : journaux du pare-feu, corrélation 100303 | T1046 | détecter la reconnaissance, connaître les angles morts d'une règle | ✅ | [fiche](scenarios/scan-nmap.md), [writeup 08](writeup/08-scenario-scan-nmap.md) |
| 3 | **FIM + VirusTotal** : dépôt du fichier de test EICAR, alerte FIM 554 puis VirusTotal 87105 (niveau 12, 66 moteurs) en ~6 s | T1203 (étiquette native), T1105 et T1204.002 (déduits) | traiter une alerte malware, enrichir avec une réputation externe | ✅ | [fiche](scenarios/malware-fim-virustotal.md), [writeup 09](writeup/09-scenario-fim-virustotal.md) |
| 3 bis | Réponse active de **suppression du fichier** sur 87105 (Windows, modèle `block-ip-win`) | — | remédiation automatique d'un malware | ⏳ | [fiche, § 8](scenarios/malware-fim-virustotal.md) |
| 4 | **Suricata** (IDS) sur l'interface ATTACK de pfSense, ET Open : scan vers Windows 11 (destination autorisée), 86601 → règle locale **100210** (niveau 10) ; corrections `HOME_NET` et décodeur `json` pour l'en-tête RFC 5424 | T1046 | lire une alerte IDS, couvrir l'angle mort du scénario 2, déboguer une ingestion | ✅ | [fiche](scenarios/suricata-nids.md), [writeup 10](writeup/10-scenario-suricata-nids.md), [intégration](integrations/suricata.md) |
| 5 | **Sysmon, accès aux identifiants et persistance** : accès à LSASS joué et validé en live le 2026-10-25 (Sysmon EID 10, règle locale **100220** niveau 12) ; persistance par **clé Run** jouée et validée le 2026-10-25 (native 92300 niveau 0, élevée par la règle locale **100230** niveau 12) ; tâche planifiée à venir | T1003.001, T1547.001, T1053.005 | détecter sur la télémétrie d'un endpoint, écrire des règles enfants Sysmon | 🔄 | [Windows et Sysmon](integrations/windows-logs-sysmon.md), [`sysmon-lab.xml`](../configs/agent-windows/sysmon-lab.xml), [`local_rules.xml`](../configs/manager/local_rules.xml), [fiche clé Run](scenarios/persistance-run-key.md), [writeup 11](writeup/11-scenario-persistance-run-key.md), [writeup 15](writeup/15-detection-acces-identifiants-lsass.md) (LSASS, en cours, à rédiger par l'auteur) |
| 6 | **SCA** (Security Configuration Assessment), CIS Microsoft Windows 11 Enterprise v3.0.0 : score 24 % (115/358/9 sur 482 après correction de 26003), boucle de durcissement prouvée sur le check 26003 | (posture, pas une technique) | mesurer et suivre une conformité, relier un réglage à PCI DSS, ISO 27001, SOC 2 | ✅ | [writeup 12](writeup/12-sca-cis-windows11.md), [intégration SCA](integrations/sca.md), [scripts de remédiation](../scripts/hardening/README.md), [writeup 13](writeup/13-durcissement-cis-automatise.md) (familles 01-03 appliquées et vérifiées le 2026-10-25, rollback de 02 validé le 2026-10-28) |
| 7 | **Vulnerability Detection** : CVE des paquets installés ; flux incrémental en échec sur 4.14.9, contourné hors ligne (base de 10 Go chargée), mais Inventory vide : limite du module constatée, diagnostic documenté | (posture, pas une technique) | diagnostiquer un module maillon par maillon, évaluer un outil | ✅ (limitation documentée) | [writeup 14](writeup/14-vulnerability-detection.md) |
| 8 | **Mouvement latéral SMB** depuis Kali vers les partages d'administration : refus par le filtrage UAC à distance, 92657 / 60104 / 67017 natives, règle locale **100240** (niveau 12) | T1021.002 | prolonger une chaîne d'attaque, critiquer les libellés et exclusions des règles natives | ✅ | [fiche](scenarios/mouvement-lateral-smb.md), [writeup 16](writeup/16-scenario-mouvement-lateral-smb.md) |
| 9 | **Effacement du journal Security** : événement 1102, native 63103 (niveau 5), règle locale **100250** (niveau 12) | T1070.001 | couvrir la tactique Defense Evasion | ✅ | [writeup 17](writeup/17-scenario-effacement-journaux.md) (à rédiger par l'auteur), [`local_rules.xml`](../configs/manager/local_rules.xml) |

Déjà en place hors scénario d'attaque : la règle locale **100100** (exécution de PowerShell
vue par Sysmon, T1059.001), validée sur de l'activité normale ([writeup 04](writeup/04-agent-windows-sysmon.md)).

## Phase 2 : profondeur, le travail d'un SOC

| Étape | Ce qu'on fait | Compétence SOC visée | Statut |
|---|---|---|---|
| Detection engineering | règles enfants (`if_sid`), corrélations (`if_matched_sid`, `same_field`), tests `wazuh-logtest` puis en live ; corriger les étiquettes MITRE fausses (60122 porte T1531) | écrire, tester et maintenir des détections | 🔄 (100100, 100210, 100220, 100230, 100231, 100240, 100250, 100300-100303, 100400 faites ; décodeur `json` restreint pour Suricata) |
| Réduction des faux positifs | mesurer le bruit (ANONYMOUS LOGON, 60106, Sysmon de bas niveau, `RunNotification` sur 100230, `IPC$` sur 100240), ajuster niveaux et exceptions sans perdre les vraies attaques | régler un SIEM, justifier chaque exception | 🔄 (cas documentés : [writeup 11](writeup/11-scenario-persistance-run-key.md) ; liste blanche 100231 validée, [writeup 18](writeup/18-tuning-faux-positifs.md)) |
| Fiabilité des mesures de conformité | faux « Failed » du SCA sur Windows en français (checks auditpol 26139-26165) ; politique SCA maison par GUID | ne pas croire un score sans vérifier la réalité technique | 🔄 (constat : [writeup 13](writeup/13-durcissement-cis-automatise.md)) |
| Cartographie MITRE ATT&CK | tenir la [couverture](mitre.md) à jour, repérer les trous par tactique | raisonner en techniques, pas en outils | 🔄 (cartographie faite le 2026-10-28 : 7 tactiques couvertes sur 14) |
| Triage et réponse à incident de bout en bout | dérouler un incident complet : alerte, qualification, périmètre, confinement, éradication, rapport | suivre un playbook, écrire un compte rendu d'incident | ⏳ |
| Threat hunting | chercher sans alerte : hypothèse, requête dans Threat Hunting, conclusion, éventuellement nouvelle règle | chasser à partir d'une hypothèse | ⏳ |
| Dashboards et métriques | tableau de bord par scénario, mesure du délai de détection (**MTTD**) et de réponse (MTTR) | mesurer l'efficacité d'un SOC | ⏳ |

## Phase 3 : livrable

| Étape | Contenu | Statut |
|---|---|---|
| Rapport d'évaluation de Wazuh | ce que Wazuh détecte bien, mal ou pas du tout dans ce lab, coût de mise en œuvre, limites (FIPS de l'OVA, champs Windows sans `srcip`, règles natives à corriger), recommandation | ⏳ |
| Présentation du projet | README soigné, schémas, writeups réutilisables pour un site portfolio | 🔄 (squelette : [portfolio](portfolio/README.md)) |

## Prochaine étape

Phase 2 sur nos règles locales : tuning avec `wazuh-logtest` (`IPC\$` sur 100240,
`RunNotification` sur 100230, `wazuh-agent.exe` sur 100220). Toujours prévus : tâche planifiée
(T1053.005) et writeup LSASS (rédigé par l'auteur). Reste
ouvert : le scénario 3 bis (suppression automatique du fichier EICAR sur 87105) et, en option,
l'ingestion Suricata « production » par rsyslog ([option B](integrations/suricata.md#option-b--rsyslog-et-fichier-json-à-valider)).
