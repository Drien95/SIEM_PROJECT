# Roadmap : un parcours d'analyste SOC sur Wazuh

Ce lab sert à **évaluer Wazuh** et, en le faisant, à pratiquer le métier d'analyste SOC. La
roadmap est organisée en trois phases :

1. **Largeur** : un mini-scénario par capacité de Wazuh.
2. **Profondeur** : le travail quotidien d'un SOC sur ces détections.
3. **Livrable** : le rapport d'évaluation et la présentation du projet.

Chaque ligne renvoie au document qui la prouve.

Statuts : ✅ fait · 🔄 en partie · ⏳ pas commencé. Mis à jour le 2026-10-29.

**Où en est le projet** : phases 0 et 1 terminées, phase 2 faite sur l'essentiel (detection
engineering, tuning, MITRE, triage, dashboard), phase 3 livrée (rapport d'évaluation, pages de
synthèse). Ce qui reste est listé en fin de page, assumé comme suite et pas comme oubli.

## Phase 0 : socle du lab ✅

| Étape | Compétence SOC visée | Statut | Preuve |
|---|---|---|---|
| Homelab VMware : pfSense, Wazuh 4.14.9 (OVA), Windows 11 | comprendre une architecture de supervision | ✅ | [writeup 01](writeup/01-homelab.md), [architecture](architecture.md) |
| Journaux pfSense en syslog, décodeur et règles locales | intégrer une source de journaux réseau | ✅ | [writeup 02](writeup/02-syslog-pfsense.md) |
| SSH par clé, mot de passe interdit | durcir les outils de l'analyste | ✅ | [writeup 03](writeup/03-durcissement-ssh.md) |
| Agent Windows et Sysmon en configuration centralisée | déployer et superviser un agent EDR/XDR | ✅ | [writeup 04](writeup/04-agent-windows-sysmon.md) |
| Réseau d'attaque séparé (VMnet11) derrière pfSense | segmenter, matrice de flux au moindre privilège | ✅ | [writeup 05](writeup/05-segment-attaque-kali.md), [matrice des flux](diagrams/flux-lab.png) |

## Phase 1 : largeur, une capacité Wazuh = un scénario ✅

| # | Scénario et capacité | MITRE ATT&CK | Compétence SOC visée | Statut | Preuve |
|---|---|---|---|---|---|
| 1 | Brute force SMB sur Windows 11 : journaux Windows, corrélation 60204, **réponse active** (blocage 180 s), règle locale **100400** « succès après rafale » | T1110, T1110.001, T1078 | lire un 4625, distinguer tentative et compromission, automatiser une réponse | ✅ | [fiche](scenarios/brute-force-smb.md), [writeup 06](writeup/06-scenario-brute-force-smb.md), [writeup 07](writeup/07-regles-et-reponse-active.md) |
| 2 | Scan nmap à travers pfSense : journaux du pare-feu, corrélation 100303 | T1046 | détecter la reconnaissance, connaître les angles morts d'une règle | ✅ | [fiche](scenarios/scan-nmap.md), [writeup 08](writeup/08-scenario-scan-nmap.md) |
| 3 | **FIM + VirusTotal** : dépôt du fichier de test EICAR, alerte FIM 554 puis VirusTotal 87105 (niveau 12, 66 moteurs) en ~6 s | T1203 (étiquette native), T1105 et T1204.002 (déduits) | traiter une alerte malware, enrichir avec une réputation externe | ✅ | [fiche](scenarios/malware-fim-virustotal.md), [writeup 09](writeup/09-scenario-fim-virustotal.md) |
| 4 | **Suricata** (IDS) sur l'interface ATTACK de pfSense, ET Open : scan vers Windows 11 (destination autorisée), 86601 → règle locale **100210** (niveau 10) ; corrections `HOME_NET` et décodeur `json` pour l'en-tête RFC 5424 | T1046 | lire une alerte IDS, couvrir l'angle mort du scénario 2, déboguer une ingestion | ✅ | [fiche](scenarios/suricata-nids.md), [writeup 10](writeup/10-scenario-suricata-nids.md), [intégration](integrations/suricata.md) |
| 5 | **Sysmon, accès aux identifiants et persistance** : accès à LSASS joué et validé en live le 2026-10-25 (Sysmon EID 10, règle locale **100220** niveau 12) ; persistance par **clé Run** jouée et validée le 2026-10-25 (native 92300 niveau 0, élevée par la règle locale **100230** niveau 12) ; tâche planifiée jouée le 2026-10-29 (ligne 10) | T1003.001, T1547.001 | détecter sur la télémétrie d'un endpoint, écrire des règles enfants Sysmon | ✅ (récit du writeup 15 à rédiger) | [Windows et Sysmon](integrations/windows-logs-sysmon.md), [`sysmon-lab.xml`](../configs/agent-windows/sysmon-lab.xml), [`local_rules.xml`](../configs/manager/local_rules.xml), [fiche clé Run](scenarios/persistance-run-key.md), [writeup 11](writeup/11-scenario-persistance-run-key.md), [writeup 15](writeup/15-detection-acces-identifiants-lsass.md) (LSASS, en cours, à rédiger par l'auteur) |
| 6 | **SCA** (Security Configuration Assessment), CIS Microsoft Windows 11 Enterprise v3.0.0 : score 24 % (115/358/9 sur 482 après correction de 26003), boucle de durcissement prouvée sur le check 26003 | (posture, pas une technique) | mesurer et suivre une conformité, relier un réglage à PCI DSS, ISO 27001, SOC 2 | ✅ | [writeup 12](writeup/12-sca-cis-windows11.md), [intégration SCA](integrations/sca.md), [scripts de remédiation](../scripts/hardening/README.md), [writeup 13](writeup/13-durcissement-cis-automatise.md) (familles 01-03 appliquées et vérifiées le 2026-10-25, rollback de 02 validé le 2026-10-28) |
| 7 | **Vulnerability Detection** : CVE des paquets installés ; flux incrémental en échec sur 4.14.9, contourné hors ligne (base de 10 Go chargée), mais Inventory vide : limite du module constatée, diagnostic documenté | (posture, pas une technique) | diagnostiquer un module maillon par maillon, évaluer un outil | ✅ (limitation documentée) | [writeup 14](writeup/14-vulnerability-detection.md) |
| 8 | **Mouvement latéral SMB** depuis Kali vers les partages d'administration : refus par le filtrage UAC à distance, 92657 / 60104 / 67017 natives, règle locale **100240** (niveau 12) | T1021.002 | prolonger une chaîne d'attaque, critiquer les libellés et exclusions des règles natives | ✅ | [fiche](scenarios/mouvement-lateral-smb.md), [writeup 16](writeup/16-scenario-mouvement-lateral-smb.md) |
| 9 | **Effacement du journal Security** : événement 1102, native 63103 (niveau 5), règle locale **100250** (niveau 12) | T1070.001 | couvrir la tactique Defense Evasion | ✅ | [writeup 17](writeup/17-scenario-effacement-journaux.md) (à rédiger par l'auteur), [`local_rules.xml`](../configs/manager/local_rules.xml) |
| 10 | **Suppression des clichés instantanés** (`vssadmin delete shadows`) : aucune native, règle locale **100260** (12) | T1490 | combler un trou du ruleset natif | ✅ | [writeup 19](writeup/19-scenario-suppression-cliches.md) |
| 11 | **PowerShell encodé** : règle locale **100101** (12) ; 100100 supprimée car elle masquait des natives | T1059.001, T1027 | comprendre l'ordre d'évaluation des règles | ✅ | [writeup 20](writeup/20-scenario-powershell-encode.md) |
| 12 | **Tâche planifiée en SYSTEM** : **100270**, **100271** (12) | T1053.005 | deux capteurs pour une technique (Sysmon, 4698) | ✅ | [writeup 21](writeup/21-scenario-tache-planifiee-system.md) |
| 13 | **Archive puis exfiltration HTTP** : **100280**, **100281**, corrélation **100282** (14) | T1560.001, T1048.003 | écrire une corrélation | ✅ | [writeup 22](writeup/22-scenario-collection-exfiltration.md) |
| 14 | **Scan de vulnérabilités** : signature Suricata maison, **100211** (10) | T1595.002 | écrire une signature IDS, déboguer une ingestion syslog | ✅ | [writeup 23](writeup/23-scenario-reconnaissance-vuln-scan.md) |
| 15 | **Téléchargement par certutil** bloqué par Defender : canal Defender collecté, **100290** (12) | T1105 | repérer un angle mort de collecte | ✅ | [writeup 24](writeup/24-scenario-telechargement-certutil.md) |

La règle locale **100100** (tout lancement de PowerShell, [writeup 04](writeup/04-agent-windows-sysmon.md)) a été
supprimée le 2026-10-29 : elle masquait des règles natives. Remplacée par **100101** (PowerShell encodé,
[writeup 20](writeup/20-scenario-powershell-encode.md)).

## Phase 2 : profondeur, le travail d'un SOC

| Étape | Ce qu'on fait | Compétence SOC visée | Statut |
|---|---|---|---|
| Detection engineering | règles enfants (`if_sid`), corrélations (`frequency`, `same_field`), validation en live ; 26 règles locales | écrire, tester et maintenir des détections | ✅ ([règles](https://github.com/Drien95/SIEM_PROJECT/blob/main/configs/manager/local_rules.xml), corrélations [100282](writeup/22-scenario-collection-exfiltration.md) et [100273](writeup/26-du-triage-au-tuning.md)) |
| Réduction des faux positifs | listes blanches construites sur la cause : 100231 (Edge), 100120 (svchost, 93 alertes/jour), 100221 (outils LSASS) | régler un SIEM, justifier chaque exception | ✅ ([writeups 18](writeup/18-tuning-faux-positifs.md), [25](writeup/25-dashboard-couverture-mitre.md), [26](writeup/26-du-triage-au-tuning.md)) ; validation de 100221 en attente |
| Cartographie MITRE ATT&CK | règle → technique → tactique, trous par tactique | raisonner en techniques, pas en outils | ✅ 13 tactiques sur 14, 17 techniques ([MITRE](mitre.md)) |
| Triage | deux alertes réelles qualifiées à l'aveugle : chronologie, qui / quoi / où, verdict, actions proposées, manques transformés en règles | qualifier une alerte, écrire un ticket | ✅ ([tickets](triage/README.md)) ; confinement et éradication proposés, non exécutés |
| Dashboards et métriques | dashboard « Couverture MITRE » (4 visualisations) ; mesure du délai de détection (MTTD) | mesurer l'efficacité d'un SOC | 🔄 dashboard fait ([writeup 25](writeup/25-dashboard-couverture-mitre.md)), MTTD non mesuré |
| Fiabilité des mesures de conformité | faux « Failed » du SCA sur Windows en français | ne pas croire un score sans vérifier | 🔄 constat documenté ([writeup 13](writeup/13-durcissement-cis-automatise.md)), politique SCA corrigée non écrite |
| Threat hunting | chercher sans alerte : hypothèse, requête, conclusion | chasser à partir d'une hypothèse | ⏳ |

## Phase 3 : livrable

| Étape | Contenu | Statut |
|---|---|---|
| Rapport d'évaluation de Wazuh | grille, forces, limites, ce que le lab ne prouve pas, recommandation | ✅ [rapport](evaluation-wazuh.md) |
| Lectures par profil | conformité (PCI DSS v4, SOC 2, CIS) et data (volumes, faux positifs) | ✅ [conformité](conformite.md), [data](analyse-alertes.md) |
| Présentation du projet | synthèse d'une minute (README, accueil), site, portfolio | 🔄 récits des writeups 15 et 17 à rédiger, vidéo de démonstration en préparation |

## Ce qui reste

- **Récits** des writeups 15 (LSASS) et 17 (effacement des journaux), à rédiger par l'auteur.
- **Threat hunting** : une chasse sur hypothèse, sans alerte de départ.
- **MTTD** : mesurer le délai entre l'action et l'alerte sur quelques scénarios.
- **Manques relevés au triage** : preuve réseau de l'exfiltration (journal pfSense des flux
  autorisés), PowerShell Script Block Logging (4104).
- **Étiquetage conformité** des règles locales (PCI DSS v4, SOC 2), voir [conformité](conformite.md).
- En option : suppression automatique du fichier EICAR par réponse active sur 87105, ingestion
  Suricata par rsyslog ([option B](integrations/suricata.md#option-b--rsyslog-et-fichier-json-à-valider)).
