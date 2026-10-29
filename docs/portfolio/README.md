# Évaluer un SIEM en conditions réelles : un lab SOC autour de Wazuh

> **Squelette de portfolio (2026-10-28).** Structure et faits déjà établis dans le dépôt ; les
> emplacements `[À COMPLÉTER]` attendent les captures et le récit de l'auteur.

![Couverture MITRE ATT&CK du lab](../diagrams/mitre-couverture.png)

## 1. Le projet en trois phrases

J'ai construit un laboratoire isolé pour **évaluer le SIEM/XDR open source Wazuh 4.14.9** du
point de vue d'un analyste SOC : déployer, collecter, détecter, puis **prouver** chaque détection
en rejouant des techniques d'attaque contre mes propres machines. Chaque scénario est relié à
MITRE ATT&CK, documenté (attendu contre observé) et, quand la règle native ne suffisait pas,
complété par une règle sur mesure. Le résultat : 16 techniques détectées en live sur 13 tactiques,
une remédiation CIS outillée, et une liste de constats sur ce que Wazuh fait bien, mal ou pas.

`[À COMPLÉTER : une phrase personnelle sur la motivation, l'objectif de carrière]`

## 2. Le lab

| Élément | Rôle | Adresse |
|---|---|---|
| pfSense CE 2.9.0 | pare-feu entre réseaux, journaux `filterlog`, IDS Suricata | `10.10.10.254` / `10.10.20.254` |
| Wazuh 4.14.9 (OVA) | manager, indexer, dashboard | `10.10.10.100` |
| Windows 11 (français) | poste supervisé : agent Wazuh, Sysmon v15.22, audit renforcé | `10.10.10.101` |
| Kali Linux | attaquant, sur un réseau séparé | `10.10.20.10` |

![Topologie du lab](../diagrams/topologie-lab.png)

- Architecture et démons Wazuh : [architecture.md](../architecture.md),
  [pipeline](../diagrams/pipeline-wazuh.png), [démons](../diagrams/demons-wazuh.png),
  [carte des capacités](../diagrams/carte-wazuh.png).
- Réseau et matrice de flux : [flux](../diagrams/flux-lab.png), [writeup 05](../writeup/05-segment-attaque-kali.md).
- Installation : [installation.md](../installation.md), [writeup 01](../writeup/01-homelab.md).

## 3. Scénarios joués et détections

| # | Technique MITRE | Tactique | Capteur / source | Détection (niveau) | Writeup | Statut |
|---|---|---|---|---|---|---|
| 1 | T1110 Brute Force, T1110.001 Password Guessing, T1078 Valid Accounts | Credential Access, Initial Access | journal Security Windows (4625, 4624) | 60122 (5) → 60204 (10) + réponse active (IP bloquée 180 s) → **100400** (12) | [06](../writeup/06-scenario-brute-force-smb.md), [07](../writeup/07-regles-et-reponse-active.md) | ✅ live |
| 2 | T1046 Network Service Discovery | Discovery | `filterlog` pfSense (syslog) | 100302 (5) → **100303** (10) | [08](../writeup/08-scenario-scan-nmap.md) | ✅ live |
| 3 | T1105 Ingress Tool Transfer (déduit, simulé) | Command and Control | FIM de l'agent + VirusTotal | 554 (5) → 87105 (12) | [09](../writeup/09-scenario-fim-virustotal.md) | ✅ live |
| 4 | T1046 Network Service Discovery | Discovery | Suricata sur pfSense (EVE JSON) | 86601 (3) → **100210** (10) | [10](../writeup/10-scenario-suricata-nids.md) | ✅ live |
| 5 | T1003.001 LSASS Memory | Credential Access | Sysmon EID 10 | 61612 (0) → **100220** (12) | [15](../writeup/15-detection-acces-identifiants-lsass.md) | ✅ live, récit `[À COMPLÉTER]` |
| 5b | T1547.001 Registry Run Keys | Persistence | Sysmon EID 13 | 92300 (0) → **100230** (12), liste blanche **100231** | [11](../writeup/11-scenario-persistance-run-key.md), [18](../writeup/18-tuning-faux-positifs.md) | ✅ live |
| 6 | T1021.002 SMB/Windows Admin Shares | Lateral Movement | journal Security (4624, 5140) | 92657 (6), 60104 (5), 67017 (3) → **100240** (12) | [16](../writeup/16-scenario-mouvement-lateral-smb.md) | ✅ live |
| 7 | T1070.001 Clear Windows Event Logs | Defense Evasion | journal Security (1102) | 63103 (5) → **100250** (12) | [17](../writeup/17-scenario-effacement-journaux.md) | ✅ live, récit `[À COMPLÉTER]` |

Hors ATT&CK (posture) : SCA / CIS Windows 11 ([writeup 12](../writeup/12-sca-cis-windows11.md)),
durcissement automatisé ([writeup 13](../writeup/13-durcissement-cis-automatise.md)),
Vulnerability Detection ([writeup 14](../writeup/14-vulnerability-detection.md)).
Couverture détaillée et trous : [mitre.md](../mitre.md).

`[À COMPLÉTER : une capture d'alerte représentative par scénario]`

## 4. Règles locales écrites pour le lab

Toutes dans [`configs/manager/local_rules.xml`](../../configs/manager/local_rules.xml), plage
100000-120000, chacune enfant d'une règle native (`if_sid`) plutôt qu'une redéfinition.

| Règle | Niveau | Détecte |
|---|---|---|
| 100101 | 12 | PowerShell à commande encodée en Base64 (T1059.001, T1027) ; remplace 100100, supprimée car elle masquait des natives |
| 100200 | 10 | alerte Suricata de sévérité 1 |
| 100210 | 10 | scan réseau signalé par Suricata (signatures ET SCAN, T1046) |
| 100220 | 12 | accès au processus LSASS vu par Sysmon (T1003.001) |
| 100230 | 12 | écriture dans une clé Run (T1547.001) |
| 100231 | 0 | liste blanche de 100230 : auto-démarrage de Microsoft Edge |
| 100240 | 12 | accès à un partage SMB depuis le segment d'attaque (T1021.002) |
| 100250 | 12 | effacement du journal Security (T1070.001) |
| 100300-100303 | 0 à 10 | journaux `filterlog` de pfSense : autorisé, bloqué, blocages répétés (scan, T1046) |
| 100400 | 12 | connexion réussie juste après une rafale d'échecs : brute force abouti (T1110, T1078) |

Plus un décodeur local pour l'en-tête RFC 5424 de Suricata sur pfSense
([`local_decoder.xml`](../../configs/manager/local_decoder.xml)).

## 5. Constats et apprentissages

Ce qui fait la valeur du projet : ce que les outils ne disent pas d'eux-mêmes.

| Constat | Pourquoi c'est important | Source |
|---|---|---|
| Le **filtrage de jeton UAC à distance** refuse `C$` même à un administrateur local | contrôle anti-mouvement-latéral actif par défaut ; ne protège pas les comptes de domaine | [writeup 16](../writeup/16-scenario-mouvement-lateral-smb.md) |
| Le **SCA signale à tort** des réglages d'audit conformes sur un Windows en français | un score de conformité est une mesure, pas la vérité ; corriger l'instrument | [writeup 13](../writeup/13-durcissement-cis-automatise.md) |
| `wazuh-logtest` **ne reproduit pas** le décodage des événements Windows (EventChannel) | valider les règles Windows en live | [writeup 18](../writeup/18-tuning-faux-positifs.md) |
| Un test avec `reg.exe` crée des **événements que l'acteur réel ne produit pas** | une méthode de test peut fabriquer son propre bruit | [writeup 18](../writeup/18-tuning-faux-positifs.md) |
| **Vulnerability Detection 4.14.9** : flux chargé, aucun résultat | savoir qu'un module est instable est un résultat d'évaluation | [writeup 14](../writeup/14-vulnerability-detection.md) |
| **Libellés et étiquettes natifs imprécis** (« possible RDP » sur du SMB, T1531 sur un échec de connexion, T1203 sur tout fichier VirusTotal) | lire les champs, pas le titre | [mitre.md](../mitre.md) |
| Règles natives **muettes** : sœurs évaluées d'abord (92300, 60117), exclusion `IPC$` inopérante dans 67017 | comprendre l'arbre des règles avant d'écrire la sienne | [writeups 11](../writeup/11-scenario-persistance-run-key.md), [16](../writeup/16-scenario-mouvement-lateral-smb.md) |
| Effacer le journal local **n'efface pas** ce que le SIEM a déjà reçu | raison d'être d'une collecte centralisée | [writeup 17](../writeup/17-scenario-effacement-journaux.md) |

## 6. Limites et suite

- **Vulnerability Detection** : aucun résultat exploitable dans cette version ; cause non établie.
- **Tuning** à poursuivre : `RunNotification` sur 100230, `IPC$` sur 100240, `wazuh-agent.exe`
  sur 100220 ; règle sur les refus d'accès aux partages d'administration.
- **Trous MITRE** : Reconnaissance, Privilege Escalation, Collection, Exfiltration, Impact ;
  Execution seulement partielle.
- **Échelle** : un seul poste Windows, hors domaine ; pas d'Active Directory.
- Phase 2 restante : triage et réponse à incident de bout en bout, threat hunting, tableaux de
  bord et MTTD ([roadmap](../roadmap.md)).

## 7. Compétences démontrées

| Domaine | Preuves |
|---|---|
| Déploiement et architecture d'un SIEM | OVA Wazuh, agent Windows, syslog pfSense, Suricata ; [architecture](../architecture.md) |
| Segmentation réseau | réseau d'attaque séparé, règles pfSense au moindre privilège ([writeup 05](../writeup/05-segment-attaque-kali.md)) |
| Detection engineering | 13 règles et un décodeur locaux, corrélations (`if_matched_sid`, `frequency`), réponse active |
| Tuning des faux positifs | liste blanche validée, diagnostic des règles muettes ([writeup 18](../writeup/18-tuning-faux-positifs.md)) |
| Cartographie MITRE ATT&CK | règle → technique → tactique, trous identifiés ([mitre.md](../mitre.md)) |
| Conformité et durcissement | SCA CIS, scripts PowerShell avec dry-run, garde-fou et rollback ([scripts](../../scripts/hardening/README.md)) |
| Méthode et documentation | « attendu contre observé », vérifié contre supposé, sources citées, 18 writeups |

`[À COMPLÉTER : liens vers le site portfolio, CV, contact]`
