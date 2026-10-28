---
title: Accueil
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Évaluer un SIEM en conditions réelles

<p class="tagline">Un laboratoire SOC isolé autour de Wazuh 4.14 : déployer, collecter, détecter, puis prouver chaque détection en rejouant des techniques MITRE ATT&CK.</p>

</div>

J'ai construit un laboratoire pour **évaluer le SIEM/XDR open source Wazuh** du point de vue
d'un analyste SOC. Chaque scénario est relié à MITRE ATT&CK, documenté en « attendu contre
observé », et complété par une règle sur mesure quand la règle native ne suffisait pas. Les
attaques sont jouées uniquement contre les machines du lab, sur des réseaux isolés.

<div class="kpis" markdown>
<div><strong>9</strong><span>techniques ATT&CK détectées en live</span></div>
<div><strong>7 / 14</strong><span>tactiques couvertes</span></div>
<div><strong>13</strong><span>règles locales écrites</span></div>
<div><strong>18</strong><span>writeups</span></div>
</div>

![Couverture MITRE ATT&CK du lab](diagrams/mitre-couverture.png)

## Parcourir le projet

<div class="grid cards" markdown>

-   :material-lan:{ .lg .middle } **Le lab**

    ---

    pfSense, Wazuh 4.14.9, Windows 11 avec Sysmon, Kali sur un réseau séparé.

    [:octicons-arrow-right-24: Architecture](architecture.md) ·
    [Construction](writeup/01-homelab.md)

-   :material-target:{ .lg .middle } **Scénarios de détection**

    ---

    Sept scénarios, du brute force à l'effacement des journaux, chacun prouvé en live.

    [:octicons-arrow-right-24: Vue d'ensemble](scenarios/README.md)

-   :material-shield-check:{ .lg .middle } **Posture et tuning**

    ---

    SCA CIS, durcissement automatisé avec rollback, Vulnerability Detection, faux positifs.

    [:octicons-arrow-right-24: SCA et CIS](writeup/12-sca-cis-windows11.md) ·
    [Tuning](writeup/18-tuning-faux-positifs.md)

-   :material-grid:{ .lg .middle } **MITRE ATT&CK**

    ---

    Règle → technique → tactique, et les trous qui restent.

    [:octicons-arrow-right-24: Couverture](mitre.md)

</div>

## Le lab en un schéma

![Topologie du lab](diagrams/topologie-lab.png)

| Élément | Rôle | Adresse |
|---|---|---|
| pfSense CE 2.9.0 | pare-feu entre réseaux, journaux `filterlog`, IDS Suricata | `10.10.10.254` / `10.10.20.254` |
| Wazuh 4.14.9 (OVA) | manager, indexer, dashboard | `10.10.10.100` |
| Windows 11 (français) | poste supervisé : agent Wazuh, Sysmon v15.22, audit renforcé | `10.10.10.101` |
| Kali Linux | attaquant, sur un réseau séparé | `10.10.20.10` |

Le chemin d'un événement, du poste au dashboard :

![Pipeline Wazuh](diagrams/pipeline-wazuh.png)

## Scénarios joués

| # | Technique | Tactique | Source | Détection (niveau) | Writeup |
|---|---|---|---|---|---|
| 1 | <span class="badge">T1110</span> <span class="badge">T1110.001</span> <span class="badge">T1078</span> Brute force, compte valide | Credential Access, Initial Access | journal Security | 60122 (5) → 60204 (10) + réponse active → **100400** (12) | [06](writeup/06-scenario-brute-force-smb.md), [07](writeup/07-regles-et-reponse-active.md) |
| 2 | <span class="badge">T1046</span> Scan de ports | Discovery | `filterlog` pfSense | 100302 (5) → **100303** (10) | [08](writeup/08-scenario-scan-nmap.md) |
| 3 | <span class="badge">T1105</span> Fichier malveillant déposé (déduit, simulé) | Command and Control | FIM + VirusTotal | 554 (5) → 87105 (12) | [09](writeup/09-scenario-fim-virustotal.md) |
| 4 | <span class="badge">T1046</span> Scan vu par l'IDS | Discovery | Suricata sur pfSense | 86601 (3) → **100210** (10) | [10](writeup/10-scenario-suricata-nids.md) |
| 5 | <span class="badge">T1003.001</span> Accès à LSASS | Credential Access | Sysmon EID 10 | 61612 (0) → **100220** (12) | [15](writeup/15-detection-acces-identifiants-lsass.md) (en cours) |
| 5b | <span class="badge">T1547.001</span> Persistance par clé Run | Persistence | Sysmon EID 13 | 92300 (0) → **100230** (12), liste blanche 100231 | [11](writeup/11-scenario-persistance-run-key.md) |
| 6 | <span class="badge">T1021.002</span> Mouvement latéral SMB | Lateral Movement | journal Security (4624, 5140) | 67017 (3) → **100240** (12) | [16](writeup/16-scenario-mouvement-lateral-smb.md) |
| 7 | <span class="badge">T1070.001</span> Effacement du journal Security | Defense Evasion | journal Security (1102) | 63103 (5) → **100250** (12) | [17](writeup/17-scenario-effacement-journaux.md) (en cours) |

Trous restants : <span class="badge gap">Reconnaissance</span> <span class="badge gap">Privilege Escalation</span>
<span class="badge gap">Collection</span> <span class="badge gap">Exfiltration</span> <span class="badge gap">Impact</span>
(détail dans [MITRE ATT&CK](mitre.md)).

## Règles locales écrites pour le lab

Plage 100000-120000, chacune enfant d'une règle native (`if_sid`) plutôt qu'une redéfinition.
Source : [`configs/manager/local_rules.xml`](https://github.com/Drien95/SIEM_PROJECT/blob/main/configs/manager/local_rules.xml).

| Règle | Niveau | Détecte |
|---|---|---|
| 100100 | 8 | exécution de PowerShell vue par Sysmon (T1059.001) |
| 100200 | 10 | alerte Suricata de sévérité 1 |
| 100210 | 10 | scan réseau signalé par Suricata (ET SCAN, T1046) |
| 100220 | 12 | accès au processus LSASS vu par Sysmon (T1003.001) |
| 100230 | 12 | écriture dans une clé Run (T1547.001) |
| 100231 | 0 | liste blanche de 100230 : auto-démarrage de Microsoft Edge |
| 100240 | 12 | accès à un partage SMB depuis le segment d'attaque (T1021.002) |
| 100250 | 12 | effacement du journal Security (T1070.001) |
| 100300 | 0 | journaux `filterlog` de pfSense (base) |
| 100301 | 3 | pfSense : trafic autorisé |
| 100302 | 5 | pfSense : paquet bloqué |
| 100303 | 10 | pfSense : blocages répétés depuis une source (scan, T1046) |
| 100400 | 12 | connexion réussie juste après une rafale d'échecs (T1110, T1078) |

## Ce que le projet a appris

!!! tip "Constats qui font la valeur du lab"

    - Le **filtrage de jeton UAC à distance** refuse `C$` même à un administrateur local :
      un contrôle anti-mouvement-latéral actif par défaut ([writeup 16](writeup/16-scenario-mouvement-lateral-smb.md)).
    - Le **SCA signale à tort** des réglages d'audit conformes sur un Windows en français
      ([writeup 13](writeup/13-durcissement-cis-automatise.md)).
    - `wazuh-logtest` **ne reproduit pas** le décodage des événements Windows : valider en live
      ([writeup 18](writeup/18-tuning-faux-positifs.md)).
    - Les **libellés natifs** sont des hypothèses : « possible RDP » sur une connexion SMB,
      T1531 sur un échec de connexion ([MITRE](mitre.md)).
    - **Vulnerability Detection 4.14.9** : flux chargé, aucun résultat ; savoir qu'un module est
      instable est un résultat d'évaluation ([writeup 14](writeup/14-vulnerability-detection.md)).

Bilan complet, limites et compétences : [Constats, limites et compétences](portfolio/README.md).

## Le réseau, paquet par paquet

Un simulateur maison rejoue les échanges du lab (ARP, DHCP, syslog, enrôlement de l'agent…) avec
les en-têtes de chaque paquet.

<div class="grid" markdown>

![Enrôlement de l'agent Wazuh](diagrams/videos/agent.gif)

![Syslog de pfSense vers Wazuh](diagrams/videos/syslog.gif)

</div>

[:octicons-arrow-right-24: Tous les scénarios du simulateur](writeup/annexe-simulateur-paquets.md)
