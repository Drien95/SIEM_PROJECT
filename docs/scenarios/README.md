# Scénarios d'attaque

Chaque scénario se joue **uniquement** contre les machines du lab, sur des réseaux host-only.
Une fiche par scénario, construite sur le [modèle](modele-scenario.md) : objectif, topologie,
prérequis, attaque, détection attendue contre observée, lecture SOC, remédiation, et un tableau
« Résultats dans notre lab ».

## Joués et validés

| # | Fiche | MITRE ATT&CK | Témoin | Règles observées | Writeup |
|---|---|---|---|---|---|
| 1 | [Brute force SMB sur Windows 11](brute-force-smb.md) | T1110, T1110.001, T1078 | agent Windows (journal Security) | 60122, 60204, réponse active `block-ip-win`, 100400 | [06](../writeup/06-scenario-brute-force-smb.md), [07](../writeup/07-regles-et-reponse-active.md) |
| 2 | [Scan de ports nmap](scan-nmap.md) | T1046 | pfSense (`filterlog`, syslog) | 100302, 100303 | [08](../writeup/08-scenario-scan-nmap.md) |
| 3 | [Fichier malveillant : FIM + VirusTotal](malware-fim-virustotal.md) | T1203 (natif), T1105 | agent Windows (FIM) + API VirusTotal | 554, 87105 | [09](../writeup/09-scenario-fim-virustotal.md) |
| 4 | [Scan vu par un IDS : Suricata sur pfSense](suricata-nids.md) | T1046 | Suricata (EVE JSON en syslog) | 86601, 100210 | [10](../writeup/10-scenario-suricata-nids.md) |
| 5b | [Persistance par clé Run](persistance-run-key.md) | T1547.001 | agent Windows (Sysmon EID 13) | 92300 (niv. 0), 100230 | [11](../writeup/11-scenario-persistance-run-key.md) |
| 6 | [Mouvement latéral SMB](mouvement-lateral-smb.md) | T1021.002 | agent Windows (Security 4624, 5140) | 92657, 60104, 67017, 100240 | [16](../writeup/16-scenario-mouvement-lateral-smb.md) |

## Préparés, pas encore joués

| Fiche | MITRE ATT&CK | Détection attendue |
|---|---|---|
| [Brute force SSH / RDP](brute-force.md) | T1110 | 5710-5712 et 5551 (Linux), 60122 et 60204 (Windows) |

Les scénarios suivants (suppression automatique, tâche planifiée, SCA, vulnérabilités) sont planifiés dans la
[roadmap](../roadmap.md) ; la couverture par technique est dans [mitre.md](../mitre.md).
