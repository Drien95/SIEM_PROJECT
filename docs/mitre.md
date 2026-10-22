# Couverture MITRE ATT&CK

Ce document liste les techniques ATT&CK que le lab sait détecter, la règle Wazuh qui les voit et
la preuve. Il est tenu à jour à chaque scénario (voir la [roadmap](roadmap.md)).

![Couverture MITRE ATT&CK par tactique](diagrams/mitre-couverture.png)

*Source : [`mitre-couverture.html`](diagrams/mitre-couverture.html).*

## Techniques détectées (scénario joué)

| Tactique | Technique | Règle Wazuh | Niveau | Source de journaux | Preuve |
|---|---|---|---|---|---|
| Accès aux identifiants (TA0006) | **T1110** Brute Force | 60204 (native), puis réponse active `block-ip-win` | 10 | journal Security de Windows, agent | [scénario 1](scenarios/brute-force-smb.md), [writeup 07](writeup/07-regles-et-reponse-active.md) |
| Accès aux identifiants (TA0006) | **T1110.001** Password Guessing (déduit) | 60122 (native), une par essai | 5 | idem | [scénario 1](scenarios/brute-force-smb.md) |
| Accès initial (TA0001) | **T1078** Valid Accounts (déduit) | **100400** (locale) « succès après rafale » ; 92652 (native) | 12 ; 6 | idem | [writeup 07, § 1.4](writeup/07-regles-et-reponse-active.md) |
| Découverte (TA0007) | **T1046** Network Service Discovery | 100302 → **100303** (locales) | 5 → 10 | `filterlog` de pfSense, syslog | [scénario 2](scenarios/scan-nmap.md) |

## Règle en place, pas encore dans un scénario d'attaque

| Tactique | Technique | Règle | Preuve |
|---|---|---|---|
| Exécution (TA0002) | **T1059.001** PowerShell | 100100 (locale, Sysmon EID 1) | 9 alertes sur de l'activité normale ([writeup 04](writeup/04-agent-windows-sysmon.md)) |

## Prévu

| Tactique | Technique | Moyen de détection | Scénario |
|---|---|---|---|
| Exécution (TA0002) | T1204.002 Malicious File (déduit) | FIM + VirusTotal (EICAR) | 3 |
| Commande et contrôle (TA0011) | T1105 Ingress Tool Transfer (déduit) | FIM + VirusTotal | 3 |
| Commande et contrôle (TA0011) | T1071 Application Layer Protocol (déduit) | Suricata | 4 |
| Accès aux identifiants (TA0006) | T1003.001 LSASS Memory | Sysmon EID 10 | 5 |
| Persistance (TA0003) | T1547.001 Run Keys | Sysmon EID 13 | 5 |
| Persistance (TA0003) | T1053.005 Scheduled Task | Sysmon, événement 4698 | 5 |

## Étiquettes MITRE à ne pas reprendre telles quelles

| Règle | MITRE du ruleset | Problème | Ce qu'on retient |
|---|---|---|---|
| 60122 (native) | T1531 Account Access Removal (Impact) | un échec de connexion ne supprime aucun accès | T1110 / T1110.001 |
| 87702 (native pfSense) | T1110 Brute Force | des blocages répétés signalent surtout un scan | T1046 (notre 100303) |

Sources : https://attack.mitre.org/ (matrice Enterprise),
https://github.com/wazuh/wazuh/tree/v4.14.0/ruleset/rules (étiquettes des règles natives).
« Déduit » : correspondance établie par nous, absente des sources.
