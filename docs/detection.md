# Détection

## Capacités natives Wazuh

Documentation : https://documentation.wazuh.com/current/user-manual/capabilities/index.html

| Capacité | Usage dans le lab |
|---|---|
| File Integrity Monitoring (FIM) | Créations, modifications, suppressions dans des dossiers sensibles |
| Collecte de journaux | Event Log Windows, Sysmon, syslog, journaux applicatifs |
| Détection de malware | Avec Windows Defender et VirusTotal |
| Security Configuration Assessment (SCA) | Durcissement des endpoints (benchmarks CIS) |
| Détection de vulnérabilités | Inventaire logiciel croisé avec le flux CTI Wazuh |
| Réponse active | Blocage automatique (ex. IP en brute force) |
| Surveillance de commandes, appels système, conteneurs, inventaire, sans agent | À explorer plus tard |

## Intégrations

Un guide par intégration, avec les erreurs des sources corrigées :

| Intégration | Guide | Règles natives Wazuh 4.14 |
|---|---|---|
| Journaux Windows + Sysmon | [integrations/windows-logs-sysmon.md](integrations/windows-logs-sysmon.md) | 60000+ (Windows), 61603 (Sysmon EID 1), 92000+ |
| File Integrity Monitoring | [integrations/fim.md](integrations/fim.md) | groupe `syscheck` |
| VirusTotal | [integrations/virustotal.md](integrations/virustotal.md) | 87100-87106 (87105 = détecté, niveau 12) |
| Suricata | [integrations/suricata.md](integrations/suricata.md) | 86600-86604 (86601 = alerte, niveau 3) |
| pfSense | [integrations/pfsense.md](integrations/pfsense.md) | 87700-87702 (87702 = blocages répétés, niveau 10) |
| Windows Defender | à écrire (source : UsmanPrime, test EICAR) | `0600-win-wdefender_rules.xml` |

Configurations prêtes à adapter : [`configs/`](../configs/) (règles locales du manager,
syslog, VirusTotal, `localfile` de l'agent Windows, règles Suricata).

Tester une règle avant déploiement : `sudo /var/ossec/bin/wazuh-logtest`, puis
`sudo systemctl restart wazuh-manager`.

## Scénarios de test

Chaque scénario se joue **uniquement** contre des machines du lab. Résultat attendu à
consigner (alerte, `rule.id`, niveau, capture).

| # | Scénario | Outil | Détection attendue | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | [Brute force SSH / RDP](scenarios/brute-force.md) | Hydra depuis Kali | Linux sshd : règles 5551, 5712 ; Windows RDP : 60122, 60204 (Event ID 4625) ; réponse active | T1110 (déduit) |
| 1 bis | [Brute force SMB sur Windows 11](scenarios/brute-force-smb.md) — **joué le 2026-10-22** | `nxc smb` depuis Kali (10.10.20.10) | Observé : 60122 ×10 (niv. 5), 60204 ×1 (niv. 10), 92652 au succès (niv. 6) | T1110, T1110.001 (déduit) |
| 2 | Modification de fichiers surveillés | Manuel | Alertes FIM (niveaux 5 et 7 selon UsmanPrime) | T1565 (déduit) |
| 3 | Fichier malveillant de test | EICAR | Alerte Defender et/ou VirusTotal | T1204 (déduit) |
| 4 | Exécution de processus | `powershell.exe` | Règle personnalisée Sysmon niveau 8 | T1059.001 |
| 5 | Trafic réseau suspect | Scan nmap depuis Kali | Alerte Suricata / pfSense | T1046 (déduit) |

« Déduit » : correspondance MITRE établie par nous, absente des sources.

Scénario 1 : IDs de règles et requêtes repris du guide de preuve de concept officiel
(`proof-of-concept-guide/detect-brute-force-attack.html`). Recherche dans *Threat Hunting* :
`rule.id:(5551 OR 5712)` pour Linux, `rule.id:(60122 OR 60204)` pour Windows.
