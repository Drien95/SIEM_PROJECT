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

## Intégrations vues dans les labs de référence

| Intégration | Principe | Source |
|---|---|---|
| **Sysmon** | Télémétrie Windows détaillée ; canal `Microsoft-Windows-Sysmon/Operational` lu par l'agent | les deux |
| **Windows Defender** | Canal Defender lu par l'agent ; test EICAR → alerte de sévérité élevée | UsmanPrime |
| **VirusTotal** | Clé API dans `ossec.conf` du manager ; analyse des fichiers signalés par FIM | marxgoo |
| **Suricata** | IDS/IPS sur Windows (Npcap), alertes envoyées à Wazuh | marxgoo |
| **pfSense** | Syslog vers Wazuh + décodeurs et règles personnalisés (autorisé, bloqué, authentification) | marxgoo |

Clé API VirusTotal : **jamais dans git**. Bloc à placer sur le **manager**
(`/var/ossec/etc/ossec.conf`), puis `systemctl restart wazuh-manager` :

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

API publique : 4 requêtes/min, 500/jour. Détails et erreurs à éviter : [lab-marxgoo.md](lab-marxgoo.md).

## Exemples de configuration (à valider)

FIM temps réel sur un dossier de test, dans `ossec.conf` de l'agent :

```xml
<syscheck>
  <directories realtime="yes" check_all="yes">C:\Users\Public\fim-test</directories>
</syscheck>
```

Lecture de Sysmon, dans `ossec.conf` de l'agent Windows :

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Règle personnalisée, dans `/var/ossec/etc/rules/local_rules.xml` du manager
(idée reprise d'UsmanPrime : élever Sysmon ID 1 au niveau 8). Le `if_sid` exact dépend
des règles Sysmon livrées avec la version installée : **à vérifier** dans le ruleset.

```xml
<group name="sysmon,custom,">
  <!-- Création de processus PowerShell (Sysmon EID 1) — MITRE T1059.001 -->
  <rule id="100100" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <description>Sysmon : exécution de PowerShell sur $(win.system.computer)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
```

Tester une règle avant déploiement : `sudo /var/ossec/bin/wazuh-logtest`, puis
`sudo systemctl restart wazuh-manager`.

## Scénarios de test

Chaque scénario se joue **uniquement** contre des machines du lab. Résultat attendu à
consigner (alerte, `rule.id`, niveau, capture).

| # | Scénario | Outil | Détection attendue | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | Brute force SSH / RDP | Hydra depuis Kali | Linux sshd : règles 5551, 5712 ; Windows RDP : 60122, 60204 (Event ID 4625) ; réponse active | T1110 (déduit) |
| 2 | Modification de fichiers surveillés | Manuel | Alertes FIM (niveaux 5 et 7 selon UsmanPrime) | T1565 (déduit) |
| 3 | Fichier malveillant de test | EICAR | Alerte Defender et/ou VirusTotal | T1204 (déduit) |
| 4 | Exécution de processus | `powershell.exe` | Règle personnalisée Sysmon niveau 8 | T1059.001 |
| 5 | Trafic réseau suspect | Scan nmap depuis Kali | Alerte Suricata / pfSense | T1046 (déduit) |

« Déduit » : correspondance MITRE établie par nous, absente des sources.

Scénario 1 : IDs de règles et requêtes repris du guide de preuve de concept officiel
(`proof-of-concept-guide/detect-brute-force-attack.html`). Recherche dans *Threat Hunting* :
`rule.id:(5551 OR 5712)` pour Linux, `rule.id:(60122 OR 60204)` pour Windows.
