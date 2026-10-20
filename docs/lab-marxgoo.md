# Notes de lecture — PDF de marxgoo/Wazuh-SOC-Lab

Source : https://github.com/marxgoo/Wazuh-SOC-Lab, dossier `docs/` (auteure : Bensekhar
Maria Golsaf, septembre 2025). Lu le 2026-10-20.

Les 8 PDF sont téléchargés localement dans `references/marxgoo-Wazuh-SOC-Lab/`, **hors git** :
le dépôt d'origine n'a pas de licence, on ne les redistribue pas.

`Soc_Home_LAB.pdf` compile les 7 autres ; seule sa partie « architecture » est nouvelle.

## Architecture du lab

- Hyperviseur VMware, VM Wazuh en **OVA**, réseau **NAT**.
- Windows 11 Pro (agent + Sysmon + Suricata), Kali (attaquant), pfSense.
- pfSense : WAN `em0` en NAT (DHCP), LAN `em1` en host-only, `192.168.1.1/24` ;
  20 Go disque, 1-2 Go RAM, 1-2 vCPU. Exemple d'IP du serveur Wazuh : `192.168.200.50`.
- Aucune version de Wazuh n'est indiquée.

## Ce qu'on retient, par PDF

| PDF | Points utiles |
|---|---|
| Wazuh_configuration | Import OVA ; identifiants par défaut de l'OVA `admin`/`admin` (à changer) ; si « server not ready », vérifier puis démarrer `wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard` ; agent Windows via *Endpoints > Deploy new agent*, commandes PowerShell en admin. |
| Logs&Sysmon_ingestion | Journaux `.evtx` dans `C:\Windows\System32\Winevt\Logs` ; Event IDs utiles ; Sysmon : `sysmon.exe -i -accepteula` puis `sysmon -c sysmonconfig.xml` (config SwiftOnSecurity) ; bloc `<localfile>` canal `Microsoft-Windows-Sysmon/Operational`, format `eventchannel`. |
| File_integrity_monitoring | `<directories check_all="yes" report_changes="yes" realtime="yes">` ; test créer / modifier / supprimer un fichier → 3 types d'alertes. |
| VirusTotal_integration | Bloc `<integration>` virustotal + FIM temps réel sur un dossier de dépôt ; rappel : tout fichier envoyé à VirusTotal devient public. |
| Suricata_integration | Install MSI (`C:\Program Files\Suricata\`) + **Npcap** (mode compatible WinPcap) ; règles `emerging-all.rules` ; sortie `eve.json` ; agent : `<localfile>` `log_format` `json` sur `eve.json` ; filtre *Threat Hunting* sur Suricata. |
| Pfsense_integration | *Status > System Logs > Settings* : remote logging vers Wazuh port 514 ; bloc `<remote>` syslog UDP 514 avec `allowed-ips` sur le manager ; décodeur `filterlog` + règles 100111-100115 (niveaux 3 / 5 / 7 / 10). |
| SSH_Brute_Force | Cible Windows avec **OpenSSH Server** activé ; `hydra -l <user> -P passwords.txt ssh://<ip>` ; alerte Event ID 4625, `logonType 8`, `processName ...\OpenSSH\sshd.exe`, `subStatus 0xc0000064`, niveau 5 ; contre-mesures : MFA, verrouillage, rate-limiting. |

## Erreurs repérées dans les PDF (à ne pas reproduire)

| PDF | Ce qui est écrit | Correction | Vérifié |
|---|---|---|---|
| VirusTotal | Le bloc `<integration>` se met dans `C:\Program Files (x86)\ossec-agent\ossec.conf` puis `net stop wazuhsvc` | Il va sur le **manager** dans `/var/ossec/etc/ossec.conf`, avec `<group>syscheck</group>`, puis `systemctl restart wazuh-manager` | doc officielle |
| VirusTotal | Dossier surveillé `/home/virustotaltest` sur un agent Windows | Chemin Windows (ex. `C:\Users\Public\vt-test`) ou agent Linux | évident |
| VirusTotal | Pas de mention des quotas | API publique : 4 requêtes/min, 500/jour, usage non commercial | doc officielle |
| FIM | Config agent Windows dans `/var/ossec/etc/ossec.conf`, restart `systemctl restart wazuh-agent` | Windows : `C:\Program Files (x86)\ossec-agent\ossec.conf`, `Restart-Service WazuhSvc` | doc / UsmanPrime |
| FIM | `recursion_level` 2 = « tous les sous-dossiers » | Profondeur 2 seulement ; c'est un attribut de `<directories>` | à valider |
| Suricata | `Restart-Service -Name wazuh` | Le service s'appelle `WazuhSvc` | UsmanPrime |
| Suricata | Section `af-packet` dans `suricata.yaml` sous Windows | `af-packet` est propre à Linux ; sous Windows c'est la capture `pcap` (via Npcap) | à valider |
| Suricata | `ping google.com` pour générer une alerte | Un ping ne déclenche en général aucune signature ; préférer une règle de test dans `local.rules` ou un scan nmap | à valider |
| pfSense | Fichier `/var/ossec/etc/ossec.cfg` | `/var/ossec/etc/ossec.conf` | doc officielle |
| pfSense | Règles `<match>pass</match>` / `block` | Correspondance sur une sous-chaîne de tout le log : faux positifs possibles ; mieux vaut décoder le champ action | déduit |
| Logs | 4741 = « compte utilisateur modifié » | 4741 = compte **ordinateur** créé ; compte utilisateur modifié = 4738 | doc Microsoft (connu) |
| Logs | Sysmon : `net start wazuh` | `Restart-Service WazuhSvc` | UsmanPrime |

## Event IDs Windows retenus

| ID | Signification |
|---|---|
| 4624 / 4625 | Ouverture de session réussie / échouée |
| 4720 / 4726 / 4738 | Compte utilisateur créé / supprimé / modifié |
| 4688 | Création de processus |
| 4104 | Bloc de script PowerShell journalisé (canal PowerShell Operational) |
| 1102 | Journal de sécurité effacé |
| Sysmon 1 | Création de processus (plus riche que 4688 : ligne de commande, hash, parent) |
