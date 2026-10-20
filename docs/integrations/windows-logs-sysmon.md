# Journaux Windows et Sysmon

Sources : PDF `Logs&Sysmon_ingestion` (marxgoo), UsmanPrime/Wazuh-Setup, ruleset Wazuh 4.14
(`0595-win-sysmon_rules.xml`, `0800-sysmon_id_1.xml`).

## Journaux Windows

- Fichiers `.evtx` dans `C:\Windows\System32\Winevt\Logs`.
- Consultation : `eventvwr.msc`, ou PowerShell en administrateur (obligatoire pour le
  journal Security) :

```powershell
Get-WinEvent -LogName Security -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20
```

Catégories : System, Application, Security, Setup, Forwarded Events. Niveaux :
Information, Warning, Error, Critical, Audit Success / Failure.

L'agent Wazuh lit par défaut les canaux Application, Security et System
(`log_format` `eventchannel`).

## Event IDs à connaître

| ID | Canal | Signification |
|---|---|---|
| 4624 / 4625 | Security | Ouverture de session réussie / échouée |
| 4720 / 4726 / 4738 | Security | Compte utilisateur créé / supprimé / modifié |
| 4688 | Security | Création de processus (audit à activer par GPO) |
| 1102 | Security | Journal de sécurité effacé |
| 4104 | PowerShell/Operational | Bloc de script PowerShell journalisé (Script Block Logging à activer) |

Le PDF indique 4741 pour « compte utilisateur modifié » : c'est faux, 4741 = compte
**ordinateur** créé.

## Sysmon

Installation (binaire de Microsoft Sysinternals), PowerShell administrateur :

```powershell
.\Sysmon64.exe -i -accepteula                 # installation
.\Sysmon64.exe -c sysmonconfig.xml            # appliquer une configuration
```

Configuration de départ : celle de SwiftOnSecurity (`sysmonconfig-export.xml`), citée
par les deux sources. Sans configuration, Sysmon journalise peu ; avec une configuration trop
large, il inonde le SIEM.

Événements dans *Observateur d'événements > Journaux des applications et des services >
Microsoft > Windows > Sysmon > Operational*.

| Sysmon ID | Événement |
|---|---|
| 1 | Création de processus (ligne de commande, hash, parent) |
| 3 | Connexion réseau |
| 7 | Chargement d'image (DLL) |
| 8 | CreateRemoteThread |
| 10 | Accès à un processus (ex. dump de LSASS) |
| 11 | Création de fichier |
| 13 | Modification de registre |

## Ingestion dans Wazuh

Dans `C:\Program Files (x86)\ossec-agent\ossec.conf` (voir
[configs/agent-windows/ossec-localfiles.xml](../../configs/agent-windows/ossec-localfiles.xml)) :

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Puis `Restart-Service -Name WazuhSvc` (le PDF écrit `net start wazuh` : le service
s'appelle `WazuhSvc`).

Wazuh décode déjà Sysmon : pas besoin de décodeur personnalisé. La règle de base de
l'événement 1 est **61603**, de niveau 0. Les événements de routine n'apparaissent donc pas
comme alertes. C'est ce qu'observe UsmanPrime. Le ruleset ajoute des détections ciblées (92000
et suivantes, groupe `sysmon_eid1_detections`).

Pour faire remonter une exécution précise, on écrit une règle locale enfant de 61603 :
[configs/manager/local_rules.xml](../../configs/manager/local_rules.xml).

Vérification dans *Threat Hunting* : `data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"`.
