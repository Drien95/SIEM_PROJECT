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

Puis `Restart-Service -Name WazuhSvc`. Le service s'appelle `WazuhSvc`, son nom affiché est
`Wazuh` : `NET START Wazuh` fonctionne aussi (constaté dans notre lab, writeup 04).
Alternative retenue dans le lab : la configuration centralisée du groupe `default`
([configs/manager/shared/default/agent.conf](../../configs/manager/shared/default/agent.conf)).

Wazuh décode déjà Sysmon : pas besoin de décodeur personnalisé. La règle de base de
l'événement 1 est **61603**, de niveau 0. Les événements de routine n'apparaissent donc pas
comme alertes. C'est ce qu'observe UsmanPrime. Le ruleset ajoute des détections ciblées (92000
et suivantes, groupe `sysmon_eid1_detections`).

Pour faire remonter une exécution précise, on écrit une règle locale enfant de 61603 :
[configs/manager/local_rules.xml](../../configs/manager/local_rules.xml).

Vérification dans *Threat Hunting* : `data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"`.

## Configuration Sysmon du lab (depuis le 2026-10-25)

La configuration SwiftOnSecurity du writeup 04 a été **remplacée** par une configuration ciblée,
[`configs/agent-windows/sysmon-lab.xml`](../../configs/agent-windows/sysmon-lab.xml), appliquée
avec `Sysmon64.exe -c C:\sysmon-lab.xml`. `-c` remplace toute la configuration en place : il n'y
a pas de fusion.

| Bloc | Effet |
|---|---|
| `ProcessAccess onmatch="include"` sur `lsass.exe` | événement 10 limité aux accès à LSASS |
| `ProcessCreate onmatch="exclude"` vide | événement 1 pour **tous** les processus (rien n'est exclu) : la règle 100101 (PowerShell encodé) continue de fonctionner (déduit de la sémantique `exclude`) |
| `RegistryEvent onmatch="include"` sur `\CurrentVersion\Run` | événements 12 à 14 limités aux clés Run ([scénario 5b](../scenarios/persistance-run-key.md)) |

Conséquence : les autres événements que journalisait SwiftOnSecurity (réseau, fichiers, DNS…)
ne sont plus produits. À réévaluer avant les prochains scénarios.

## Règles natives et locales par événement Sysmon (ruleset v4.14.0, vérifié)

| Événement | Règle de base | Détections natives | Règles locales du lab |
|---|---|---|---|
| 1 (création de processus) | 61603 (niveau 0) | `0800-sysmon_id_1.xml` (92000+) | 100101 (PowerShell encodé, niveau 12) ; 100100 supprimée le 2026-10-29 ([writeup 20](../writeup/20-scenario-powershell-encode.md)) |
| 10 (accès à un processus) | 61612 (niveau 0) | `0945-sysmon_id_10.xml` : 92900 (niveau 12), 92910, 92920 | 100220 (niveau 12) |
| 13 (valeur de registre écrite) | 61615 (niveau 0) | `0860-sysmon_id_13.xml` : **92300** (clé Run, niveau 0), 92301-92303 | 100230 (niveau 12, enfant de 92300) |

Leçon du scénario 5b : une règle native de niveau 0 peut intercepter un événement en silence.
Avant d'écrire une règle locale, chercher les natives qui partagent le même parent ou le même
groupe, et s'accrocher **sous** elles (`if_sid`).

