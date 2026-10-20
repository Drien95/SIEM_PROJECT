# Suricata (IDS/IPS réseau)

Sources : PDF `Suricata_integration` (marxgoo), https://docs.suricata.io/,
ruleset Wazuh 4.14 `0475-suricata_rules.xml`.

## IDS ou IPS

- **IDS** : inspecte le trafic (signatures, IoC, scripts Lua), alerte sans bloquer.
  Mode par défaut de Suricata.
- **IPS** : bloque ou laisse passer en ligne. Sous Windows, il nécessite WinDivert.

## Installation sur Windows (lab marxgoo)

1. Installer **Npcap** (https://npcap.com) en cochant le mode compatible WinPcap, puis
   vérifier : `Get-Service -Name npcap` doit être `Running`.
2. Installer le MSI Suricata (https://suricata.io/download/) dans `C:\Program Files\Suricata\`.
   On y trouve `suricata.exe`, `suricata.yaml`, `rules\` et `log\`.

## Configuration

Dans `suricata.yaml` :

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json

rule-files:
  - local.rules
  - emerging-all.rules     # règles Emerging Threats, à placer dans rules\
```

Le PDF configure la capture dans une section `af-packet`. AF_PACKET est un mécanisme Linux.
Sous Windows, Suricata capture via **Npcap/libpcap**, et c'est l'option `-i` qui choisit
l'interface. À valider dans notre lab.

Lancement (PowerShell administrateur) :

```powershell
Get-NetAdapter | Select-Object Name, Status
cd "C:\Program Files\Suricata\"
.\suricata.exe -c suricata.yaml -i <IP_ou_nom_de_l_interface>
```

Journaux dans `log\` : `eve.json` (JSON complet), `fast.log` (une ligne par alerte),
`stats.log`.

Option recommandée, à valider : installer Suricata sur une **VM Linux** ou sur **pfSense**
(paquet), en coupure ou en écoute du trafic du LAN du lab. C'est plus proche d'un déploiement
réel qu'un IDS sur le poste.

## Ingestion dans Wazuh

Dans `ossec.conf` de l'agent :

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\Program Files\Suricata\log\eve.json</location>
</localfile>
```

Puis `Restart-Service -Name WazuhSvc`. Le PDF écrit `-Name wazuh`, ce qui est faux.

Wazuh décode nativement le JSON de Suricata :

| Règle | Niveau | Événement |
|---|---|---|
| 86600 | 0 | Tout message Suricata |
| **86601** | **3** | `event_type: alert` : *Suricata: Alert - <signature>* |
| 86602 / 86603 / 86604 | 0 | http / dns / tls |

Les alertes sortent au niveau 3, donc il faut une règle locale pour élever les signatures
graves (voir [configs/manager/local_rules.xml](../../configs/manager/local_rules.xml)).

## Test

Le PDF propose `ping google.com`. Un ping ne correspond à aucune signature courante. Mieux :

- une règle de test dans `rules\local.rules` (voir
  [configs/suricata/local.rules](../../configs/suricata/local.rules)) ;
- un scan `nmap -sS` depuis Kali vers l'endpoint.

Recherche : `rule.groups:suricata`.
