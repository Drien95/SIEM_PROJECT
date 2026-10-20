# pfSense (pare-feu)

Sources : PDF `Pfsense_integration` (marxgoo), ruleset Wazuh 4.14
(`0455-pfsense_decoders.xml`, `0540-pfsense_rules.xml`),
https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html

## VM pfSense

| Paramètre | Valeur (lab marxgoo) |
|---|---|
| Disque | 20 Go minimum |
| RAM / CPU | 1 Go (2 conseillés) / 1 vCPU (2 conseillés) |
| Carte 1 — WAN (`em0`) | NAT, DHCP |
| Carte 2 — LAN (`em1`) | Host-only, `192.168.1.1/24` |

Interface web : `https://192.168.1.1` depuis une VM du LAN. Identifiants par défaut
`admin` / `pfsense`, à **changer immédiatement**.

## Envoi des journaux vers Wazuh

**pfSense** : *Status > System Logs > Settings > Remote Logging*. Cocher *Enable Remote
Logging*, indiquer `<IP_WAZUH>:514` et choisir les catégories (Firewall, System, DHCP, DNS,
VPN…).

**Manager Wazuh**, dans `/var/ossec/etc/ossec.conf` (le PDF écrit `ossec.cfg`, ce qui est
faux). Voir
[configs/manager/ossec-remote-syslog.xml](../../configs/manager/ossec-remote-syslog.xml) :

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.1</allowed-ips>
</remote>
```

`allowed-ips` est obligatoire : sans lui, le manager refuse le syslog. Ensuite,
`sudo systemctl restart wazuh-manager` et ouvrir 514/UDP sur la VM Wazuh.

## Décodage : utiliser le natif d'abord

Le PDF crée un décodeur `pfsense-custom` sur `filterlog` et des règles 100111 à 100115.
Or **Wazuh 4.14 décode déjà pfSense** :

- décodeur `pf` sur `program_name` `filterlog`, qui extrait `id`, `action`, `protocol`,
  `srcip`, `dstip`, `srcport` et `dstport` ;
- règle 87700 (niveau 0, groupe), 87701 (`action` = `block`, niveau 5, `no_log`), et
  **87702** (niveau 10 : 18 blocages de la même IP en 45 s, MITRE T1110).

Conséquences, déduites de la lecture du ruleset et **à valider** avec `wazuh-logtest` :

- Le décodeur natif `pf` matche avant le décodeur du PDF, donc les règles `decoded_as
  pfsense-custom` ne se déclencheraient jamais.
- Les règles du PDF utilisent `<match>pass</match>` / `block` sur tout le message. Une
  sous-chaîne comme « pass » peut apparaître ailleurs. Le champ décodé `<action>` est fiable.
- « Successful login » et « authentication error » ne viennent pas de `filterlog` (ce sont
  les journaux de l'interface web et de sshd). Des règles enfants du groupe filterlog ne
  peuvent donc pas les voir.

Notre approche : des règles locales **enfants de 87700**, sur le champ `action`. Voir
[configs/manager/local_rules.xml](../../configs/manager/local_rules.xml).

## Test

1. Depuis Kali (LAN) : `nmap -sS <IP_WAN_ou_hôte_bloqué>` pour déclencher des blocages en
   série. Attendu : 87702.
2. `sudo /var/ossec/bin/wazuh-logtest`, puis coller une ligne `filterlog` d'exemple pour
   vérifier le décodage.

Recherche : `rule.groups:pfsense`.
