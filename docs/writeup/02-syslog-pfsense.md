# Writeup 02 : envoyer les journaux de pfSense vers Wazuh

> Deuxième étape du lab : le pare-feu pfSense envoie ses journaux (syslog) au manager Wazuh,
> qui les décode et lève des alertes. Document vivant : la partie « Résultats » se remplit au
> fil des tests.
>
> Version : Wazuh 4.14.9, pfSense CE 2.9.0. Prérequis : [writeup 01](01-homelab.md).

## 1. Comprendre

### 1.1 Le chemin d'un événement dans Wazuh

```
 Source            Collecte              Analyse (manager)                  Stockage / vue
┌────────┐  syslog  ┌──────────────┐  ┌─────────┐  ┌────────┐  ┌───────┐  ┌──────────┐  ┌──────────┐
│pfSense │ ───────▶ │ wazuh-remoted│─▶│décodeur │─▶│ règles │─▶│alerte │─▶│ Filebeat │─▶│ Indexer  │─▶ Dashboard
└────────┘ UDP 514  │   (manager)  │  │(champs) │  │(niveau)│  │(JSON) │  │          │  │(OpenSearch)
┌────────┐  agent   │              │  └─────────┘  └────────┘  └───────┘  └──────────┘  └──────────┘
│Windows │ ───────▶ │ TCP 1514     │
└────────┘          └──────────────┘
```

1. **Collecte.** Deux façons de faire entrer un journal dans Wazuh :
   - par un **agent** installé sur la machine (Windows, Linux) : il lit les journaux
     localement et les envoie chiffrés au manager sur TCP 1514 ;
   - en **syslog** (*agentless*) : l'équipement envoie lui-même ses journaux. C'est le cas
     des pare-feu, routeurs et switchs, où l'on ne peut pas installer d'agent.
2. **Décodage.** Un journal brut n'est qu'une ligne de texte. Le **décodeur** la découpe en
   champs nommés : `srcip`, `dstip`, `dstport`, `action`… Sans ces champs, on ne peut ni
   filtrer ni corréler.
3. **Règles.** Chaque règle teste des champs décodés et attribue un **niveau** de 0 à 15.
   Les règles s'enchaînent en arbre : une règle enfant (`if_sid`) précise une règle parent.
4. **Alerte.** Seuls les événements qui atteignent un niveau suffisant (3 par défaut)
   deviennent des alertes. Filebeat les expédie à l'**indexer**, et le **dashboard** les
   affiche.

### 1.2 Syslog en deux minutes

- Protocole historique (RFC 3164, puis RFC 5424) pour envoyer des journaux sur le réseau,
  généralement en **UDP 514**.
- Chaque message porte une *facility* (qui émet : kernel, auth…), une *severity* (0 =
  urgence, 7 = debug), une date, un nom d'hôte, un programme et le texte.
- UDP n'a ni accusé de réception ni chiffrement : un message perdu est perdu, et le trafic
  peut être lu. On l'accepte dans un lab isolé. En production, on préfère TCP, voire TLS.

### 1.3 Ce que pfSense envoie

Le pare-feu journalise chaque paquet qui touche une règle avec l'option *log*. Par défaut,
c'est le cas de la règle « default deny » : **tout ce qui est bloqué est journalisé**. Chaque
ligne vient du programme `filterlog` et contient, en CSV, l'interface, l'action
(`pass`/`block`), le protocole, les IP et les ports.

### 1.4 Ce que Wazuh en fait (ruleset natif 4.14)

| ID | Niveau | Ce qu'elle détecte |
|---|---|---|
| 87700 | 0 | Groupe pfSense : tout événement `filterlog` décodé (aucune alerte) |
| 87701 | 5 | Un paquet bloqué, mais avec `no_log` : pas d'alerte individuelle |
| **87702** | **10** | **18 blocages depuis la même IP en 45 s** : scan ou force brute probable (MITRE T1110) |

Conséquence importante pour un analyste : un paquet bloqué isolé **ne fait pas d'alerte**,
c'est du bruit normal sur un pare-feu. Wazuh alerte sur le **motif** : une même source qui
insiste. C'est la *corrélation* (`frequency` + `timeframe` + `same_source_ip`).

### 1.5 Ce qu'un analyste SOC en retire

- **Visibilité réseau** : qui tente d'entrer, depuis où, vers quels ports.
- **Détection de reconnaissance** : un scan de ports produit des dizaines de blocages en
  quelques secondes, donc la règle 87702.
- **Contexte pour l'enquête** : une alerte sur Windows (par exemple une connexion suspecte)
  se recoupe avec les journaux du pare-feu pour la même IP et la même heure.

## 2. Mise en œuvre

### 2.1 Côté Wazuh : ouvrir l'écoute syslog

Dans `/var/ossec/etc/ossec.conf`, ajouter un bloc `<remote>` **en plus** de celui qui existe
déjà (le bloc `secure` sur 1514, utilisé par les agents) :

```bash
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.10.10.254</allowed-ips>
</remote>
```

Fichier de référence : [configs/manager/ossec-remote-syslog.xml](../../configs/manager/ossec-remote-syslog.xml).

- `allowed-ips` est **obligatoire** : sans lui, le manager rejette le syslog. C'est aussi
  une protection, car seul pfSense peut injecter des journaux.
- `10.10.10.254` est l'IP LAN de pfSense, celle par laquelle il joint Wazuh.

```bash
sudo /var/ossec/bin/wazuh-control restart        # ou : sudo systemctl restart wazuh-manager
sudo ss -ulpn | grep ':514'                      # attendu : wazuh-remoted à l'écoute en UDP 514
```

Si `firewalld` est actif sur la VM (`sudo systemctl is-active firewalld`), ouvrir le port.
Sur l'OVA, il n'est a priori pas installé (à vérifier) :

```bash
sudo firewall-cmd --permanent --add-port=514/udp && sudo firewall-cmd --reload
```

### 2.2 Côté pfSense : activer l'envoi

*Status > System Logs > Settings*, section *Remote Logging Options* :

| Champ | Valeur |
|---|---|
| Enable Remote Logging | coché |
| Source Address | `LAN` |
| IP Protocol | IPv4 |
| Remote log servers | `10.10.10.100:514` |
| Remote Syslog Contents | `Firewall Events` (puis `System Events` si besoin) |

Garder le format de message par défaut (BSD / RFC 3164), attendu par le décodeur natif (à
valider). Puis *Save*.

### 2.3 Générer du trafic bloqué et vérifier

Depuis l'hôte Windows, viser le **WAN** de pfSense : tout trafic entrant y est bloqué et
journalisé par défaut.

```powershell
ping -n 60 -w 200 192.168.30.131
```

Piège rencontré : sans `-w`, chaque ping bloqué attend 4 s de timeout, soit environ 11 paquets
en 45 s, sous le seuil de 87702 (18 en 45 s). Avec `-w 200` (200 ms de timeout), le rythme
dépasse le seuil.

Vérifications, de la source vers l'alerte :

1. pfSense : *Status > System Logs > Firewall* montre les blocages ICMP sur WAN.
2. Wazuh reçoit le syslog (si `tcpdump` est présent sur la VM) :
   `sudo tcpdump -ni any udp port 514 -c 5`
3. Le décodage fonctionne : `sudo /var/ossec/bin/wazuh-logtest`, puis coller une ligne
   `filterlog` copiée depuis pfSense. Attendu : décodeur `pf`, règle 87700 ou 87701.
4. Dashboard, *Threat Hunting* : filtre `rule.groups:pfsense` ou `rule.id:87702`.

### 2.4 Dépannage : « je ne vois aucune alerte »

Vérifié dans le ruleset 4.14 (`0540-pfsense_rules.xml`) : 87700 est de niveau 0 et 87701
porte `<options>no_log</options>`. Un blocage isolé n'apparaît donc **jamais** dans le
dashboard. Seule 87702 s'y affiche, et elle se tait ensuite 4 minutes (`ignore="240"`). Un
*Threat Hunting* vide ne prouve rien : on remonte le chemin depuis la source.

1. **Réseau** : `sudo tcpdump -ni any udp port 514 -c 5` pendant la rafale de pings.
   - Rien : côté pfSense, *Log Message Format* = BSD (RFC 3164), *Log packets matched from
     the default block rules* coché, *Source Address* = `LAN`.
2. **Décodage** : `sudo /var/ossec/bin/wazuh-logtest`, puis coller une ligne de test :

   ```
   Oct 21 04:30:00 pfSense filterlog: 5,,,1000000103,vmx0,match,block,in,4,0x0,,64,1234,0,none,1,icmp,60,192.168.30.1,192.168.30.131,datalength=40
   ```

   Attendu : décodeur `pf`, `action: block`, `srcip: 192.168.30.1`, règle 87701.
3. **Archives** : `<logall>yes</logall>` dans `<global>`, redémarrer le manager, puis
   `sudo grep filterlog /var/ossec/logs/archives/archives.log | tail -3`. Remettre à `no`
   après le test, car l'archive grossit vite (cf. disque plein du writeup 01).

Le décodeur natif `pf` reconnaît la ligne par son `program_name` (`filterlog`). Il faut donc
un en-tête syslog BSD, que Wazuh sait découper.

## 3. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| `remoted` écoute en UDP 514 | ligne `wazuh-remoted` dans `ss` | ✅ OK |
| Syslog reçu par Wazuh (`tcpdump`) | `10.10.10.254 > 10.10.10.100.syslog` | ✅ OK : `local0.info`, ~1 paquet/s pendant la rafale |
| `wazuh-logtest` sur la ligne d'exemple | décodeur `pf`, règle 87701 | ✅ OK : `action: block`, `srcip: 192.168.30.1`, 87701 niveau 5 (logtest affiche « Alert to be generated » ; il n'applique probablement pas `no_log`, déduit) |
| `wazuh-logtest` sur une vraie ligne pfSense 2.9 | idem | à faire |
| Rafale `ping -n 60 -w 200` | alerte **87702** (niveau 10) | à faire |

Sources : https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html,
ruleset Wazuh 4.14 (`0455-pfsense_decoders.xml`, `0540-pfsense_rules.xml`), voir
[docs/integrations/pfsense.md](../integrations/pfsense.md).
