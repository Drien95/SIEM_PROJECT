# Suricata (IDS réseau)

Sources :
https://docs.netgate.com/pfsense/en/latest/packages/suricata/index.html (paquet pfSense),
https://docs.suricata.io/en/latest/output/eve/eve-json-output.html (EVE JSON),
https://docs.suricata.io/en/latest/configuration/suricata-yaml.html (variables `HOME_NET`),
https://rules.emergingthreats.net/ (ruleset ET Open),
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0475-suricata_rules.xml,
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/decoders/0006-json_decoders.xml,
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html,
PDF `Suricata_integration` (marxgoo, pour l'annexe Windows).

Déploiement retenu dans le lab : **Suricata sur pfSense**, en écoute sur l'interface ATTACK,
validé en live le 2026-10-22 ([scénario 4](../scenarios/suricata-nids.md),
[writeup 10](../writeup/10-scenario-suricata-nids.md)). Un capteur réseau sur le pare-feu voit
toutes les machines derrière lui, sans rien installer sur elles.

![Chaîne Suricata vers Wazuh](../diagrams/suricata-pipeline.png)

## 1. Installation sur pfSense CE 2.9.0

1. **System > Package Manager > Available Packages** : installer `suricata`.
2. **Services > Suricata > Global Settings** : cocher **ET Open** (Emerging Threats Open,
   gratuit, sans clé), fixer une mise à jour périodique des règles, puis **Updates > Update**.
3. **Services > Suricata > Interfaces > Add** : interface **ATTACK** (`em0`).
   - *Block Offenders* : **désactivé** (IDS, alerte seule).
   - *EVE JSON Log* : activé, *EVE Output Type* = **Syslog**, *EVE Logged Info* : au minimum
     *Alerts*.
4. Onglet **ATTACK Categories** : activer au moins `emerging-scan` (signatures `ET SCAN`).
5. **System > Advanced > Networking** : cocher la désactivation du *Hardware Checksum
   Offloading*, du *TCP Segmentation Offloading* et du *Large Receive Offloading*, puis
   **redémarrer pfSense**. Recommandation Netgate pour Suricata (à valider : effet non isolé
   dans le lab).
6. **Status > System Logs > Settings** : *Remote Syslog Contents* = **Everything**, serveur
   distant `10.10.10.100:514`. Sinon les lignes de Suricata ne partent pas.
7. Démarrer Suricata sur l'interface (icône lecture dans **Services > Suricata > Interfaces**).

Le pfSense du lab n'a que 1 Go de RAM : Suricata avec ET Open y tourne, mais avec peu de marge
(à surveiller dans **Status > Monitoring**).

## 2. `HOME_NET` : la variable qui décide de tout

Une signature ET « inbound » s'écrit `$EXTERNAL_NET any -> $HOME_NET <port>`.
`$EXTERNAL_NET` vaut par défaut `!$HOME_NET`. Si l'attaquant est dans `HOME_NET`, la signature
ne peut pas correspondre.

**Piège observé** : par défaut, pfSense remplit `HOME_NET` avec les réseaux de **toutes** ses
interfaces, donc aussi `10.10.20.0/24` (ATTACK). Kali était « interne » : aucune alerte
ET SCAN.

Correction :

1. **Firewall > Aliases > Add** : type **Network(s)**, nom `HOMENET_LAB`, valeur
   `10.10.10.0/24`.
2. **Services > Suricata > ATTACK > Variables > Custom Variables** : *Type* = Server,
   *Name* = `HOME_NET`, *Value* = **`HOMENET_LAB`**. Enregistrer, redémarrer Suricata sur
   l'interface.

La liste *Home Net* de l'onglet de l'interface ne propose pas les alias, et le champ
*Custom Variables* refuse un CIDR brut (« Only aliases are allowed ») : il faut **le nom de
l'alias**.

## 3. Ce que reçoit Wazuh

pfSense envoie chaque ligne EVE dans un en-tête syslog **RFC 5424**. Ligne réelle capturée sur le
manager (abrégée) :

```bash
sudo tcpdump -i any -A -n udp port 514 | grep event_type
```

```
<141>1 2026-10-22T... pfSense.siem.lab suricata 12345 - - {"timestamp":"...","event_type":"alert",...}
```

Après le PID viennent **deux tirets** : MSGID vide, puis données structurées vides. Le
décodeur natif `json` exige une ligne qui commence par `{` (`<prematch>^{\s*"</prematch>`) : il
ignore cette ligne.

Effet de bord de pfSense : la sortie EVE vers syslog force aussi « Send Alerts to System Log »
(`fast.log` en texte). Les deux ne se séparent pas. Pas de doublon dans Wazuh pour autant : la
ligne texte n'a pas de JSON, donc pas de `timestamp` ni d'`event_type`, et 86600 ne se déclenche
pas (déduit du ruleset, cohérent avec le dashboard).

## 4. Décodeur et règles côté Wazuh

### Décodeur (option A, en place)

Dans `/var/ossec/etc/decoders/local_decoder.xml` (extrait :
[`configs/manager/local_decoder.xml`](../../configs/manager/local_decoder.xml)) :

```xml
<decoder name="json">
  <prematch>suricata \d+ - - </prematch>
  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>
```

- Un seul décodeur, motif de la documentation officielle de `JSON_Decoder`.
- Nommé `json` pour que les règles natives (`<decoded_as>json</decoded_as>`) s'appliquent sans
  être réécrites ; le `<prematch>` limite ce décodeur aux lignes Suricata relayées par syslog.
- Erreurs rencontrées avant d'y arriver (1452, 2107, 2111, 2120) : voir le
  [writeup 10, § 3.2](../writeup/10-scenario-suricata-nids.md#32-le-débogage--quatre-erreurs-instructives).
- Toujours écrire le `<prematch>` à partir d'une ligne **capturée en live**, pas d'un exemple
  tapé : `wazuh-logtest` validait une ligne à un seul tiret, le live en avait deux.

### Règles natives (ruleset v4.14.0, vérifié)

| Règle | Niveau | Condition |
|---|---|---|
| 86600 | 0 | `decoded_as json`, champs `timestamp` et `event_type` présents |
| **86601** | **3** | `event_type` = `alert` : *Suricata: Alert - $(alert.signature)* |
| 86602 / 86603 / 86604 | 0 | `event_type` = `http` / `dns` / `tls` |

### Règles locales

Dans [`configs/manager/local_rules.xml`](../../configs/manager/local_rules.xml), enfants de 86601 :

| Règle | Niveau | Condition | MITRE | Statut |
|---|---|---|---|---|
| 100200 | 10 | `alert.severity` = 1 (sévérité la plus haute) | — | en place, pas encore vue en action |
| **100210** | **10** | `alert.signature` contient `ET SCAN` | T1046 | ✅ validée le 2026-10-22 |

Recherche : `rule.groups:suricata`. Les alertes portent `agent.name: wazuh-server` (source
syslog, sans agent) ; la source réelle est dans `location`.

## Option B : rsyslog et fichier JSON (à valider)

Variante « production » : retirer l'en-tête **avant** Wazuh, pour décoder le JSON nativement et
ne maintenir aucun décodeur. Non testée dans le lab ; la syntaxe ci-dessous est un point de
départ.

1. pfSense envoie aussi son syslog vers le manager sur un port dédié, par exemple
   `10.10.10.100:5140` (le 514 est déjà pris par `wazuh-remoted`).
2. rsyslog sur le manager (à installer si absent de l'OVA, à valider) écrit le seul message,
   donc le JSON, des lignes `suricata` :

   ```
   # /etc/rsyslog.d/10-suricata.conf (à valider)
   module(load="imudp")
   template(name="eve_only" type="string" string="%msg%\n")
   ruleset(name="suricata_eve") {
     if $programname == "suricata" and $msg contains "event_type" then {
       action(type="omfile" file="/var/log/suricata-eve.json" template="eve_only")
     }
     stop
   }
   input(type="imudp" port="5140" ruleset="suricata_eve")
   ```

3. Wazuh lit le fichier comme du JSON (bloc dans `ossec.conf` du manager) :

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/suricata-eve.json</location>
   </localfile>
   ```

4. Prévoir une rotation (`logrotate`) et retirer notre décodeur `json` local.

| | Option A : décodeur local (en place) | Option B : rsyslog + fichier |
|---|---|---|
| Composants | Wazuh seul | rsyslog et `logrotate` en plus |
| Décodage | décodeur local à maintenir | natif |
| Robustesse | dépend de l'en-tête exact de pfSense | indépendante de l'en-tête |
| Filtrage | tout passe par `wazuh-remoted` | rsyslog peut ne garder que les `alert` |

## Annexe : Suricata sur un poste Windows (lab marxgoo)

Variante non retenue : un IDS sur le poste ne voit que le trafic de ce poste, et un attaquant
qui le compromet peut l'arrêter. Notes conservées pour référence.

### IDS ou IPS

- **IDS** : inspecte le trafic (signatures, IoC, scripts Lua), alerte sans bloquer.
  Mode par défaut de Suricata.
- **IPS** : bloque ou laisse passer en ligne. Sous Windows, il nécessite WinDivert.

### Installation sur Windows (lab marxgoo)

1. Installer **Npcap** (https://npcap.com) en cochant le mode compatible WinPcap, puis
   vérifier : `Get-Service -Name npcap` doit être `Running`.
2. Installer le MSI Suricata (https://suricata.io/download/) dans `C:\Program Files\Suricata\`.
   On y trouve `suricata.exe`, `suricata.yaml`, `rules\` et `log\`.

### Configuration

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


### Ingestion par l'agent Windows

Dans `ossec.conf` de l'agent :

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\Program Files\Suricata\log\eve.json</location>
</localfile>
```

Puis `Restart-Service -Name WazuhSvc`. Le PDF écrit `-Name wazuh`, ce qui est faux.

Ici, le fichier `eve.json` ne contient que du JSON pur : le décodeur natif `json` suffit.
