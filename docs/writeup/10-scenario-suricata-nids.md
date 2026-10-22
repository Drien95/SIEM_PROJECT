# Writeup 10 : quatrième scénario, un IDS réseau Suricata sur pfSense

> Un scan nmap lancé depuis Kali vers Windows 11 traverse pfSense. Suricata, installé sur
> l'interface ATTACK du pare-feu, le reconnaît grâce aux signatures **ET SCAN** du ruleset
> Emerging Threats Open. L'alerte part en syslog vers Wazuh, qui la décode et lève la règle
> locale **100210** au niveau 10. Il a fallu deux corrections pour y arriver : une variable
> `HOME_NET` mal définie et un en-tête syslog que Wazuh ne savait pas lire. L'analyse détaillée
> est dans la fiche [`docs/scenarios/suricata-nids.md`](../scenarios/suricata-nids.md),
> l'installation dans [integrations/suricata.md](../integrations/suricata.md).
>
> Versions : pfSense CE 2.9.0 (paquet Suricata), Wazuh 4.14.9, Kali. Date : 2026-10-22, alertes
> natives à 23:37 et règle 100210 à 23:47 (heure du dashboard).

![Chaîne de détection Suricata : du paquet nmap à l'alerte 100210](../diagrams/suricata-pipeline.png)

*Source : [`suricata-pipeline.html`](../diagrams/suricata-pipeline.html).*

## 1. Comprendre

### 1.1 Un IDS réseau, et pourquoi sur le pare-feu

Jusqu'ici, deux témoins regardaient le lab :

- l'**agent** sur Windows 11, qui voit ce qui se passe **sur le poste** (journaux, fichiers,
  Sysmon) ;
- le **pare-feu** pfSense, qui dit seulement **autorisé ou bloqué** pour chaque paquet
  journalisé (`filterlog`, [writeup 08](08-scenario-scan-nmap.md)).

Il manquait un témoin qui lise **le contenu du trafic**. C'est le rôle d'un **NIDS** (*Network
Intrusion Detection System*) : il compare chaque paquet et chaque flux à des milliers de
**signatures**, des motifs connus d'attaques, de scans ou de malwares.

**Suricata** est un NIDS libre très répandu. On l'installe **sur pfSense**, en écoute sur
l'interface **ATTACK** (`em0`), et non sur le poste Windows. C'est le déploiement « pro » :

- un capteur réseau voit **toutes** les machines derrière lui sans rien installer sur elles ;
- l'attaquant ne peut pas le désactiver depuis un poste compromis ;
- il est placé au point de passage obligé entre le réseau d'attaque et le LAN.

Mode choisi : **IDS, alerte seule** (*Block Offenders* désactivé). Suricata signale, il ne coupe
rien. Le blocage reste le travail des règles du pare-feu et de la réponse active de Wazuh
([writeup 07](07-regles-et-reponse-active.md)).

### 1.2 L'angle mort que Suricata couvre

Le [scénario 2](08-scenario-scan-nmap.md) détectait un scan par la **rafale de blocages**
(100303). Il avait un angle mort : un scan vers une destination **autorisée** (Windows 11,
règle 2 de l'interface ATTACK) ne produit pas de blocage, donc pas de 100303. Suricata, lui,
regarde la **forme** du trafic, qu'il soit autorisé ou non. C'est pourquoi ce scénario vise
précisément `10.10.10.101`.

### 1.3 Les signatures ET Open

Les signatures viennent du ruleset **ET Open** (Emerging Threats, Proofpoint), gratuit, activé
dans le paquet Suricata de pfSense. Une signature `ET SCAN` ressemble à ceci (forme générale) :

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN Suspicious inbound to mySQL port 3306"; flags:S; threshold: ...; sid:...;)
```

Deux variables pilotent tout : **`$HOME_NET`** (ce qu'on protège) et **`$EXTERNAL_NET`** (le
reste, par défaut `!$HOME_NET`). Une signature « inbound » ne se déclenche que pour un trafic
qui va **de l'extérieur vers HOME_NET**. Retenir ce point : c'est la cause de la première panne.

### 1.4 Le chemin d'une alerte

| Étape | Où | Ce qui se passe |
|---|---|---|
| 1 | Kali `10.10.20.10` | `nmap -sS -Pn 10.10.10.101` envoie des SYN vers de nombreux ports |
| 2 | pfSense, Suricata sur `em0` | une signature ET SCAN correspond ; Suricata écrit une ligne **EVE JSON** `event_type: alert` |
| 3 | pfSense, syslog | la ligne part en syslog **RFC 5424** vers `10.10.10.100:514/udp` |
| 4 | Wazuh, `wazuh-remoted` | reçoit la ligne (bloc `<remote>` syslog de [`ossec-remote-syslog.xml`](../../configs/manager/ossec-remote-syslog.xml)) |
| 5 | Wazuh, `wazuh-analysisd` | notre décodeur `json` extrait le JSON ; la règle native **86600** reconnaît Suricata, **86601** (niveau 3) l'alerte ; notre **100210** l'élève au niveau 10 |
| 6 | indexer, dashboard | recherche `rule.groups:suricata` |

## 2. Mise en place côté pfSense

Le détail, clic par clic, est dans [integrations/suricata.md](../integrations/suricata.md). En
résumé :

| Réglage | Valeur | Pourquoi |
|---|---|---|
| Paquet | **Suricata** (System > Package Manager) | le NIDS |
| Ruleset | **ET Open** activé, catégorie `emerging-scan` | les signatures de scan |
| Interface | **ATTACK** (`em0`) | le point d'entrée de l'attaquant |
| Block Offenders | **désactivé** | IDS, pas IPS |
| EVE JSON Log | activé, sortie **Syslog** | format structuré lisible par Wazuh |
| Offloading matériel (checksum, TSO, LRO) | **désactivé**, puis redémarrage de pfSense | recommandation Netgate pour Suricata : la capture doit voir les vrais paquets (à valider : effet non mesuré seul dans le lab) |
| Status > System Logs > Settings > Remote Syslog Contents | **Everything** | sinon les lignes de Suricata ne partent pas vers Wazuh |

### 2.1 Première panne : `HOME_NET` contenait l'attaquant

Premier scan : **aucune alerte ET SCAN**. Par défaut, pfSense construit `HOME_NET` à partir des
réseaux de **toutes** ses interfaces, donc il y mettait aussi `10.10.20.0/24`, le réseau
d'attaque. Pour Suricata, Kali était donc **interne**, et une signature « de l'extérieur vers
HOME_NET » ne pouvait pas correspondre.

Correction, en deux temps (le formulaire a ses exigences) :

1. **Firewall > Aliases** : créer un alias de type **Network(s)** `HOMENET_LAB` =
   `10.10.10.0/24` (le LAN seul).
2. **Services > Suricata > ATTACK > Variables > Custom Variables** : ajouter
   *Type* = Server, *Name* = `HOME_NET`, *Value* = **`HOMENET_LAB`**.

Deux pièges observés : la liste déroulante *Home Net* de l'onglet de l'interface **ne propose
pas** les alias, et le champ *Custom Variables* refuse un CIDR brut avec le message « Only
aliases are allowed ». Il faut donc **le nom de l'alias**.

> **Leçon SOC** : un IDS mal renseigné sur ce qui est « chez nous » est silencieux sans être
> en panne. Vérifier `HOME_NET` fait partie de tout déploiement d'IDS.

## 3. Mise en place côté Wazuh

### 3.1 Deuxième panne : l'en-tête syslog

Une fois `HOME_NET` corrigé, Suricata alertait bien sur pfSense, mais rien n'arrivait dans le
dashboard. La règle native **86600** porte `<decoded_as>json</decoded_as>` : elle attend un
événement décodé par le décodeur natif `json`. Or celui-ci ne reconnaît une ligne que si elle
**commence par `{`** (`<prematch>^{\s*"</prematch>` dans `0006-json_decoders.xml`, vérifié dans
le ruleset v4.14.0).

Ce que pfSense envoie réellement, capturé sur le manager :

```bash
sudo tcpdump -i any -A -n udp port 514 | grep event_type
```

```
<141>1 2026-10-22T... pfSense.siem.lab suricata 12345 - - {"timestamp":"...","event_type":"alert","src_ip":"10.10.20.10",...}
```

*(Ligne abrégée ; le PID est illustratif.)* Chaque ligne JSON est enveloppée dans un en-tête
**RFC 5424** : priorité, version, horodatage, hôte, programme, PID, puis **deux tirets** (MSGID
vide et données structurées vides). Le JSON ne commence donc pas la ligne, et le décodeur natif
l'ignore.

### 3.2 Le débogage : quatre erreurs instructives

La solution paraît simple : un décodeur qui saute l'en-tête puis passe le reste au plugin
`JSON_Decoder`. Le chemin a croisé quatre erreurs de `wazuh-analysisd`. Les noter fait gagner
des heures la prochaine fois.

| Erreur | Cause | Leçon |
|---|---|---|
| **1452** | `\{` dans un `<prematch>` | `<prematch>` et `<regex>` utilisent **OS_Regex**, pas PCRE : `{` y est déjà littéral et `\{` est invalide. `type="pcre2"` seulement là où on a besoin de PCRE |
| **2107** | décodeur enfant portant **le même nom** que son `<parent>` ; ou `<regex>` sans `<order>` | parent et enfant ont des noms différents ; une `<regex>` doit dire où ranger ses captures |
| **2111** | `<regex>` + `<order>` + `<plugin_decoder>` dans le même décodeur | « Additional data to plugin decoder » : un décodeur extrait des champs **ou** passe la main à un plugin, pas les deux |
| **2120** | `offset="after_prematch"` sur un enfant dont le `<prematch>` est sur le parent | `after_prematch` exige un `<prematch>` **dans le même décodeur** ; sinon `after_parent` ou `after_regex` |

Et un piège sans message d'erreur : **`wazuh-logtest` validait, le live échouait**. Le test
portait sur une ligne recopiée à la main, avec un seul tiret. Les vraies lignes en ont deux.
D'où la règle : **toujours construire le décodeur sur une ligne capturée en live**
(`tcpdump` ci-dessus), jamais sur un exemple tapé.

### 3.3 Le décodeur final

C'est le motif de la documentation officielle de `JSON_Decoder` : un **seul** décodeur, un
`<prematch>` qui s'arrête juste avant le `{`, et le plugin lancé à partir de là. Ni parent, ni
enfant, ni `<regex>`. Déployé dans `/var/ossec/etc/decoders/local_decoder.xml` (extrait dans
[`configs/manager/local_decoder.xml`](../../configs/manager/local_decoder.xml)) :

```xml
<decoder name="json">
  <prematch>suricata \d+ - - </prematch>
  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>
```

Pourquoi le nommer **`json`**, comme le décodeur natif ? Parce que 86600 filtre sur
`decoded_as json`. Avec ce nom, **toutes les règles natives Suricata** (86600 à 86604)
s'appliquent sans être réécrites, comme le demande la convention du projet (étendre, ne pas
redéfinir). Notre décodeur se comporte comme une **variante restreinte** du natif : son
`<prematch>` ne correspond qu'aux lignes de Suricata relayées par syslog, il ne capte rien
d'autre. Vérifié en live : 86601 s'est déclenchée sur ces lignes dès ce décodeur en place.

### 3.4 La règle locale 100210

86601 sort au **niveau 3**, trop bas pour qu'un analyste la remarque. On ajoute une règle
enfant (extrait dans [`configs/manager/local_rules.xml`](../../configs/manager/local_rules.xml)) :

```xml
<group name="local,suricata,">
  <!-- Suricata : scan réseau détecté par signature ET SCAN (reconnaissance active). MITRE T1046. -->
  <rule id="100210" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature" type="pcre2">(?i)ET SCAN</field>
    <description>Suricata : scan réseau détecté - $(alert.signature)</description>
    <mitre><id>T1046</id></mitre>
    <group>recon,</group>
  </rule>
</group>
```

- `<if_sid>86601</if_sid>` : seulement les alertes Suricata déjà reconnues par la règle native.
- `alert.signature` : champ extrait par `JSON_Decoder` du JSON d'EVE (`{"alert":{"signature":…}}`).
- `$(alert.signature)` : la signature apparaît dans le titre de l'alerte.

La règle existante **100200** (enfant de 86601, `alert.severity` = 1, niveau 10) reste en
place. Elle ne couvre que la **sévérité 1** de Suricata, alors que les signatures ET SCAN de ce
scénario sont de sévérité 2 (déduit : elles sont sorties au niveau 3 sans 100200). D'où une
règle dédiée aux scans.

Validation : `sudo /var/ossec/bin/wazuh-analysisd -t` puis
`sudo systemctl restart wazuh-manager`.

## 4. Déroulé et résultat

Depuis Kali (réseau d'attaque isolé, cible du lab) :

```bash
sudo nmap -sS -Pn 10.10.10.101
```

Dans *Threat Hunting*, `rule.groups:suricata` (capture 94) :

- à **23:37**, avant la règle 100210 : 9 alertes **86601** niveau 3 « Suricata: Alert - ET SCAN
  … » (MSSQL 1433, mySQL 3306, PostgreSQL 5432, Oracle 1521, VNC 5800-5820) ;
- à **23:47**, après le déploiement de 100210 : **100210** niveau 10 « Suricata : scan réseau
  détecté - ET SCAN Suspicious inbound to MSSQL port 1433 » et « … mySQL port 3306 ».

![Threat Hunting rule.groups:suricata : 100210 niveau 10 au-dessus des 86601 niveau 3](../homelab/screenshots/94-wazuh-100210-suricata-scan.png)

*Capture 94 : 13 hits en 15 minutes ; en haut les 100210 (niveau 10), en bas les 86601 du
premier passage (niveau 3).*

À noter : les alertes portent `agent.name: wazuh-server`. Les journaux syslog n'ont pas
d'agent ; Wazuh les rattache au manager. La vraie source est dans le champ `location`
(l'adresse de pfSense) et dans `src_ip` / `dest_ip` du JSON.

## 5. Ce qu'on retient

### 5.1 Deux témoins valent mieux qu'un

| Témoin | Ce qu'il voit du scan vers Windows 11 | Règle |
|---|---|---|
| pfSense `filterlog` | trafic **autorisé** par la règle 2 : rien d'anormal | 100301 (niveau 3) |
| Suricata | la **forme** d'un scan vers des ports de bases de données et de VNC | 86601 → **100210** (niveau 10) |

Le pare-feu dit « qui parle à qui », l'IDS dit « ce que ça ressemble ». Un SOC croise les deux.

### 5.2 Une alerte en double ? Non

Sur pfSense, activer la sortie EVE vers syslog **force** aussi « Send Alerts to System Log »
(le `fast.log`, une ligne texte par alerte) : les deux cases ne se séparent pas. Chaque alerte
part donc deux fois, en JSON et en texte. Il n'y a pourtant **pas de doublon** dans Wazuh : la
ligne texte passe le `<prematch>`, mais `JSON_Decoder` n'en tire aucun champ, et 86600 exige
`timestamp` et `event_type` (déduit du ruleset ; cohérent avec le dashboard, qui ne montre
aucun doublon).

### 5.3 Option B, la variante « production »

Le décodeur personnalisé marche, mais il dépend du format exact de l'en-tête de pfSense. La
variante plus propre consiste à **retirer l'en-tête avant Wazuh** :

1. pfSense envoie le syslog de Suricata à un **rsyslog** sur le manager (port dédié, par
   exemple `5140/udp`, pour ne pas entrer en conflit avec `wazuh-remoted` sur 514) ;
2. rsyslog n'écrit que le message, c'est-à-dire le JSON pur, dans `/var/log/suricata-eve.json` ;
3. Wazuh lit ce fichier comme du JSON natif :

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata-eve.json</location>
</localfile>
```

| | Option A : décodeur `json` (en place) | Option B : rsyslog + fichier JSON (à valider) |
|---|---|---|
| Composants | Wazuh seul | rsyslog en plus sur le manager, rotation du fichier (`logrotate`) |
| Décodage | décodeur local à maintenir | natif, aucun décodeur |
| Robustesse | casse si pfSense change l'en-tête (un tiret de plus ou de moins) | indépendante de l'en-tête |
| Volume | tout passe par `wazuh-remoted` | rsyslog peut filtrer (garder `alert`, jeter `flow` ou `stats`) |
| Pédagogie | montre comment Wazuh décode | montre une architecture de collecte réelle |

En production, on retrouve plutôt l'option B, ou un agent installé directement sur le capteur.
Dans le lab, l'option A suffit et a beaucoup appris. Le détail de l'option B est dans
[integrations/suricata.md](../integrations/suricata.md#option-b--rsyslog-et-fichier-json-à-valider).

## 6. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| Alerte ET SCAN avec le `HOME_NET` par défaut | alerte | ❌ aucune : Kali dans `HOME_NET` |
| Alerte ET SCAN avec `HOME_NET` = `HOMENET_LAB` | alerte sur pfSense | ✅ |
| Ligne EVE reçue par le manager | JSON après en-tête RFC 5424 | ✅ capturée avec `tcpdump`, deux tirets |
| Décodage par le natif `json` | 86600 / 86601 | ❌ la ligne ne commence pas par `{` |
| Décodage par notre décodeur `json` | 86601 niveau 3 | ✅ 9 alertes à 23:37 |
| Règle locale 100210 | niveau 10, T1046 | ✅ 23:47 (capture 94) |
| Doublon EVE + `fast.log` | aucun | ✅ aucun observé |

Sources : voir la [fiche du scénario](../scenarios/suricata-nids.md).
