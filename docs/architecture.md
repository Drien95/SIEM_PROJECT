# Architecture

## Composants Wazuh

| Composant | Rôle |
|---|---|
| **Agent** | Installé sur les endpoints (Windows, Linux, macOS…). Collecte journaux, intégrité des fichiers, inventaire, et exécute les réponses actives. |
| **Serveur (manager)** | Reçoit les événements, les décode et applique les règles (moteur d'analyse). Expose l'API REST. |
| **Indexeur** | Stocke et indexe alertes et événements (moteur basé sur OpenSearch). |
| **Dashboard** | Interface web : recherche, visualisation, gestion des agents. |

Source : https://documentation.wazuh.com/current/getting-started/architecture.html

## Flux de données

```
Agent ──(1514/TCP, AES)──► Serveur ──Filebeat (9200/TCP, TLS)──► Indexeur
                              ▲                                      │
                              └──── API 55000/TCP ──── Dashboard ◄───┘ (HTTPS)
```

1. L'agent envoie ses événements au serveur (1514/TCP, chiffrement AES par défaut).
2. Filebeat, sur le serveur, transmet alertes et événements à l'indexeur (9200/TCP, TLS).
3. Le dashboard interroge l'indexeur (HTTPS) et l'API du serveur (55000/TCP).

Les équipements sans agent (pare-feu pfSense, etc.) envoient du **syslog** au serveur
(514/UDP ou TCP, désactivé par défaut, à activer dans `ossec.conf` du manager).

## Comment Wazuh fonctionne : `ossec.conf` et les démons

> **La formule** : `ossec.conf` = **quoi** faire ; les démons = **qui** le fait ; indexer +
> dashboard = **où** l'on regarde.

![Chaîne des démons Wazuh, de l'agent au dashboard](diagrams/demons-wazuh.png)

*Qui fait quoi, avec les trois branches qui partent de l'analyse (intégrations, réponse active,
vulnérabilités). Source : [`demons-wazuh.html`](diagrams/demons-wazuh.html). Le détail des trois
passes d'analysisd sur une vraie ligne pfSense est dans le
[pipeline annoté](diagrams/pipeline-wazuh.png) (writeup 02).*

### `ossec.conf` : le fichier maître, déclaratif

Chaque machine Wazuh a son `ossec.conf` : `/var/ossec/etc/ossec.conf` sur le manager,
`C:\Program Files (x86)\ossec-agent\ossec.conf` sur un agent Windows. On y **déclare** ce que
Wazuh doit faire, sans écrire de code :

| Bloc (manager) | Rôle | Dans le lab |
|---|---|---|
| `<remote>` | réception : agents sur 1514/TCP, syslog sur 514 | syslog pfSense ([writeup 02](writeup/02-syslog-pfsense.md)) |
| `<ruleset>` | décodeurs et règles chargés (natifs + `local_decoder.xml`, `local_rules.xml`) | règles 100100 à 100400 |
| `<integration>` | appel d'un service externe sur certaines alertes | VirusTotal (prévu, [intégration](integrations/virustotal.md)) |
| `<command>` + `<active-response>` | quel script lancer, sur quelle règle, où, combien de temps | `block-ip-win` sur 60204 ([writeup 07](writeup/07-regles-et-reponse-active.md)) |
| `<vulnerability-detection>` | détection des CVE à partir de l'inventaire des agents | à venir ([roadmap](roadmap.md)) |

Côté agent : `<localfile>` (quels journaux lire), `<syscheck>` (FIM), `<sca>` (audit de
configuration). Ces blocs peuvent être poussés depuis le manager par la configuration
centralisée `agent.conf` ([writeup 04](writeup/04-agent-windows-sysmon.md)).

Le fichier peut contenir **plusieurs blocs `<ossec_config>`** : Wazuh les lit tous au
démarrage, comme un seul ensemble de configuration. C'est pourquoi on peut ajouter nos réglages
dans un bloc à part, ou juste avant la dernière balise `</ossec_config>`. Pour savoir combien
de blocs contient notre fichier : `sudo grep -c '<ossec_config>' /var/ossec/etc/ossec.conf`
(nombre exact à relever, à valider).

### Les démons : qui fait le travail

| Où | Démon | Ce qu'il fait |
|---|---|---|
| Agent | `wazuh-logcollector` | lit les journaux déclarés (`<localfile>` : Event Log, Sysmon, fichiers) |
| Agent | `wazuh-syscheckd` | FIM : empreintes des fichiers, détection des changements |
| Agent | `wazuh-modulesd` | modules : SCA, inventaire du système (paquets, ports, processus) |
| Agent | `wazuh-agentd` | chiffre (AES) et envoie tout au manager sur 1514/TCP |
| Agent | `wazuh-execd` | exécute les réponses actives reçues |
| Manager | `wazuh-remoted` | reçoit les agents (1514) et le syslog (514) ; renvoie les ordres de réponse active aux agents |
| Manager | `wazuh-analysisd` | le moteur : pré-décodage, décodage, règles ; écrit les alertes dans `alerts.json` |
| Manager | `wazuh-integratord` | lit les alertes et appelle les intégrations (VirusTotal, Slack…) |
| Manager | `wazuh-execd` | exécute les réponses actives `location` `server` |
| Manager | `wazuh-modulesd` | modules côté serveur, dont la détection de vulnérabilités |
| Manager | Filebeat | expédie `alerts.json` vers l'indexer (9200/TCP, TLS) |
| Indexer | `wazuh-indexer` | stocke et indexe (OpenSearch) |
| Dashboard | `wazuh-dashboard` | l'interface de l'analyste (443) |

Sur **Windows**, la partie agent tourne dans un seul service, `WazuhSvc` (`wazuh-agent.exe`), qui
regroupe collecte, FIM, SCA et réponse active ; sur Linux ce sont des démons séparés. Un agent
arrêté coupe donc **toute** la remontée du poste (piège du [writeup 07, § 4.3](writeup/07-regles-et-reponse-active.md)).

### `wazuh-analysisd` : d'un journal brut à une alerte

1. **Pré-décodage** : extrait l'en-tête commun (date, nom d'hôte, programme) quand il y en a un
   (syslog BSD). Les événements Windows arrivent en JSON et n'en ont pas besoin.
2. **Décodage** : un décodeur reconnaît le format et extrait les champs utiles : `srcip`,
   `user`, `win.eventdata.ipAddress`, hash de fichier… (natifs, ou notre `pfsense-filterlog`).
3. **Règles** : le ruleset natif puis `local_rules.xml`. Chaque règle a un **niveau** (0 à 15) ;
   les règles de corrélation (`frequency`, `timeframe`, `if_matched_sid`, `same_field`)
   regardent ce qui s'est passé avant (60204, 100303, 100400).

Seuls les événements qui atteignent une règle de niveau suffisant deviennent des **alertes**,
écrites dans `/var/ossec/logs/alerts/alerts.json`, puis expédiées par Filebeat.

**`wazuh-analysisd -t`** : mode test. Le démon charge la configuration et tout le ruleset,
signale la moindre erreur de syntaxe, puis s'arrête sans démarrer. C'est le filet de sécurité
à lancer **avant** chaque `systemctl restart wazuh-manager` : une règle mal formée peut empêcher
le manager de redémarrer.

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

### Les trois branches après l'analyse

- **Intégration** : `wazuh-integratord` prend une alerte (par exemple FIM) et interroge un
  service externe. La réponse de VirusTotal revient comme un **nouvel événement** analysé à son
  tour : règle 87105 (niveau 12) si des moteurs détectent le fichier.
- **Réponse active** : `analysisd` déclenche, mais n'agit pas lui-même. Pour `location` `local`,
  l'ordre repart par `wazuh-remoted` vers l'agent, dont `wazuh-execd` lance le script.
- **Vulnérabilités** : `wazuh-modulesd` croise l'inventaire des agents avec le flux de CVE
  (`cti.wazuh.com`) et écrit l'état dans l'indexer.

Sources : https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html,
https://documentation.wazuh.com/current/user-manual/reference/daemons/index.html,
https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html,
https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html,
https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html,
ruleset v4.14.0 `0490-virustotal_rules.xml` (règle 87105).

## Ports

| Composant | Port | Protocole | Usage |
|---|---|---|---|
| Serveur | 1514 | TCP | Connexion des agents |
| Serveur | 1515 | TCP | Enrôlement des agents |
| Serveur | 1516 | TCP | Cluster Wazuh |
| Serveur | 514 | UDP/TCP | Collecteur syslog (désactivé par défaut) |
| Serveur | 55000 | TCP | API REST |
| Indexeur | 9200 | TCP | API REST de l'indexeur |
| Indexeur | 9300-9400 | TCP | Communication entre nœuds |
| Dashboard | 443 | TCP | Interface web |

Sorties nécessaires : `cti.wazuh.com:443` (flux de vulnérabilités) et
`packages.wazuh.com:443` (paquets, mises à jour d'agents).

## Topologie de lab cible

Synthèse des deux labs de référence (voir [sources.md](sources.md)). Proposition à valider.

| Machine | Rôle | Source |
|---|---|---|
| VM Wazuh (OVA ou Ubuntu 24.04 all-in-one) | Serveur + indexeur + dashboard | les deux dépôts |
| Windows 11 | Agent Wazuh + Sysmon (+ Suricata en option) | marxgoo |
| Kali Linux | Attaquant (Hydra) et/ou endpoint Linux avec agent | les deux dépôts |
| pfSense (optionnel) | Pare-feu ; WAN en NAT, LAN host-only `192.168.1.1/24` ; logs envoyés en syslog | marxgoo |

Hyperviseur : VMware Workstation ou VirtualBox. Réseau : mode **pont** (UsmanPrime) pour
que l'hôte joigne la VM, ou réseau host-only/NAT dédié pour isoler les attaques
(recommandation de notre part, à valider).

## Matrice des flux du lab (moindre privilège)

Principe : chaque machine n'ouvre que les flux dont elle a besoin. Tout le reste est refusé.
Décidé le 2026-10-21 pour notre homelab (voir [homelab/plan.md](homelab/plan.md)).

| Source | Destination | Port / proto | Usage | État |
|---|---|---|---|---|
| Hôte `10.10.10.1` | pfSense `10.10.10.254` | 443/tcp, 22/tcp (clé) | administration | OK (SSH par clé, writeup 03) |
| Hôte `10.10.10.1` | Wazuh `10.10.10.100` | 443/tcp, 22/tcp (clé) | dashboard, administration | OK |
| pfSense `10.10.10.254` | Wazuh `10.10.10.100` | 514/udp | syslog du pare-feu | ✅ validé (writeup 02) |
| Windows 11 `10.10.10.101` | Wazuh `10.10.10.100` | 1514/tcp, 1515/tcp | agent : événements, enrôlement | ✅ validé (writeup 04) |
| Kali `10.10.20.10` (VMnet11, réservation DHCP) | Windows 11 `10.10.10.101` | tout (règle 2 d'ATTACK, journalisée) | scénarios (22, 3389, 445…) | règle en place (writeup 05), Kali à installer |
| Kali | pfSense `10.10.20.254` 53 ; Internet 80, 443 | TCP/UDP 53, TCP 80, 443 | DNS, mises à jour (règles 1, 6, 7, sans journal) | règles en place |
| Hôte `10.10.10.1` | Kali `10.10.20.10` | 22/tcp (clé) | piloter Kali (`ssh siem-kali`) | route `10.10.20.0/24` via `10.10.10.254` sur l'hôte, règle LAN par défaut (writeup 05, § 2.7) |
| LAN | Internet via pfSense | 80, 443, 53 | mises à jour | OK (règle LAN par défaut) |

À **ne pas** autoriser :

- Kali vers Wazuh ou pfSense (22, 443, 55000) : l'attaquant ne doit pas atteindre la
  supervision. Appliqué par les règles 3 (LAN), 4 (pfSense) et 5 (réseau WAN) de l'interface
  ATTACK, avec journal (writeup 05) ;
- Wazuh vers les postes : le manager reçoit, il n'initie rien ;
- Windows 11 vers Wazuh en SSH (22) : Windows est la **cible** du lab ; s'il est compromis, sa
  clé SSH donnerait l'accès au SIEM (mouvement latéral, T1021.004). **Décidé le 2026-10-21 :
  agent seulement (1514/1515)**, la clé déjà déposée est retirée (writeup 03, § 2.3).

![Matrice des flux du lab](diagrams/flux-lab.png)

Source du schéma : `diagrams/flux-lab.html`.

### Qui peut faire respecter cette matrice ?

Point clé : **pfSense ne voit pas le trafic interne au LAN**. Windows 11, Wazuh et l'hôte
sont sur le même switch virtuel (VMnet10, même sous-réseau `10.10.10.0/24`). Entre eux, les
paquets vont directement de machine à machine sans passer par la passerelle. Une règle pfSense
ne peut donc filtrer que :

- ce qui sort vers Internet ou le WAN ;
- ce qui vise pfSense lui-même (22, 443).

Pour filtrer à l'intérieur du LAN, deux options :

1. **Pare-feu local sur chaque machine** : `firewalld` sur Wazuh, qui n'accepte 22 que depuis
   l'hôte, 1514/1515 que depuis les agents et 514 que depuis pfSense ; pare-feu Windows sur
   Windows 11.
2. **Segmenter le réseau** (recommandé pour la suite) : mettre Kali sur un réseau virtuel séparé
   (par exemple VMnet11, une 3ᵉ carte sur pfSense), pour que ses attaques **traversent**
   pfSense. Elles sont alors filtrées, journalisées et visibles dans Wazuh, comme dans une vraie
   architecture où l'attaquant vient de l'extérieur. **Retenu et en place** (2026-10-22,
   [writeup 05](writeup/05-segment-attaque-kali.md)) : VMnet11 `10.10.20.0/24`, interface
   ATTACK (`em0`, `10.10.20.254`), 7 règles.

![Règles de l'interface ATTACK](diagrams/regles-attack.png)

Source du schéma : `diagrams/regles-attack.html`. Les flux internes au LAN (Windows 11, Wazuh,
hôte) relèvent toujours de l'option 1.
