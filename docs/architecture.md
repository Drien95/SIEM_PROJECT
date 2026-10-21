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
| Hôte `10.10.10.1` | pfSense `10.10.10.254` | 443/tcp, 22/tcp (clé) | administration | 443 OK, 22 à activer |
| Hôte `10.10.10.1` | Wazuh `10.10.10.100` | 443/tcp, 22/tcp (clé) | dashboard, administration | OK |
| pfSense `10.10.10.254` | Wazuh `10.10.10.100` | 514/udp | syslog du pare-feu | ✅ validé (writeup 02) |
| Windows 11 `10.10.10.101` | Wazuh `10.10.10.100` | 1514/tcp, 1515/tcp | agent : événements, enrôlement | à faire |
| Kali | Windows 11 | ports attaqués (22, 3389, 445…) | scénarios | plus tard |
| Hôte | Kali | 22/tcp | piloter Kali (optionnel) | plus tard |
| LAN | Internet via pfSense | 80, 443, 53 | mises à jour | OK (règle LAN par défaut) |

À **ne pas** autoriser :

- Kali vers Wazuh ou pfSense (22, 443, 55000) : l'attaquant ne doit pas atteindre la
  supervision ;
- Wazuh vers les postes : le manager reçoit, il n'initie rien ;
- Windows 11 vers Wazuh en SSH (22) : Windows est la **cible** du lab ; s'il est compromis, sa
  clé SSH donne l'accès au SIEM. Recommandation : agent seulement (1514/1515). Adrien a demandé
  ce flux ; à trancher, et si on le garde, révoquer la clé dès qu'elle ne sert plus.

### Qui peut faire respecter cette matrice ?

Point clé : **pfSense ne voit pas le trafic interne au LAN**. Windows 11, Wazuh, Kali et l'hôte
sont sur le même switch virtuel (VMnet10, même sous-réseau `10.10.10.0/24`). Entre eux, les
paquets vont directement de machine à machine sans passer par la passerelle. Une règle pfSense
ne peut donc filtrer que :

- ce qui sort vers Internet ou le WAN ;
- ce qui vise pfSense lui-même (22, 443).

Pour filtrer à l'intérieur du LAN, deux options (à décider) :

1. **Pare-feu local sur chaque machine** : `firewalld` sur Wazuh, qui n'accepte 22 que depuis
   l'hôte, 1514/1515 que depuis les agents et 514 que depuis pfSense ; pare-feu Windows sur
   Windows 11.
2. **Segmenter le réseau** (recommandé pour la suite) : mettre Kali sur un réseau virtuel séparé
   (par exemple VMnet11, une 3ᵉ carte sur pfSense), pour que ses attaques **traversent**
   pfSense. Elles sont alors filtrées, journalisées et visibles dans Wazuh, comme dans une vraie
   architecture où l'attaquant vient de l'extérieur.
