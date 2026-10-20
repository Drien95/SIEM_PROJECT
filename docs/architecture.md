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
| pfSense (optionnel) | Pare-feu, logs envoyés en syslog | marxgoo |

Hyperviseur : VMware Workstation ou VirtualBox. Réseau : mode **pont** (UsmanPrime) pour
que l'hôte joigne la VM, ou réseau host-only/NAT dédié pour isoler les attaques
(recommandation de notre part, à valider).
