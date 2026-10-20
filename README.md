# SIEM_PROJECT — Base de connaissance Wazuh

Base de connaissance pour **tester un SIEM Wazuh** en laboratoire : architecture,
installation, configuration des agents, cas de détection et validation par
simulation d'attaques.

> Statut : base documentaire initiale (synthèse des sources). Aucun lab n'a
> encore été déployé à partir de ce dépôt ; les valeurs marquées « à valider »
> restent à confirmer en pratique.

## Contenu

| Document | Sujet |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Composants Wazuh, flux de données, ports, topologie de lab cible |
| [docs/installation.md](docs/installation.md) | Prérequis, installation (OVA / all-in-one), agents, dépannage |
| [docs/detection.md](docs/detection.md) | Capacités de détection, intégrations, règles personnalisées, scénarios de test |
| [docs/sources.md](docs/sources.md) | Sources utilisées, ce qu'on en retient, limites |
| [CLAUDE.md](CLAUDE.md) | Objectif, conventions et règles de contribution (humains et Claude) |

## Version de référence

Wazuh **4.14** (branche documentée sur `documentation.wazuh.com/current` au
2026-10-20). Les commandes sont à revérifier si la version change.

## Démarrage rapide

1. Lire [docs/architecture.md](docs/architecture.md) pour choisir la topologie.
2. Suivre [docs/installation.md](docs/installation.md) pour le serveur puis les agents.
3. Dérouler les scénarios de [docs/detection.md](docs/detection.md) et consigner les résultats.
