# SIEM_PROJECT — Base de connaissance Wazuh

Laboratoire complet pour **évaluer le SIEM/XDR Wazuh** comme le ferait un analyste SOC. On y
monte une infrastructure isolée, on y branche des sources de journaux, puis on joue de vraies
attaques pour vérifier ce que Wazuh détecte, comment il corrèle et comment il réagit.

> **Statut au 2026-10-22** : le lab est monté et durci. Il comprend pfSense CE 2.9.0,
> Wazuh 4.14.9 (OVA), un agent Windows 11 avec Sysmon, et Kali sur un réseau d'attaque séparé.
> **Trois scénarios** ont été joués et validés en live, et une réponse active bloque
> automatiquement l'attaquant. Suite : voir la [roadmap](docs/roadmap.md).
> Toute affirmation non testée est marquée « à valider ».

## Le lab en un coup d'œil

![Topologie du lab : WAN, LAN et réseau d'attaque séparés par pfSense](docs/diagrams/topologie-lab.png)

| Machine | Rôle | Adresse |
|---|---|---|
| pfSense CE 2.9.0 | pare-feu, passerelle, source de journaux (syslog) | LAN `10.10.10.254`, ATTACK `10.10.20.254` |
| Wazuh 4.14.9 (OVA) | manager, indexer, dashboard | `10.10.10.100` |
| Windows 11 (SIEM-Win11) | poste supervisé : agent Wazuh, Sysmon | `10.10.10.101` |
| Kali Linux | attaquant, sur son propre réseau | `10.10.20.10` |

## Résultats

| # | Scénario | MITRE ATT&CK | Détection et réponse observées | Fiche |
|---|---|---|---|---|
| 1 | Brute force SMB sur Windows 11 | T1110, T1110.001, T1078 | 60122 par essai → 60204 (niv. 10) → **réponse active** : IP bloquée 180 s → **100400** (niv. 12) si un compte est ensuite ouvert | [brute-force-smb.md](docs/scenarios/brute-force-smb.md) |
| 2 | Scan de ports nmap à travers pfSense | T1046 | 100302 par paquet bloqué → **100303** (niv. 10, scan probable) | [scan-nmap.md](docs/scenarios/scan-nmap.md) |
| 3 | Fichier malveillant déposé (EICAR) | T1203 (natif), T1105 | FIM **554** (niv. 5) → VirusTotal **87105** (niv. 12, 66 moteurs) en ~6 s | [malware-fim-virustotal.md](docs/scenarios/malware-fim-virustotal.md) |

Couverture complète par tactique : [docs/mitre.md](docs/mitre.md).

## Lire le projet dans l'ordre

| Writeup | Sujet |
|---|---|
| [01 · Homelab](docs/writeup/01-homelab.md) | Montage VMware : pfSense, Wazuh, Windows 11 ; incidents et leçons |
| [02 · Syslog pfSense](docs/writeup/02-syslog-pfsense.md) | Journaux du pare-feu vers Wazuh, décodeur et règles locales |
| [03 · Durcissement SSH](docs/writeup/03-durcissement-ssh.md) | SSH par clé vers Wazuh et pfSense, mot de passe interdit (OVA en mode FIPS) |
| [04 · Agent Windows et Sysmon](docs/writeup/04-agent-windows-sysmon.md) | Agent Wazuh, incident « API Offline », Sysmon en configuration centralisée |
| [05 · Réseau d'attaque](docs/writeup/05-segment-attaque-kali.md) | Kali sur VMnet11 derrière pfSense, règles de l'interface ATTACK |
| [06 · Scénario 1 : brute force SMB](docs/writeup/06-scenario-brute-force-smb.md) | Première détection : 4625, 60122, 60204, pièges de préparation |
| [07 · Règles et réponse active](docs/writeup/07-regles-et-reponse-active.md) | Cours sur les règles, réponse active testée en live, règle locale 100400 |
| [08 · Scénario 2 : scan nmap](docs/writeup/08-scenario-scan-nmap.md) | pfSense comme témoin, 100302 et 100303, angle mort d'une règle |
| [09 · Scénario 3 : FIM + VirusTotal](docs/writeup/09-scenario-fim-virustotal.md) | EICAR détecté en ~6 s : 554 puis 87105, pièges Defender, `-NoNewline` et quota |
| [Annexe · Simulateur de paquets](docs/writeup/annexe-simulateur-paquets.md) | Simulateur façon Packet Tracer (ARP, DHCP, NAT, syslog, agent, Kali), avec vidéos |

## Documents de référence

| Document | Sujet |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Composants Wazuh, `ossec.conf` et chaîne des démons (cours), flux de données, ports, matrice des flux du lab |
| [docs/installation.md](docs/installation.md) | Prérequis, installation (OVA / all-in-one), agents, dépannage |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap en trois phases (largeur, profondeur, livrable), compétence SOC visée et statut de chaque étape |
| [docs/mitre.md](docs/mitre.md) | Couverture MITRE ATT&CK : techniques détectées, prévues, étiquettes natives à corriger |
| [docs/detection.md](docs/detection.md) | Capacités de détection, intégrations, règles personnalisées, scénarios de test |
| [docs/sources.md](docs/sources.md) | Sources utilisées, ce qu'on en retient, limites |
| [docs/homelab/plan.md](docs/homelab/plan.md) | Plan du homelab VMware : réseau, VM, ordre de montage, images |
| [docs/homelab/screenshots/](docs/homelab/screenshots/README.md) | Captures d'écran du montage, numérotées |
| [docs/diagrams/](docs/diagrams/README.md) | Schémas : réseau du lab façon Packet Tracer, règles pare-feu ATTACK, flux de détection du brute force SMB, couverture MITRE, chaîne des démons et carte complète de Wazuh, matrice des flux, pipeline Wazuh annoté, règle et réponse active, modèle de scénario (sources HTML et PNG) |
| [docs/integrations/](docs/integrations/) | Un guide par intégration : Windows/Sysmon, FIM, VirusTotal, Suricata, pfSense |
| [docs/scenarios/](docs/scenarios/README.md) | Index des scénarios : joués (brute force SMB, scan nmap), prévus, modèle de fiche |
| [configs/](configs/) | Configurations du lab : règles et décodeur locaux, syslog, réponse active (`block-ip-win`), agent Windows, pfSense, VirusTotal, Suricata |
| [docs/lab-marxgoo.md](docs/lab-marxgoo.md) | Notes de lecture des PDF du lab marxgoo, avec les erreurs corrigées |
| [CLAUDE.md](CLAUDE.md) | Objectif, conventions et règles de contribution (humains et Claude) |

## Version de référence

Wazuh **4.14** (branche documentée sur `documentation.wazuh.com/current` au
2026-10-20). Les commandes sont à revérifier si la version change.

## Reproduire le lab

1. [docs/homelab/plan.md](docs/homelab/plan.md) et [docs/architecture.md](docs/architecture.md) : réseau, VM, matrice des flux.
2. [docs/installation.md](docs/installation.md) puis les writeups 01 à 05 : serveur, agents, sources de journaux.
3. Les fiches de [docs/scenarios/](docs/scenarios/README.md) : jouer un scénario, comparer attendu et observé, consigner les résultats.

Sécurité : aucun secret dans le dépôt (mots de passe, `client.keys`, clés API, certificats) ;
les attaques ne visent que les machines du lab, sur des réseaux host-only.
