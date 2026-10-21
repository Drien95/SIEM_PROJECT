# Schémas

| Fichier | Contenu |
|---|---|
| `topologie-lab.html` | Source du schéma réseau du lab (SVG inline, style Cisco Packet Tracer). S'ouvre dans un navigateur, thème clair ou sombre. |
| `topologie-lab.png` | Capture du schéma (thème clair, 2x), insérée dans les writeups 01, 02 et 05. Trois réseaux : WAN, LAN, ATTACK (Kali sur VMnet11). |
| `regles-attack.html` / `.png` | Règles de l'interface ATTACK de pfSense lues de haut en bas, cinq paquets de Kali d'exemple (passe, bloqué, journalisé) et chemin des journaux jusqu'aux alertes 100301/100302/100303. Inséré dans le writeup 05, § 1.3, et `architecture.md`. |
| `pipeline-wazuh.html` / `.png` | Pipeline interne de Wazuh (remoted, analysisd et ses 3 phases, alerts.json, Filebeat, indexer, dashboard) avec une vraie ligne pfSense annotée. Inséré dans le writeup 02, § 1.1. |
| `scenario-modele.html` / `.png` | Modèle de planche « scénario d'attaque », piloté par l'objet `SCENARIO` du script ; pré-rempli avec le brute force. Voir `docs/scenarios/modele-scenario.md`. |
| `flux-lab.html` / `.png` | Matrice des flux (moindre privilège) : flux autorisés, prévus et interdits entre l'hôte, pfSense, Wazuh, Windows 11 et Kali (VMnet11, règles ATTACK). Insérée dans `architecture.md` et le writeup 03. PNG rendue par Edge headless (`--screenshot`, 2x, thème clair). |
| `simulateur-paquets.html` | Simulateur interactif façon Packet Tracer (mode Simulation) : 8 scénarios pas à pas avec les en-têtes des paquets. Enregistrements dans `videos/` (GIF + MP4). Voir l'[annexe du writeup](../writeup/annexe-simulateur-paquets.md). |
| `reseau-chemins.html` / `.png` | Cours réseau : même sous-réseau (ARP, switch) contre réseau routé (passerelle pfSense), et échange DHCP DORA. Inséré dans le writeup 04, § 1.2. |

Pour régénérer la PNG après modification du HTML : ouvrir la page dans Chromium et faire une
capture de l'élément `figure` (ou Playwright : `locator('figure').screenshot()`).
