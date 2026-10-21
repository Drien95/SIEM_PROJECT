# Schémas

| Fichier | Contenu |
|---|---|
| `topologie-lab.html` | Source du schéma réseau du lab (SVG inline, style Cisco Packet Tracer). S'ouvre dans un navigateur, thème clair ou sombre. |
| `topologie-lab.png` | Capture du schéma (thème clair, 2x), insérée dans les writeups 01 et 02. |
| `pipeline-wazuh.html` / `.png` | Pipeline interne de Wazuh (remoted, analysisd et ses 3 phases, alerts.json, Filebeat, indexer, dashboard) avec une vraie ligne pfSense annotée. Inséré dans le writeup 02, § 1.1. |
| `scenario-modele.html` / `.png` | Modèle de planche « scénario d'attaque », piloté par l'objet `SCENARIO` du script ; pré-rempli avec le brute force. Voir `docs/scenarios/modele-scenario.md`. |
| `flux-lab.html` / `.png` | Matrice des flux (moindre privilège) : flux autorisés, prévus et interdits entre l'hôte, pfSense, Wazuh, Windows 11 et Kali. Insérée dans `architecture.md` et le writeup 03. PNG rendue par Edge headless (`--screenshot`, 2x, thème clair). |
| `reseau-chemins.html` / `.png` | Cours réseau : même sous-réseau (ARP, switch) contre réseau routé (passerelle pfSense), et échange DHCP DORA. Inséré dans le writeup 04, § 1.2. |

Pour régénérer la PNG après modification du HTML : ouvrir la page dans Chromium et faire une
capture de l'élément `figure` (ou Playwright : `locator('figure').screenshot()`).
