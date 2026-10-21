# Schémas

| Fichier | Contenu |
|---|---|
| `topologie-lab.html` | Source du schéma réseau du lab (SVG inline, style Cisco Packet Tracer). S'ouvre dans un navigateur, thème clair ou sombre. |
| `topologie-lab.png` | Capture du schéma (thème clair, 2x), insérée dans les writeups 01 et 02. |

Pour régénérer la PNG après modification du HTML : ouvrir la page dans Chromium et faire une
capture de l'élément `#topologie` (ou Playwright : `locator('#topologie').screenshot()`).
