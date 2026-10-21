# Captures du montage

Captures d'écran du homelab, numérotées dans l'ordre du montage : un aide-mémoire, et la
trace du travail réalisé. Nommage : `NN-composant-etape.png`.

Source : `C:\Users\machn\Pictures\Screenshots` (Win+Maj+S). Claude les recopie ici après
chaque étape. On vérifie avant chaque commit qu'aucune capture ne montre de mot de passe ni
de clé API.

| # | Fichier | Étape |
|---|---|---|
| 01 | [01-pfsense-iso-netgate.png](01-pfsense-iso-netgate.png) | Choix de l'image pfSense : « AMD64 ISO IPMI/Virtual Machines » |
| 02 | [02-vmware-plantage-vmui-0xc0000094.png](02-vmware-plantage-vmui-0xc0000094.png) | Plantage de VMware à l'ouverture (`coresPerSocket` manquant) |
| 03 | [03-erreur-pcie-ethernet0-1.png](03-erreur-pcie-ethernet0-1.png) | « No PCIe slot available for Ethernet0 » (ponts PCIe absents) |
| 04 | [04-erreur-pcie-ethernet0-2.png](04-erreur-pcie-ethernet0-2.png) | Même erreur (emplacements PCI obsolètes 21 et 22) |
| 05 | [05-pfsense-carte-nat.png](05-pfsense-carte-nat.png) | Réglages VM pfSense : carte 1 en NAT (WAN) |
| 06 | [06-pfsense-carte-vmnet10.png](06-pfsense-carte-vmnet10.png) | Réglages VM pfSense : carte 2 sur VMnet10 (LAN) |
| 07 | [07-pfsense-invite-chargeur.png](07-pfsense-invite-chargeur.png) | Menu de démarrage, invite du chargeur (`OK`) |
| 08 | [08-pfsense-choix-wan-vmx0.png](08-pfsense-choix-wan-vmx0.png) | Netgate Installer : WAN = `vmx0` (`00:0c:29:0e:fc:69`) |
