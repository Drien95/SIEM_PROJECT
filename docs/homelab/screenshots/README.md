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
| 09 | [09-pfsense-wan-dhcp.png](09-pfsense-wan-dhcp.png) | WAN `vmx0` en DHCP (client) |
| 10 | [10-pfsense-choix-lan-vmx1.png](10-pfsense-choix-lan-vmx1.png) | Choix du LAN : `vmx1` (`00:0c:29:0e:fc:73`) |
| 11 | [11-pfsense-lan-ip-dhcp-avant.png](11-pfsense-lan-ip-dhcp-avant.png) | LAN en `10.10.10.254/24`, plage DHCP encore par défaut (192.168.1.x) |
| 12 | [12-pfsense-lan-ip-dhcp-10.10.10.png](12-pfsense-lan-ip-dhcp-10.10.10.png) | Plage DHCP corrigée : `10.10.10.100`–`10.10.10.199` |
| 13 | [13-pfsense-confirmation-interfaces.png](13-pfsense-confirmation-interfaces.png) | Confirmation : LAN = `vmx1`, WAN = `vmx0` |
| 14 | [14-pfsense-choix-install-ce.png](14-pfsense-choix-install-ce.png) | Pas d'abonnement Plus : « Install CE » |
| 15 | [15-pfsense-options-zfs-gpt.png](15-pfsense-options-zfs-gpt.png) | Système de fichiers ZFS, partitionnement GPT |
| 16 | [16-pfsense-zfs-stripe.png](16-pfsense-zfs-stripe.png) | ZFS en stripe (un seul disque) |
| 17 | [17-pfsense-disque-da0.png](17-pfsense-disque-da0.png) | Disque `da0` de 20 Go |
| 18 | [18-pfsense-version-2.9.0.png](18-pfsense-version-2.9.0.png) | Version pfSense CE 2.9.0 (stable) |
| 19 | [19-pfsense-console-installe.png](19-pfsense-console-installe.png) | pfSense 2.9.0 démarré : WAN `192.168.30.131/24` (DHCP), LAN `10.10.10.254/24` |
| 20 | [20-wazuh-echec-demarrage-featurecompat.png](20-wazuh-echec-demarrage-featurecompat.png) | « Failed to start the virtual machine » : correctif AMD (`featureCompat`) incompatible avec le matériel virtuel 20 |
| 21 | [21-wazuh-console-login-4.14.9.png](21-wazuh-console-login-4.14.9.png) | VM Wazuh 4.14.9 démarrée, invite de connexion |
| 22 | [22-pfsense-web-connexion.png](22-pfsense-web-connexion.png) | Interface web pfSense sur `https://10.10.10.254` |
| 23 | [23-pfsense-assistant-accueil.png](23-pfsense-assistant-accueil.png) | Assistant de configuration (pfSense CE) |
| 24 | [24-pfsense-assistant-general-dns.png](24-pfsense-assistant-general-dns.png) | Hostname `pfSense`, domaine `siem.lab`, DNS `1.1.1.1` / `9.9.9.9` |
| 25 | [25-pfsense-assistant-ntp-fuseau.png](25-pfsense-assistant-ntp-fuseau.png) | Serveur NTP et fuseau (passé ensuite à `Europe/Paris`) |
| 26 | [26-pfsense-assistant-wan-dhcp.png](26-pfsense-assistant-wan-dhcp.png) | WAN en DHCP |
| 27 | [27-pfsense-assistant-wan-dhcp-suite.png](27-pfsense-assistant-wan-dhcp-suite.png) | WAN : paramètres DHCP / PPPoE laissés vides |
| 28 | [28-pfsense-assistant-wan-rfc1918-bogons.png](28-pfsense-assistant-wan-rfc1918-bogons.png) | RFC1918 et bogons (valeurs par défaut ; RFC1918 ensuite décoché) |
| 29 | [29-pfsense-assistant-lan.png](29-pfsense-assistant-lan.png) | LAN `10.10.10.254/24` |
| 30 | [30-wazuh-console-connexion.png](30-wazuh-console-connexion.png) | Connexion console `wazuh-user` (bannière de l'OVA avec les identifiants par défaut publics) |
| 31 | [31-wazuh-dashboard-inactif.png](31-wazuh-dashboard-inactif.png) | `wazuh-indexer` actif, `wazuh-dashboard` « inactive (dead) » ; mémoire libre |
| 32 | [32-wazuh-dashboard-enable.png](32-wazuh-dashboard-enable.png) | `systemctl enable --now wazuh-dashboard` |
| 33 | [33-wazuh-flood-stage-read-only.png](33-wazuh-flood-stage-read-only.png) | Index patterns refusés : flood-stage watermark, index en lecture seule |
| 34 | [34-wazuh-disque-25g-plein.png](34-wazuh-disque-25g-plein.png) | `sda1` de 25 Go sur un disque de 50 Go, pleine à 100 % |
| 35 | [35-wazuh-growpart-xfs-growfs.png](35-wazuh-growpart-xfs-growfs.png) | `growpart` + `xfs_growfs` : `/` passe à 50 Go (51 %) |
| 36 | [36-wazuh-curl-all-403.png](36-wazuh-curl-all-403.png) | Déblocage sur `_all` refusé (403, index de sécurité protégé) |
| 37 | [37-wazuh-curl-index-acknowledged.png](37-wazuh-curl-index-acknowledged.png) | Déblocage sur `wazuh-*,.kibana*` : `{"acknowledged":true}` |

Captures volontairement **non versionnées** (mot de passe visible) : les sorties de
`wazuh-passwords-tool.sh` et de `filebeat test output` de 03:42, 03:43 et 03:47.
