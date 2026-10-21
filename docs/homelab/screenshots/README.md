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

### Windows 11 (première tentative) et syslog pfSense

| # | Fichier | Étape |
|---|---|---|
| 38 | [38-win11-efi-network-timeout.png](38-win11-efi-network-timeout.png) | Win11 : le firmware EFI tente un démarrage réseau (« Time out ») |
| 39 | [39-win11-demarrage-iso.png](39-win11-demarrage-iso.png) | Win11 : démarrage sur l'ISO |
| 40 | [40-win11-langue.png](40-win11-langue.png) | Choix de la langue (Français) |
| 41 | [41-win11-labconfig-reg-add.png](41-win11-labconfig-reg-add.png) | `Maj+F10` : `reg add …\LabConfig` `BypassTPMCheck` et `BypassSecureBootCheck` |
| 42 | [42-win11-option-installation.png](42-win11-option-installation.png) | « Installer Windows 11 » |
| 43 | [43-win11-preparation.png](43-win11-preparation.png) | Préparation de l'installation |
| 44 | [44-win11-image-pro.png](44-win11-image-pro.png) | Image Windows 11 Professionnel |
| 45 | [45-win11-disque-64go.png](45-win11-disque-64go.png) | Disque NVMe de 64 Go non alloué |
| 46 | [46-win11-installation-en-cours.png](46-win11-installation-en-cours.png) | Installation en cours |
| 47 | [47-wazuh-remote-secure-1514.png](47-wazuh-remote-secure-1514.png) | Bloc `<remote>` existant (agents, TCP 1514) dans `ossec.conf` |
| 48 | [48-wazuh-remoted-514-firewalld-inactif.png](48-wazuh-remoted-514-firewalld-inactif.png) | `wazuh-remoted` écoute en UDP 514 ; `firewalld` inactif |
| 49 | [49-pfsense-remote-logging.png](49-pfsense-remote-logging.png) | pfSense : Remote Logging vers `10.10.10.100:514`, System et Firewall Events |
| 50 | [50-hote-ping-40-timeout.png](50-hote-ping-40-timeout.png) | Premier test : `ping -n 40`, timeouts de 4 s (rythme trop lent) |
| 51 | [51-win11-dialogue-mise-a-niveau.png](51-win11-dialogue-mise-a-niveau.png) | Win11 : redémarrage sur l'ISO, « mise à niveau » proposée |
| 52 | [52-win11-pas-de-chargeur.png](52-win11-pas-de-chargeur.png) | Win11 : « No compatible bootloader found » sur le NVMe, installation relancée |
| 53 | [53-wazuh-threat-hunting-vide.png](53-wazuh-threat-hunting-vide.png) | `rule.groups:pfsense` : aucun résultat |
| 54 | [54-wazuh-tcpdump-514.png](54-wazuh-tcpdump-514.png) | `tcpdump` : syslog de `10.10.10.254` reçu (~1/s) |
| 55 | [55-wazuh-tcpdump-bsd-sans-hostname.png](55-wazuh-tcpdump-bsd-sans-hostname.png) | `tcpdump -A` : ligne BSD sans hostname (`filterlog[34901]:`) |
| 56 | [56-wazuh-tcpdump-rfc5424.png](56-wazuh-tcpdump-rfc5424.png) | `tcpdump -A` : même événement en RFC 5424 |
| 57 | [57-wazuh-logtest-rfc5424-aucun-decodeur.png](57-wazuh-logtest-rfc5424-aucun-decodeur.png) | logtest RFC 5424 : seul le timestamp, « No decoder matched » |
| 58 | [58-wazuh-logtest-decodeur-pcre2-echec.png](58-wazuh-logtest-decodeur-pcre2-echec.png) | Décodeur local v1 (prematch PCRE2) : toujours « No decoder matched » |
| 59 | [59-wazuh-logtest-decodeur-local-ok.png](59-wazuh-logtest-decodeur-local-ok.png) | Décodeur local v2 : `pfsense-filterlog`, champs extraits, règle 100302 |
| 60 | [60-hote-ping-60-w200.png](60-hote-ping-60-w200.png) | `ping -n 60 -w 200` : 60 paquets bloqués |
| 61 | [61-wazuh-dashboard-17-alertes.png](61-wazuh-dashboard-17-alertes.png) | Threat Hunting : premières alertes 100302 |
| 62 | [62-wazuh-events-100302.png](62-wazuh-events-100302.png) | Events : alertes 100302 `192.168.30.1 -> 192.168.30.131 (icmp)` |
| 63 | [63-wazuh-alerte-100303.png](63-wazuh-alerte-100303.png) | **Alerte 100303** niveau 10 : « blocages répétés depuis 192.168.30.1 (scan probable) » |
