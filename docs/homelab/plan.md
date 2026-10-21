# Plan du homelab (VMware Workstation Pro)

Statut : **proposition**, à valider au montage. Les écarts constatés se notent ici.

## Hôte

| Élément | Valeur |
|---|---|
| CPU | AMD Ryzen 5 5600X (6 cœurs / 12 threads) |
| RAM | 32 Go |
| Hyperviseur | VMware Workstation Pro 17.0.0 (`D:\Logiciel\VMware\`, avec `vmrun.exe` et `OVFTool\ovftool.exe`) |
| Dossier des VM | `D:\VM\SIEM_LAB\` (hors dépôt git ; ~343 Go libres sur D:) |

## Réseau

| Réseau VMware | Type | Sous-réseau | Rôle |
|---|---|---|---|
| VMnet8 (existant) | NAT | 192.168.30.0/24 | WAN de pfSense, accès Internet |
| **VMnet10** (à créer) | Host-only, **DHCP VMware désactivé** | 10.10.10.0/24 | LAN du lab, derrière pfSense |

L'adaptateur hôte VMnet10 reste connecté pour que le PC atteigne le dashboard. En
contrepartie, le PC est joignable depuis Kali : le pare-feu Windows de l'hôte doit rester
actif. Les attaques visent uniquement les VM.

```
            Internet
               │
        VMnet8 (NAT 192.168.30.0/24)
               │ WAN
           ┌───┴────┐
           │pfSense │ 10.10.10.254 (passerelle, DHCP, DNS)
           └───┬────┘
               │ LAN — VMnet10 (10.10.10.0/24)
   ┌───────────┼──────────────┬───────────────┐
 Wazuh       Windows 11      Kali           Hôte (PC)
 10.10.10.10 10.10.10.20     10.10.10.66    10.10.10.1
```

## VM

| VM | Image | vCPU | RAM | Disque | IP |
|---|---|---|---|---|---|
| pfSense | ISO pfSense CE | 1 | 1 Go | 20 Go | WAN DHCP / LAN 10.10.10.254 |
| Wazuh | OVA 4.14.9 (Amazon Linux 2023) | 4 | 8 Go | 50 Go | 10.10.10.10 (statique) |
| Windows 11 | ISO Microsoft | 2 | 4 Go | 64 Go | 10.10.10.20 (réservation DHCP) |
| Kali | Image VMware officielle | 2 | 4 Go | 80 Go | 10.10.10.66 (réservation DHCP) |
| **Total** | | 9 | 17 Go | ~215 Go (alloués à la demande) | |

Il reste environ 15 Go de RAM pour l'hôte.

## Ordre de montage

1. **Réseau** : créer VMnet10 (Éditeur de réseau virtuel) en host-only, DHCP désactivé.
2. **pfSense** : WAN sur VMnet8, LAN sur VMnet10 ; changer `admin`/`pfsense` ; DHCP
   10.10.10.100-199 et réservations. Voir [../integrations/pfsense.md](../integrations/pfsense.md).
3. **Wazuh** : import de l'OVA. **CPU AMD** : ajouter les lignes `cpuid.*` et
   `featureCompat.enable = "FALSE"` à la fin du `.vmx` **avant le premier démarrage**, sinon
   l'erreur « The guest operating system has disabled the CPU » apparaît (doc officielle,
   section dépannage VMware). Carte réseau sur VMnet10, IP statique ; changer
   `wazuh-user`/`wazuh` et `admin`/`admin`.
4. **Windows 11** : agent Wazuh, Sysmon, OpenSSH Server. Voir
   [../integrations/windows-logs-sysmon.md](../integrations/windows-logs-sysmon.md).
5. **Kali** : outils d'attaque (Hydra, nmap).
6. **Intégrations** : syslog pfSense, FIM, VirusTotal, puis Suricata.
7. **Scénarios** : [../scenarios/brute-force.md](../scenarios/brute-force.md) en premier.

Chaque étape se termine par un contrôle : services actifs, agent `Active`, alerte de test
visible dans *Threat Hunting*.

## Images à récupérer

| Image | Source | Taille | Intégrité |
|---|---|---|---|
| Wazuh OVA 4.14.9 | https://packages.wazuh.com/4.x/vm/wazuh-4.14.9.ova | 4,8 Go | SHA512 : https://packages.wazuh.com/4.x/checksums/wazuh/4.14.9/wazuh-4.14.9.ova.sha512 |
| pfSense CE | https://www.pfsense.org/download/ (installeur Netgate) | ~0,5-1 Go | SHA256 publié |
| Windows 11 | https://www.microsoft.com/software-download/windows11 | ~6 Go | — |
| Kali (VMware) | https://www.kali.org/get-kali/#kali-virtual-machines | ~3 Go (7z) | SHA256 publié |

Une VM Kali 2024.3 existe déjà dans `D:\VM\kali-linux-2024.3-vmware-amd64.vmwarevm` :
on peut la réutiliser, en passant sa carte réseau sur VMnet10 pendant les tests.

Les images restent dans `D:\VM\SIEM_LAB\images\`, hors git (`*.ova` et `*.iso` sont dans
`.gitignore`).
