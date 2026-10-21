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

## Journal de montage

Captures d'écran de chaque étape : [screenshots/](screenshots/README.md).

### 2026-10-21 — VM créées (non démarrées)

| VM | Fichier | État |
|---|---|---|
| SIEM-Wazuh | `D:\VM\SIEM_LAB\SIEM-Wazuh\SIEM-Wazuh.vmx` | OVA 4.14.9 importée (SHA512 vérifié), correctif AMD ajouté, `virtualHW.version` passé de 99 à 20, carte sur VMnet10. Original : `.vmx.orig`. |
| SIEM-pfSense | `D:\VM\SIEM_LAB\SIEM-pfSense\SIEM-pfSense.vmx` | 2 vCPU, 2 Go, 20 Go, UEFI ; `vmx0` = NAT (WAN), `vmx1` = VMnet10 (LAN) ; ISO Netgate Installer v1.2 montée. |
| SIEM-Win11 | `D:\VM\SIEM_LAB\SIEM-Win11\SIEM-Win11.vmx` | 2 vCPU, 4 Go, 64 Go NVMe, UEFI + Secure Boot, carte sur VMnet10 ; ISO Windows 11 FR (build 26300) montée. |

Pour ouvrir une VM : *File > Open* dans VMware, puis choisir le `.vmx`.

### Incident — plantage de VMware (0xc0000094)

À l'ouverture de SIEM-pfSense, VMware 17.0 a planté (« unrecoverable error (vmui) Exception
0xc0000094 », division entière par zéro). Le journal `vmware-ui-*.log` montre une division
de 2 (`numvcpus`) par 0 dans la page des paramètres.

Cause probable (déduite, pas confirmée par VMware) : `cpuid.coresPerSocket` absent alors que
`numvcpus` > 1. Correctif : ajout de `cpuid.coresPerSocket` dans SIEM-pfSense (2) et
SIEM-Wazuh (4). SIEM-Win11 l'avait déjà.

Deuxième erreur au démarrage : « No PCIe slot available for Ethernet0 ». Les cartes
`vmxnet3` / `e1000e` et le contrôleur NVMe se branchent sur des ports PCIe, qui n'existent pas
si le `.vmx` ne déclare pas de pont. Correctif : `pciBridge0` plus `pciBridge4` à `pciBridge7`
en `pcieRootPort` (8 fonctions chacun), ainsi que `vmci0` et `hpet0`, ajoutés aux 3 VM. Test :
SIEM-Win11 démarre et s'arrête proprement avec `vmrun`.

Les ponts ne suffisaient pas pour pfSense. Lors du premier démarrage raté, VMware avait inscrit
`ethernet0.pciSlotNumber = "21"` et `ethernet1.pciSlotNumber = "22"`, des emplacements PCI
classiques où une carte vmxnet3 ne peut pas se brancher. Une fois ces deux lignes supprimées,
VMware place les cartes en 160 et 192 (PCIe) : la VM démarre (testé avec `vmrun`).

Règles pour nos `.vmx` écrits à la main :
- toujours définir `numvcpus` **et** `cpuid.coresPerSocket` ;
- toujours déclarer les ponts PCIe (`pciBridge4` à `7`) ;
- fermer l'onglet de la VM dans VMware avant de modifier son `.vmx` ;
- après un démarrage raté, supprimer les `*.pciSlotNumber` que VMware a écrits.

### Installation de pfSense

Le **Netgate Installer** télécharge pfSense CE pendant l'installation : le WAN (`vmx0`, NAT)
doit avoir Internet.

1. Démarrer SIEM-pfSense et suivre l'installeur : WAN = `vmx0` (DHCP), LAN = `vmx1`.
2. Choisir **pfSense CE** et l'installation par défaut (ZFS).
3. Après le redémarrage, dans la console : option 2, LAN `10.10.10.254/24`, serveur DHCP
   activé sur `10.10.10.100`–`10.10.10.199`.
4. Depuis une VM du LAN : `https://10.10.10.254`, `admin` / `pfsense`, puis assistant et
   **changement du mot de passe**.

Les interfaces vmxnet3 s'appellent `vmx0` / `vmx1` sous pfSense. Le PDF marxgoo utilise des
cartes e1000, d'où ses noms `em0` / `em1`.

### Windows 11 sans vTPM

Workstation 17.0 n'offre un TPM virtuel que si la VM est chiffrée. Pour un lab, on
contourne la vérification au début de l'installation (à valider) :

1. Sur l'écran de sélection de langue : `Maj+F10`, puis `regedit`.
2. Créer la clé `HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig` avec les DWORD
   `BypassTPMCheck = 1` et `BypassSecureBootCheck = 1`.
3. Fermer, puis continuer l'installation. Choisir un **compte local** (« Je n'ai pas
   Internet » ou `oobe\bypassnro` si l'option manque).
