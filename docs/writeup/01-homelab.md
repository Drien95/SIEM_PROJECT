# Writeup 01 : montage du homelab Wazuh sur VMware Workstation

> Rapport de montage du laboratoire SIEM : ce qui a été fait, dans quel ordre, avec les
> commandes exactes, les captures et les incidents rencontrés (cause, correctif, leçon).
> Document vivant, complété à chaque étape du lab.
>
> Auteur : Adrien, avec Claude. Dates : 2026-10-20 → en cours. Version Wazuh : **4.14.9**.

## Sommaire

1. [Objectif et périmètre](#1-objectif-et-périmètre)
2. [Architecture](#2-architecture)
3. [Préparation : images et intégrité](#3-préparation--images-et-intégrité)
4. [Création des VM](#4-création-des-vm)
5. [Incidents VMware : plantage et slots PCIe](#5-incidents-vmware--plantage-et-slots-pcie)
6. [pfSense : installation et assistant](#6-pfsense--installation-et-assistant)
7. [Wazuh : démarrage et correctif AMD](#7-wazuh--démarrage-et-correctif-amd)
8. [Wazuh : dashboard arrêté](#8-wazuh--dashboard-arrêté)
9. [Wazuh : disque plein et index en lecture seule](#9-wazuh--disque-plein-et-index-en-lecture-seule)
10. [Wazuh : changement des mots de passe](#10-wazuh--changement-des-mots-de-passe)
11. [État actuel et suite](#11-état-actuel-et-suite)
12. [Leçons retenues](#12-leçons-retenues)

---

## 1. Objectif et périmètre

Monter un laboratoire isolé pour **tester Wazuh** : collecte de journaux (Windows, Sysmon,
pfSense, Suricata), détection, puis validation par des attaques simulées depuis Kali. Les
attaques visent **uniquement** les VM du lab.

| Élément | Valeur |
|---|---|
| Hôte | Windows 11, AMD Ryzen 5 5600X (6c/12t), 32 Go de RAM |
| Hyperviseur | VMware Workstation Pro 17.0.0 |
| Stockage des VM | `D:\VM\SIEM_LAB\` (hors git) |
| Dépôt | `Drien95/SIEM_PROJECT` (documentation et configurations, aucun secret) |

## 2. Architecture

```
            Internet
               │
        VMnet8 (NAT 192.168.30.0/24)
               │ WAN (vmx0, DHCP : 192.168.30.131)
           ┌───┴────┐
           │pfSense │ LAN 10.10.10.254 : passerelle, DHCP .100-.199, DNS
           └───┬────┘
               │ LAN (vmx1) — VMnet10, host-only, 10.10.10.0/24
   ┌───────────┼──────────────┬───────────────┐
 Wazuh       Windows 11      Kali           Hôte (PC)
 10.10.10.100 (→ .10)  .20 (prévu)  .66 (prévu)  10.10.10.1
```

| VM | Image | vCPU | RAM | Disque | Réseau |
|---|---|---|---|---|---|
| SIEM-pfSense | Netgate Installer v1.2 → pfSense CE 2.9.0 | 2 | 2 Go | 20 Go | NAT + VMnet10 |
| SIEM-Wazuh | OVA 4.14.9 (Amazon Linux 2023) | 4 | 8 Go | 50 Go | VMnet10 |
| SIEM-Win11 | ISO Windows 11 FR (build 26300) | 2 | 4 Go | 64 Go NVMe | VMnet10 |
| Kali | VM Kali existante (à rebrancher sur VMnet10) | 2 | 4 Go | 80 Go | VMnet10 |

Choix :

- **VMnet10 en host-only, DHCP VMware désactivé** : c'est pfSense qui distribue les adresses. Le
  lab n'a pas d'accès direct à Internet ni au réseau domestique ; il sort par pfSense.
- L'hôte garde une patte sur VMnet10 (`10.10.10.1`) pour atteindre les interfaces web. En
  contrepartie, il est joignable depuis Kali : son pare-feu reste actif.

## 3. Préparation : images et intégrité

Images rangées dans `D:\VM\SIEM_LAB\images\`, exclues de git (`*.ova`, `*.iso` dans
`.gitignore`).

| Image | Source |
|---|---|
| `wazuh-4.14.9.ova` (4,8 Go) | https://packages.wazuh.com/4.x/vm/wazuh-4.14.9.ova |
| `netgate-installer-v1.2-RELEASE-amd64.iso` | https://www.pfsense.org/download/ |
| `Windows11_Client_x64_fr-fr_26300_9457.iso` | https://www.microsoft.com/software-download/windows11 |

Vérification de l'OVA avec la somme SHA512 publiée par Wazuh :

```bash
cd /d/VM/SIEM_LAB/images
curl -sO https://packages.wazuh.com/4.x/checksums/wazuh/4.14.9/wazuh-4.14.9.ova.sha512
echo "attendu: $(cut -d' ' -f1 wazuh-4.14.9.ova.sha512)"
echo "obtenu : $(sha512sum wazuh-4.14.9.ova | cut -d' ' -f1)"
```

Résultat : les deux empreintes sont identiques (`df1f3430…263346a7`).

Pour pfSense, on choisit l'image **AMD64 ISO IPMI/Virtual Machines** :

![Choix de l'image pfSense](../homelab/screenshots/01-pfsense-iso-netgate.png)

## 4. Création des VM

**Réseau** : VMnet10 créé dans l'éditeur de réseau virtuel de VMware (*Edit > Virtual Network
Editor*) en *Host-only*, case « Use local DHCP service » **décochée**, sous-réseau
`10.10.10.0`.

**Wazuh** : import de l'OVA avec l'`ovftool` livré avec Workstation, puis le `.vmx` est ajusté
à la main (matériel virtuel 20, carte sur VMnet10). L'original est gardé en `.vmx.orig`.

**pfSense et Windows 11** : `.vmx` écrits à la main, disques créés avec `vmware-vdiskmanager` :

```bash
VD='/d/Logiciel/VMware/vmware-vdiskmanager.exe'
"$VD" -c -s 20GB -a lsilogic -t 0 /d/VM/SIEM_LAB/SIEM-pfSense/SIEM-pfSense.vmdk
"$VD" -c -s 64GB -a lsilogic -t 0 /d/VM/SIEM_LAB/SIEM-Win11/SIEM-Win11.vmdk
```

`-t 0` crée un disque à allocation dynamique : il ne consomme sur D: que ce qui est écrit.

Extrait du `.vmx` de pfSense (version finale, après les correctifs de la section 5) :

```ini
virtualHW.version = "20"
guestOS = "freebsd13-64"
firmware = "efi"
numvcpus = "2"
cpuid.coresPerSocket = "2"
memsize = "2048"
ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.connectionType = "nat"         # WAN
ethernet1.present = "TRUE"
ethernet1.virtualDev = "vmxnet3"
ethernet1.connectionType = "custom"
ethernet1.vnet = "VMnet10"               # LAN
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
# … idem pour pciBridge5, 6 et 7
vmci0.present = "TRUE"
hpet0.present = "TRUE"
```

Les deux cartes de pfSense dans l'interface VMware :

| WAN (NAT) | LAN (VMnet10) |
|---|---|
| ![Carte NAT](../homelab/screenshots/05-pfsense-carte-nat.png) | ![Carte VMnet10](../homelab/screenshots/06-pfsense-carte-vmnet10.png) |

## 5. Incidents VMware : plantage et slots PCIe

### 5.1 Plantage de l'interface VMware (0xc0000094)

**Symptôme** : à l'ouverture de `SIEM-pfSense.vmx`, VMware plante avec « unrecoverable error
(vmui) Exception 0xc0000094 ».

![Plantage vmui](../homelab/screenshots/02-vmware-plantage-vmui-0xc0000094.png)

**Analyse** : `0xc0000094` est une division entière par zéro. Le journal
`vmware-ui-*.log` montre la page des paramètres CPU qui divise `numvcpus` (2) par un nombre de
cœurs par socket nul.

**Cause** (déduite, non confirmée par VMware) : `cpuid.coresPerSocket` absent alors que
`numvcpus` > 1.

**Correctif** :

```ini
cpuid.coresPerSocket = "2"   # pfSense ; "4" pour Wazuh
```

### 5.2 « No PCIe slot available for Ethernet0 »

![Erreur PCIe 1](../homelab/screenshots/03-erreur-pcie-ethernet0-1.png)

**Cause** : les cartes `vmxnet3` / `e1000e` et le contrôleur NVMe se branchent sur des ports
PCIe. Un `.vmx` écrit à la main n'en déclare aucun.

**Correctif 1** : déclarer les ponts PCIe (`pciBridge0`, puis `pciBridge4` à `7` en
`pcieRootPort` avec 8 fonctions), plus `vmci0` et `hpet0`. Windows 11 démarre ensuite :

```bash
VMRUN='/d/Logiciel/VMware/vmrun.exe'
"$VMRUN" -T ws start /d/VM/SIEM_LAB/SIEM-Win11/SIEM-Win11.vmx nogui
"$VMRUN" -T ws stop  /d/VM/SIEM_LAB/SIEM-Win11/SIEM-Win11.vmx hard
```

**Correctif 2** (pfSense seulement) : l'erreur persistait.

![Erreur PCIe 2](../homelab/screenshots/04-erreur-pcie-ethernet0-2.png)

Lors du premier démarrage raté, VMware avait écrit `ethernet0.pciSlotNumber = "21"` et
`ethernet1.pciSlotNumber = "22"` : des emplacements PCI classiques, incompatibles avec
vmxnet3. Une fois ces deux lignes supprimées, VMware attribue `160` et `192` (ports PCIe) et la
VM démarre.

```bash
sed -i '/^ethernet[01]\.pciSlotNumber/d' /d/VM/SIEM_LAB/SIEM-pfSense/SIEM-pfSense.vmx
```

## 6. pfSense : installation et assistant

### 6.1 Installation (Netgate Installer v1.2)

Le Netgate Installer **télécharge** pfSense CE pendant l'installation : le WAN doit avoir
Internet (ici par le NAT de VMware).

| Étape | Capture |
|---|---|
| Invite du chargeur | ![](../homelab/screenshots/07-pfsense-invite-chargeur.png) |
| WAN = `vmx0` | ![](../homelab/screenshots/08-pfsense-choix-wan-vmx0.png) |
| WAN en DHCP | ![](../homelab/screenshots/09-pfsense-wan-dhcp.png) |
| LAN = `vmx1` | ![](../homelab/screenshots/10-pfsense-choix-lan-vmx1.png) |
| LAN `10.10.10.254/24`, plage DHCP encore par défaut | ![](../homelab/screenshots/11-pfsense-lan-ip-dhcp-avant.png) |
| Plage DHCP corrigée `10.10.10.100`–`.199` | ![](../homelab/screenshots/12-pfsense-lan-ip-dhcp-10.10.10.png) |
| Confirmation des interfaces | ![](../homelab/screenshots/13-pfsense-confirmation-interfaces.png) |
| « Install CE » (pas d'abonnement Plus) | ![](../homelab/screenshots/14-pfsense-choix-install-ce.png) |
| ZFS, GPT | ![](../homelab/screenshots/15-pfsense-options-zfs-gpt.png) |
| ZFS stripe (un disque) | ![](../homelab/screenshots/16-pfsense-zfs-stripe.png) |
| Disque `da0` 20 Go | ![](../homelab/screenshots/17-pfsense-disque-da0.png) |
| Version 2.9.0 | ![](../homelab/screenshots/18-pfsense-version-2.9.0.png) |

Résultat : pfSense CE 2.9.0 démarré, WAN `192.168.30.131/24` (DHCP), LAN `10.10.10.254/24`.

![Console pfSense installée](../homelab/screenshots/19-pfsense-console-installe.png)

À noter : sous pfSense, les cartes vmxnet3 s'appellent `vmx0` / `vmx1`. Le PDF du lab
marxgoo parle de `em0` / `em1` parce qu'il utilise des cartes e1000.

Contrôle depuis l'hôte :

```powershell
Test-NetConnection 10.10.10.254 -Port 443   # TcpTestSucceeded : True
```

### 6.2 Assistant web (`https://10.10.10.254`)

![Connexion web](../homelab/screenshots/22-pfsense-web-connexion.png)

| Paramètre | Valeur | Capture |
|---|---|---|
| Hostname / domaine | `pfSense` / `siem.lab` | ![](../homelab/screenshots/24-pfsense-assistant-general-dns.png) |
| DNS | `1.1.1.1`, `9.9.9.9` | (même capture) |
| Fuseau | `Europe/Paris` | ![](../homelab/screenshots/25-pfsense-assistant-ntp-fuseau.png) |
| WAN | DHCP | ![](../homelab/screenshots/26-pfsense-assistant-wan-dhcp.png) |
| Block RFC1918 | **décoché** | ![](../homelab/screenshots/28-pfsense-assistant-wan-rfc1918-bogons.png) |
| Block bogons | coché | (même capture) |
| LAN | `10.10.10.254/24` | ![](../homelab/screenshots/29-pfsense-assistant-lan.png) |
| Mot de passe `admin` | changé (hors git) | — |

**Pourquoi décocher RFC1918** : le WAN de pfSense est lui-même sur un réseau privé (VMnet8,
`192.168.30.0/24`). Bloquer les adresses RFC1918 en entrée sur le WAN couperait le trafic
venant de la passerelle NAT de VMware.

## 7. Wazuh : démarrage et correctif AMD

La documentation Wazuh propose, pour les CPU AMD sous VMware, d'ajouter des lignes `cpuid.*`
et `featureCompat.enable` au `.vmx`. Appliquées par précaution, elles **empêchent** le
démarrage :

![Échec featureCompat](../homelab/screenshots/20-wazuh-echec-demarrage-featurecompat.png)

Journal (`vmware.log`) : « Disabling featureCompat.enable is not allowed for HWversion >= 9 ».

**Correctif** : retirer ces lignes. La VM démarre sur le Ryzen 5 5600X sans l'erreur « The guest
operating system has disabled the CPU ». Le correctif vise donc d'anciens matériels virtuels ou
d'anciens CPU AMD (déduit).

**Leçon** : n'appliquer un correctif de documentation que si le symptôme qu'il traite apparaît.

![Console Wazuh](../homelab/screenshots/21-wazuh-console-login-4.14.9.png)

Wazuh obtient `10.10.10.100` par le DHCP de pfSense (MAC `00:0c:29:9f:81:64`).

![Connexion console](../homelab/screenshots/30-wazuh-console-connexion.png)

La bannière affiche les identifiants **par défaut et publics** de l'OVA (`wazuh-user` /
`wazuh`), identiques sur toutes les copies : à changer (`passwd`).

## 8. Wazuh : dashboard arrêté

**Symptôme** : le manager (1514) et l'API (55000) répondent, mais pas le dashboard (443).

```bash
sudo systemctl status wazuh-indexer wazuh-dashboard --no-pager | grep -E "●|Active"
free -h
```

![Dashboard inactif](../homelab/screenshots/31-wazuh-dashboard-inactif.png)

`wazuh-indexer` est actif, `wazuh-dashboard` est « inactive (dead) ». La mémoire n'est pas en
cause (2,6 Gio disponibles).

**Correctif** :

```bash
sudo systemctl enable --now wazuh-dashboard
```

![enable --now](../homelab/screenshots/32-wazuh-dashboard-enable.png)

La création du lien symbolique montre que le service **n'était pas activé** au démarrage.
Contrôle depuis l'hôte :

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://10.10.10.100/app/login   # 200
```

## 9. Wazuh : disque plein et index en lecture seule

**Symptôme** : à la première connexion, le dashboard ne peut pas créer ses index patterns :

![Flood stage](../homelab/screenshots/33-wazuh-flood-stage-read-only.png)

```
index [.kibana_1] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded
flood-stage watermark, index has read-only-allow-delete block]
```

**Diagnostic** :

```bash
df -h /
lsblk
sudo du -xh --max-depth=1 /var | sort -h | tail -5
```

![Disque plein](../homelab/screenshots/34-wazuh-disque-25g-plein.png)

**Cause** : dans l'OVA 4.14.9, le disque `sda` fait 50 Go mais la partition racine `sda1` n'en
couvre que **25 Go**. Elle est pleine à 100 % (33 Mo libres), dont 21 Go dans `/var/ossec`. Au-delà
de 95 % d'occupation (*flood stage*), OpenSearch passe les index en
`read-only-allow-delete` pour se protéger.

**Correctif 1 : étendre la partition et le système de fichiers** (XFS, à chaud) :

```bash
sudo journalctl --vacuum-size=50M     # libérer quelques Mo pour que growpart puisse travailler
sudo dnf clean all
sudo growpart /dev/sda 1              # sda1 : 52 404 191 → 104 832 991 secteurs
sudo xfs_growfs /                     # le système de fichiers suit la partition
df -h /                               # 50G, 26G utilisés, 25G libres (51 %)
sudo du -xh --max-depth=2 /var/ossec | sort -h | tail -8
```

![growpart et xfs_growfs](../homelab/screenshots/35-wazuh-growpart-xfs-growfs.png)

Répartition de `/var/ossec` (21 Go) : `queue/vd` 9,1 Go (base de vulnérabilités, normal) et
`tmp` 9,7 Go (probablement l'import de cette base ; à vérifier qu'il se vide).

**Correctif 2 : lever le blocage des index**. Première tentative, sur tous les index :

```bash
curl -k -u admin -X PUT "https://localhost:9200/_all/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
```

![403 sur _all](../homelab/screenshots/36-wazuh-curl-all-403.png)

Réponse **403 `security_exception`** : `_all` inclut l'index de sécurité de l'indexeur, que même
`admin` ne peut pas modifier. On cible donc seulement les index concernés :

```bash
curl -k -u admin -X PUT "https://localhost:9200/wazuh-*,.kibana*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
```

![acknowledged](../homelab/screenshots/37-wazuh-curl-index-acknowledged.png)

Réponse : `{"acknowledged":true}`. `-u admin` sans mot de passe dans la commande : curl le
demande à l'invite, il ne reste donc pas dans l'historique du shell.

## 10. Wazuh : changement des mots de passe

Les identifiants par défaut de l'OVA (`admin` / `admin` pour le dashboard) sont publics : on les
change avec l'outil officiel.

```bash
sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -u admin -p '<NOUVEAU_MOT_DE_PASSE>'
sudo filebeat test output
```

Contraintes de l'outil : 8 à 64 caractères, majuscule, minuscule, chiffre et symbole, pris
**uniquement** parmi `.*+?-`.

Incidents :

1. Premier essai refusé : le mot de passe contenait `#`, qui n'est pas dans la liste des
   symboles acceptés.
2. Deuxième essai lancé **pendant que le disque était plein** : l'outil met à jour le keystore
   de Filebeat, puis échoue sur « Could not load the changes ». Filebeat et l'indexeur ne
   partagent alors plus le même mot de passe.
3. Après l'extension du disque et le déblocage des index, l'outil termine sur « Password
   changed ». `filebeat test output` va jusqu'à `talk to server... OK` (TLS 1.2, version 7.10.2).
4. Juste après, `https://10.10.10.100` renvoie `{"statusCode":500,"error":"Internal Server
   Error"}`. Cause : le navigateur (Brave) présente le cookie d'une session ouverte avec
   l'ancien mot de passe. Correctif : supprimer les cookies du site, ou ouvrir une fenêtre
   privée, puis se reconnecter. Le dashboard s'affiche normalement.

> Les captures de cette étape ne sont **pas versionnées** : le mot de passe y apparaît en
> clair. Bonne pratique : ne pas passer le mot de passe en argument (il reste dans
> `~/.bash_history` et dans `ps`), ou purger l'historique ensuite (`history -c`, puis
> nettoyer `~/.bash_history`).

## 11. État actuel et suite

| Composant | État |
|---|---|
| VMnet10 | ✅ host-only, DHCP VMware désactivé |
| pfSense CE 2.9.0 | ✅ installé, assistant fait, mot de passe changé |
| Wazuh 4.14.9 | ✅ services actifs, disque étendu, index débloqués, mot de passe `admin` changé, Filebeat OK, connexion au dashboard OK |
| Windows 11 | 🔄 installation en cours |
| Kali | ⏳ à rebrancher sur VMnet10 |

Prochaines étapes :

1. Windows 11 : contournement TPM (`LabConfig`), compte local.
2. Réservations DHCP dans pfSense : Wazuh `10.10.10.10`, Windows `10.10.10.20`, Kali `10.10.10.66`.
3. Agent Wazuh + Sysmon + OpenSSH sur Windows ([intégration](../integrations/windows-logs-sysmon.md)).
4. Syslog pfSense, FIM, VirusTotal, Suricata.
5. Premier scénario : [brute force](../scenarios/brute-force.md).

## 12. Leçons retenues

| # | Leçon |
|---|---|
| 1 | Dans un `.vmx` écrit à la main, toujours déclarer `cpuid.coresPerSocket` et les ponts PCIe (`pciBridge4-7`). |
| 2 | Après un démarrage raté, supprimer les `*.pciSlotNumber` que VMware a écrits. |
| 3 | N'appliquer un correctif de documentation (ex. AMD) que si son symptôme apparaît. |
| 4 | Après l'import de l'OVA Wazuh, vérifier `lsblk` / `df -h` **avant** de laisser tourner les services : la partition ne couvre que la moitié du disque. |
| 5 | Ne jamais lancer d'outil qui modifie la configuration sur un disque plein : il peut échouer à mi-parcours et laisser un état incohérent. |
| 6 | Sur OpenSearch, viser des motifs d'index précis plutôt que `_all` (index de sécurité protégé). |
| 7 | Aucun mot de passe en clair dans les captures, l'historique ou git. |
| 8 | Après un changement de mot de passe, une erreur 500 du dashboard peut venir du cookie de l'ancienne session : essayer d'abord une fenêtre privée. |

Sources : [docs/sources.md](../sources.md) ; journal détaillé :
[docs/homelab/plan.md](../homelab/plan.md).
