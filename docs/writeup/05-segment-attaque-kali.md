# Writeup 05 : un réseau d'attaque pour Kali, derrière pfSense

> Créer un troisième réseau virtuel, réservé à l'attaquant, que pfSense sépare du LAN. Les
> attaques de Kali traverseront alors le pare-feu, qui les filtrera et les journalisera.
> Document vivant : les étapes non encore réalisées sont marquées « à faire ».
>
> Versions : VMware Workstation 17.0.0, pfSense CE 2.9.0, Kali Linux (image VMware
> officielle), Wazuh 4.14.9.

## 1. Comprendre

### 1.1 Pourquoi un réseau à part

Si Kali était branché sur VMnet10, comme Windows 11 et Wazuh, ses paquets iraient directement
de machine à machine par le switch : pfSense ne verrait rien et ne pourrait rien bloquer
(cours du writeup 04, § 1.2, et [schéma des chemins](../diagrams/reseau-chemins.png)). En le
plaçant sur **son propre réseau**, `10.10.20.0/24`, chaque paquet vers le LAN doit passer par
sa **passerelle**, pfSense. On gagne trois choses :

- **filtrer** : la [matrice des flux](../architecture.md) devient applicable (Kali peut viser
  Windows 11, pas Wazuh ni pfSense) ;
- **journaliser** : chaque tentative passe par `filterlog`, donc par le syslog vers Wazuh
  (writeup 02) ;
- **ressembler au réel** : en entreprise, l'attaquant arrive d'un autre réseau (Internet, un
  VLAN invité, un poste compromis ailleurs), rarement du même switch que le SIEM.

### 1.2 Ce qu'on construit

| Élément | Valeur |
|---|---|
| Réseau VMware | **VMnet11**, host-only, `10.10.20.0/24`, **sans** carte sur l'hôte, **sans** DHCP VMware |
| pfSense | 3ᵉ carte `em0` → interface **OPT1** renommée **ATTACK**, `10.10.20.254/24` |
| DHCP | serveur DHCP de pfSense sur ATTACK, plage `10.10.20.100` à `.199` |
| Kali | carte réseau sur VMnet11, adresse reçue par DHCP |

Pourquoi **sans carte sur l'hôte** : l'hôte n'a rien à faire sur le réseau de l'attaquant. Avec
une carte, Kali pourrait joindre l'hôte directement, sans passer par pfSense.
Pourquoi **sans DHCP VMware** : c'est pfSense qui distribue les adresses, et il annonce
`10.10.20.254` comme passerelle. Deux serveurs DHCP sur un même réseau se contrediraient.

### 1.3 Les règles du pare-feu

Sur pfSense, les règles d'une interface s'appliquent au trafic qui **entre** par cette
interface, de **haut en bas** : la première qui correspond décide. Une interface neuve
(OPT) n'a **aucune** règle, donc tout est bloqué par défaut. On autorise seulement ce qu'il
faut, et on journalise (*Log packets*) ce qui compte pour Wazuh.

Règles de l'interface **ATTACK**, dans cet ordre :

| # | Action | Source | Destination | Port | Log | Pourquoi |
|---|---|---|---|---|---|---|
| 1 | Pass | ATTACK net | ATTACK address (`10.10.20.254`) | 53 TCP/UDP | non | DNS, pour que Kali résolve les noms |
| 2 | Pass | ATTACK net | `10.10.10.101` (Windows 11) | any | **oui** | les scénarios d'attaque, journalisés |
| 3 | Block | ATTACK net | LAN net (`10.10.10.0/24`) | any | **oui** | Wazuh, l'hôte et le reste du LAN : interdit |
| 4 | Block | ATTACK net | This Firewall (self) | any | **oui** | administration de pfSense (443, 22) : interdite |
| 5 | Block | ATTACK net | WAN net (`192.168.30.0/24`) | any | **oui** | l'hôte côté NAT : interdit |
| 6 | Pass | ATTACK net | any | 80, 443 TCP | non | mises à jour de Kali vers Internet |

Le sens retour (Windows 11 qui répond à Kali) est autorisé automatiquement : pfSense est
**stateful**, il mémorise chaque connexion ouverte et laisse passer ses réponses.

**Ordre** : la règle 2 doit précéder la règle 3, sinon le blocage du LAN entier masquerait
l'exception pour Windows 11.

## 2. Mise en œuvre

### 2.1 Créer VMnet11 (à faire)

*Edit > Virtual Network Editor > Change Settings* (droits administrateur), *Add Network…*
→ **VMnet11** :

- **Host-only** ;
- décocher *Connect a host virtual adapter to this network* ;
- décocher *Use local DHCP service to distribute IP address to VMs* ;
- *Subnet IP* `10.10.20.0`, *Subnet mask* `255.255.255.0` ;
- *Apply*.

Constaté le 2026-10-21 : VMnet11 existe dans le registre de VMware sans configuration (pas
de carte associée). Il faut donc bien le créer dans l'éditeur.

### 2.2 Ajouter la 3ᵉ carte à pfSense (à faire)

pfSense **éteint** (*Shut Down*, pas *Suspend*) : *VM > Settings > Add… > Network Adapter*,
*Custom* : **VMnet11**. Démarrer pfSense.

Constaté le 2026-10-21 : la carte apparaît comme **`em0`**, pas `vmx2`. VMware ajoute une
nouvelle carte avec le modèle par défaut **e1000** (pilote FreeBSD `em`), alors que les deux
premières sont des **vmxnet3** (pilote `vmx`). Les deux fonctionnent ; vmxnet3 est plus
performant. Pour l'uniformité, on pourrait mettre `ethernet2.virtualDev = "vmxnet3"` dans
`SIEM-pfSense.vmx`, VM éteinte, avant l'affectation (la carte deviendrait alors `vmx2`). Choix
du lab : on garde `em0`, suffisant pour du trafic de test.

### 2.3 Interface ATTACK et DHCP (à faire)

1. *Interfaces > Assignments* : ajouter `em0` → OPT1, *Save*.
2. *Interfaces > OPT1* : *Enable*, *Description* `ATTACK`, *IPv4 Configuration Type*
   **Static IPv4**, `10.10.20.254` / `24`, *Save*, *Apply Changes*.
3. *Services > DHCP Server > ATTACK* : *Enable*, plage `10.10.20.100` à `10.10.20.199`,
   *Save*.

### 2.4 Règles (à faire)

*Firewall > Rules > ATTACK*, créer les six règles du § 1.3 dans l'ordre (*Add* avec la flèche
vers le bas ajoute en fin de liste), cocher *Log packets that are handled by this rule* pour
2 à 5, puis *Apply Changes*.

### 2.5 Kali (à faire)

- Image : la **machine virtuelle VMware** officielle, sur https://www.kali.org/get-kali/
  (section *Virtual Machines*). Vérifier le **SHA256** affiché sur la page avant
  d'extraire, comme pour les autres images (writeup 01).
- Emplacement : `C:\VM\SIEM_LAB\SIEM-Kali\`, sur le **SSD** (le disque `D:` mécanique a déjà
  fait échouer Windows 11, writeup 01, § 11).
- Mémoire : **2 Go**. L'hôte a 32 Go, et seulement 2,5 Go libres avec les trois VM
  allumées (mesuré le 2026-10-21) : fermer les applications lourdes de l'hôte avant de
  démarrer Kali.
- Réseau : *Network Adapter* → *Custom* **VMnet11**, avant le premier démarrage.
- Premier démarrage : changer le mot de passe par défaut (`passwd`). Il ne va jamais dans
  git.

### 2.6 Vérifier (à faire)

Dans Kali :

```bash
ip -4 addr show eth0            # attendu : 10.10.20.1xx/24
ip route                        # attendu : default via 10.10.20.254
nc -zv -w 3 10.10.10.101 3389   # Windows 11 : la règle 2 laisse passer (le port peut être fermé)
nc -zv -w 3 10.10.10.100 443    # Wazuh : la règle 3 bloque, attendu « timed out »
```

Dans Wazuh, *Threat Hunting* : `rule.id:100302 and data.srcip:10.10.20.*`. Le blocage vers
Wazuh doit apparaître, avec l'interface ATTACK.

## 3. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| VMnet11 créé, sans carte hôte ni DHCP | oui | à faire |
| pfSense ATTACK `10.10.20.254` | interface active | à faire |
| Kali reçoit `10.10.20.1xx`, passerelle `.254` | oui | à faire |
| Kali → Windows 11 | autorisé, journalisé | à faire |
| Kali → Wazuh 443 | bloqué, alerte 100302 | à faire |
| Kali → administration pfSense | bloqué | à faire |

Sources :
https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html (ordre des règles,
première correspondance),
https://docs.netgate.com/pfsense/en/latest/interfaces/assign.html (affectation d'interfaces),
https://www.kali.org/docs/virtualization/import-premade-vmware/ (image VMware de Kali).
