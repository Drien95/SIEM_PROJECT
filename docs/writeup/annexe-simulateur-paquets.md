# Annexe : simulateur de paquets du lab

> Un simulateur interactif, façon mode « Simulation » de Cisco Packet Tracer, pour voir paquet
> par paquet ce qui circule dans le homelab : en-têtes, équipements traversés, décisions.
> Document vivant, à compléter quand le lab change (segment Kali, Suricata).
>
> Versions : pfSense CE 2.9.0, Wazuh 4.14.9, Windows 11. Source :
> [`docs/diagrams/simulateur-paquets.html`](../diagrams/simulateur-paquets.html).

![Simulateur : scénario ARP](../diagrams/videos/arp.gif)

## 1. Comprendre

### 1.1 Ce que c'est

Une page web autonome (un seul fichier HTML, aucun serveur) qui dessine la topologie du lab et
anime les paquets. On choisit un scénario, puis on avance étape par étape. Pour chaque étape :

- **le canevas** montre l'enveloppe du paquet qui se déplace, l'équipement concerné entouré, et
  le sort du paquet à l'arrivée (reçu, ignoré, bloqué, sans réponse) ;
- **le panneau « Le paquet sur le câble »** détaille les en-têtes couche par couche (Ethernet,
  IPv4, UDP ou TCP, puis le protocole applicatif). Quand un équipement **réécrit** le paquet
  (routage, NAT), les champs modifiés sont surlignés ;
- **les tables** (cache ARP, table MAC du switch, baux DHCP, table d'états de pfSense) évoluent
  au fil des étapes ;
- **la liste des événements** reprend le principe de Packet Tracer : un paquet par ligne, cliquable ;
- **« Pour l'analyste SOC »** dit ce que le scénario apporte à la détection, et **« Le voir dans le
  vrai lab »** donne les commandes pour vérifier sur les VM.

### 1.2 Pourquoi

Les schémas statiques ([topologie](../diagrams/topologie-lab.png),
[chemins réseau](../diagrams/reseau-chemins.png), [matrice des flux](../diagrams/flux-lab.png))
disent **où** passent les flux. Ils ne montrent pas **comment** : qui demande la MAC, pourquoi
pfSense ne voit pas le trafic local, ce que change le NAT, pourquoi un journal syslog peut se
perdre sans bruit. Or un analyste SOC lit des alertes qui ne contiennent que des adresses et des
ports : comprendre le trajet des paquets, c'est savoir **ce que chaque source de journaux peut
voir ou non**, et donc où chercher.

### 1.3 Les notions à retenir

| Notion | En une phrase | Scénario |
|---|---|---|
| Encapsulation | Chaque couche ajoute son en-tête : Ethernet (MAC) autour d'IP (adresses) autour de TCP/UDP (ports) autour des données. | tous |
| Switch | Livre une trame d'après la **MAC** de destination ; apprend les MAC en lisant la source ; inonde tous les ports s'il ne sait pas (ou si c'est une diffusion). | ARP |
| ARP | Traduit une IP du réseau local en MAC : question en diffusion, réponse en unicast. Aucune authentification. | ARP, DHCP |
| Masque et passerelle | Avec le masque, la machine décide si la cible est locale (envoi direct) ou distante (envoi à la passerelle). | ARP, Internet, APIPA |
| Couche 2 contre couche 3 | En routage, l'**IP** de destination reste la cible finale, la **MAC** de destination est le prochain saut. | Internet, Kali |
| DHCP (DORA) | Discover, Offer, Request, Ack : le client sans adresse obtient IP, masque, passerelle et DNS. | DHCP |
| APIPA | Sans réponse DHCP, Windows se donne une adresse `169.254.x.x` qui ne mène nulle part. | APIPA |
| NAT | pfSense remplace l'IP privée par celle de son WAN ; VMware puis la box refont la même chose. | Internet |
| Pare-feu à états | Les réponses à une connexion sortante rentrent sans règle ; le reste du trafic entrant est bloqué. | Internet, syslog |
| Syslog UDP | Pas d'accusé de réception : un journal perdu l'est en silence. | syslog |
| Agent Wazuh | Enrôlement sur 1515 (ID + clé), puis événements chiffrés AES sur 1514. | agent |
| SSH par clé | Seule une signature voyage, la clé privée reste sur l'hôte. | SSH |
| Segmentation | Un réseau séparé force l'attaquant à traverser pfSense, qui filtre et journalise. | Kali |

## 2. Utiliser le simulateur

1. Ouvrir [`docs/diagrams/simulateur-paquets.html`](../diagrams/simulateur-paquets.html) dans un
   navigateur (double-clic sur le fichier en local, après `git pull`). Une version publiée existe
   aussi en Artifact privé : https://claude.ai/artifact/HWnLujA9XGeerQn3Zx9ehx
2. Choisir un scénario en haut.
3. **Lecture** déroule tout ; **Suivant** / **Précédent** avancent d'une étape ; un clic sur une
   ligne de la liste d'événements y saute. Clavier : espace (lecture/pause), flèches.
4. Vitesse 0,5× pour lire, 2× pour revoir.
5. Lien direct vers un scénario : ajouter `#arp`, `#dhcp`, `#apipa`, `#internet`, `#syslog`,
   `#agent`, `#ssh` ou `#kali` à l'adresse.

## 3. Les scénarios

Chaque scénario a deux enregistrements, produits avec Playwright à partir du même fichier HTML
(voir § 5) : un **GIF accéléré ×2** affiché ci-dessous, et un **MP4 à vitesse réelle** (environ
1 min, à mettre en pause pour lire le panneau).

### 3.1 ARP et trafic local : Windows 11 pingue Wazuh

Windows constate que `10.10.10.100` est dans son `/24`, demande la MAC par ARP (diffusion), le
switch inonde, Wazuh répond en unicast, puis le ping va directement. pfSense ne voit que la
diffusion ARP : **le trafic est-ouest échappe au pare-feu**.

![ARP et trafic local](../diagrams/videos/arp.gif)

[MP4](../diagrams/videos/arp.mp4)

**Valeur SOC** : pour voir ce trafic, il faut des sources sur les machines (agent, Sysmon
événement 3). ARP sans authentification permet l'empoisonnement (T1557.002) : une IP qui change
de MAC est un indicateur.

### 3.2 DHCP (DORA)

Discover et Request en diffusion depuis `0.0.0.0`, Offer et Ack de pfSense avec IP, masque,
passerelle, DNS et domaine `siem.lab`, puis sonde ARP anti-conflit.

![DHCP DORA](../diagrams/videos/dhcp.gif)

[MP4](../diagrams/videos/dhcp.mp4)

**Valeur SOC** : le bail relie IP, MAC et nom de machine à un instant donné ; sans historique DHCP,
une alerte qui ne donne qu'une IP ne désigne aucun poste. Un serveur DHCP pirate (T1557.003) peut
se déclarer passerelle.

### 3.3 DHCP sans pfSense (APIPA)

Le vrai incident du writeup 01 : pfSense éteint, aucune Offer, Windows prend `169.254.x.x`, et le
ping vers Wazuh échoue **sans rien envoyer** (pas de route).

![APIPA](../diagrams/videos/apipa.gif)

[MP4](../diagrams/videos/apipa.mp4)

**Valeur SOC** : un poste en APIPA est coupé ; son agent passe « Disconnected » (règle 504).
Plusieurs postes à la fois : DHCP en panne ou épuisé.

### 3.4 Sortie vers Internet : routage et NAT

Windows télécharge l'agent depuis `packages.wazuh.com` (writeup 04). Requête DNS à pfSense, puis
SYN avec **MAC de pfSense mais IP du site**. pfSense applique la règle LAN, route vers
`192.168.30.2`, traduit `10.10.10.101:50123` en `192.168.30.131:41722` ; VMware et la box
traduisent à leur tour. La réponse rentre grâce à la table d'états.

![Routage et NAT](../diagrams/videos/internet.gif)

[MP4](../diagrams/videos/internet.mp4)

**Valeur SOC** : vu d'Internet, tout vient de l'IP publique ; retrouver le poste demande la table
d'états ou filterlog de pfSense, puis le bail DHCP. La sortie est l'endroit où se voient les
communications de commande et contrôle (T1071).

### 3.5 pfSense syslog vers Wazuh

Le test du writeup 02 rejoué : ping de l'hôte (`192.168.30.1`) vers le WAN, bloqué ; la vraie
ligne `filterlog` part en syslog UDP 514 **par le LAN** ; `wazuh-remoted` (filtré par
`allowed-ips`), décodeur `pfsense-filterlog`, règle `100302` ; l'analyste ouvre le dashboard.

![Syslog pfSense vers Wazuh](../diagrams/videos/syslog.gif)

[MP4](../diagrams/videos/syslog.mp4)

**Valeur SOC** : UDP ne prévient pas en cas de perte, il faut donc surveiller l'**absence** de
journaux. Syslog en clair peut être lu ou forgé sur le LAN.

### 3.6 Agent Wazuh : enrôlement et événements

Connexion TCP 1515, demande `OSSEC A:'SIEM-Win11'` dans TLS, réponse avec l'ID `001` et la clé
(masquée) ; puis canal 1514 : messages `!001!#AES:` chiffrés (démarrage, événement `4625`,
keepalive).

![Agent Wazuh](../diagrams/videos/agent.gif)

[MP4](../diagrams/videos/agent.mp4)

**Valeur SOC** : l'agent voit ce que le réseau ne voit pas et chiffre tout. Un agent qui se tait
(504) peut être un attaquant qui a arrêté le service (T1562.001).

### 3.7 SSH d'administration depuis l'hôte

`ssh siem-wazuh` : bannières en clair, échange de clés (courbes NIST, mode FIPS), authentification
`ecdsa-sha2-nistp384`, session ouverte, ligne `Accepted publickey` côté serveur.

![SSH](../diagrams/videos/ssh.gif)

[MP4](../diagrams/videos/ssh.mp4)

**Valeur SOC** : le SSH vers le SIEM ne vient que de `10.10.10.1` par construction ; toute autre
source est une alerte à fort signal. Échecs en rafale puis succès : force brute réussie (T1110).

### 3.8 Kali face aux règles ATTACK

Kali sur VMnet11 (adresse DHCP `10.10.20.1xx`, ici `10.10.20.100` en exemple) derrière l'interface
ATTACK (`em0`) de pfSense, avec les 7 vraies règles du [writeup 05](05-segment-attaque-kali.md).
`10.10.10.100:443` : règle 3, bloqué, journalisé, alerte `100302`. `10.10.10.101:3389` : règle 2,
passé et routé (MAC réécrite, TTL 63, IP inchangées), journalisé aussi (alerte `100301`).
`10.10.20.254:443` (interface web de pfSense) : règle 4, bloqué. Voir aussi le
[schéma des règles](../diagrams/regles-attack.png).

![Kali bloqué](../diagrams/videos/kali.gif)

[MP4](../diagrams/videos/kali.mp4)

**Valeur SOC** : segmenter fait de pfSense un passage obligé : l'attaquant qui cherche le SIEM se
trahit, et ses attaques réussies vers la cible restent journalisées.

## 4. Vérifié ou supposé

Le simulateur est **pédagogique** : il reconstitue les échanges, il ne capture pas le réseau.

| Élément | Statut |
|---|---|
| IP, ports, interfaces, plage DHCP, domaine `siem.lab` | ✅ relevés dans le lab (writeups 01 à 04) |
| Ligne `filterlog` et règles 100300/100302/100303 | ✅ vraie ligne et vraies alertes du writeup 02 |
| Agent `001` `SIEM-Win11`, ports 1514/1515 | ✅ writeup 04 |
| Clé ECDSA P-384, mode FIPS, alias `siem-wazuh` | ✅ writeup 03 |
| Adresses MAC | ⚠️ **exemples** au format VMware (`00:0c:29`, `00:50:56:c0:00:0a`) ; relever les vraies avec `arp -a` |
| `203.0.113.10` pour `packages.wazuh.com` | ⚠️ adresse de documentation (RFC 5737), pas l'IP réelle |
| Ports source (`50123`, `41722`…), identifiant DHCP `xid` | ⚠️ exemples (choisis au hasard par le système en vrai) |
| Passerelle NAT VMware `192.168.30.2` | ⚠️ valeur par défaut de VMware, à valider dans *Virtual Network Editor* |
| Règle `5715` sur la connexion SSH, règles `503`/`504` de l'agent | à valider dans notre lab |
| Segment Kali : interface ATTACK `em0`, DHCP, 7 règles | ✅ en place (writeup 05) ; VM Kali à installer, son adresse est un exemple |

Exercice recommandé : capturer le vrai trafic (`tcpdump -w` sur Wazuh, ou Wireshark sur la carte
VMnet10 de l'hôte) et comparer champ par champ avec le panneau du simulateur.

## 5. Comment c'est fait

- Un seul fichier HTML, SVG + JavaScript sans bibliothèque. Les icônes reprennent celles du
  [schéma de topologie](../diagrams/topologie-lab.html).
- Les scénarios sont des données dans l'objet `SCENARIOS` du script : pour chaque étape, le trajet
  (`mv("win>sw10>wazuh", "ok")`), le protocole, les couches du paquet et le texte. Ajouter un
  scénario (par exemple Suricata, ou le brute force) = ajouter une entrée.
- La page expose `window.sim` (`select`, `play`, `setSpeed`, `setHold`, `state`) pour piloter
  l'enregistrement. Enregistrement : Playwright (`recordVideo`, 1440×900, vitesse 1, pauses
  ×1,8), puis `ffmpeg` : MP4 H.264 (`-crf 26`), GIF accéléré ×2, 880 px, 5 images/s, palette de 48
  couleurs (2,5 à 3,5 Mo chacun).

## 6. Sources

- ARP : RFC 826, https://www.rfc-editor.org/rfc/rfc826
- DHCP : RFC 2131, https://www.rfc-editor.org/rfc/rfc2131
- Adresses link-local IPv4 (APIPA) : RFC 3927, https://www.rfc-editor.org/rfc/rfc3927
- Adresses de documentation : RFC 5737, https://www.rfc-editor.org/rfc/rfc5737
- Syslog : RFC 5424, https://www.rfc-editor.org/rfc/rfc5424
- NAT sortant pfSense : https://docs.netgate.com/pfsense/en/latest/nat/outbound.html
- Pare-feu à états pfSense : https://docs.netgate.com/pfsense/en/latest/firewall/fundamentals.html
- Enrôlement des agents Wazuh : https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html
- Ports Wazuh : https://documentation.wazuh.com/current/getting-started/architecture.html
- MITRE ATT&CK : T1557.002 (empoisonnement ARP), T1557.003 (usurpation DHCP), T1071, T1046,
  T1110, T1562.001, https://attack.mitre.org/
