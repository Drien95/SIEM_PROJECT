# Writeup 08 : deuxième scénario, un scan nmap repéré par pfSense

> Kali balaye les ports du serveur Wazuh. Aucun agent n'est sur le chemin : c'est **pfSense**
> qui témoigne, par ses journaux de blocage envoyés en syslog à Wazuh. L'analyse détaillée est
> dans la fiche [`docs/scenarios/scan-nmap.md`](../scenarios/scan-nmap.md) ; ce writeup raconte
> le déroulé et ce qu'on en apprend.
>
> Versions : Wazuh 4.14.9, pfSense CE 2.9.0, Kali Linux (nmap). Date : 2026-10-22, 21:00
> heure locale.

## 1. Comprendre

### 1.1 Le pare-feu comme source de journaux

Dans le scénario 1, la trace venait de la **cible** (journal Security de Windows, via
l'agent). Ici, elle vient du **réseau** : chaque paquet que pfSense refuse sur l'interface
ATTACK devient une ligne `filterlog`. Cette ligne part en syslog vers Wazuh (writeup 02), où
notre décodeur `pfsense-filterlog` la découpe en champs, puis :

1. **100302** (niveau 5) : un paquet bloqué, une alerte ;
2. **100303** (niveau 10) : 18 blocages de la même IP en 45 s, c'est un scan probable
   (MITRE T1046).

C'est la même chaîne que celle validée au writeup 02 avec un ping depuis l'hôte (capture 63).
Cette fois, elle est jouée par un vrai attaquant, depuis le réseau d'attaque.

### 1.2 Ce que fait un scan SYN

`nmap -sS` envoie un SYN, le premier paquet d'une connexion TCP, sur chaque port. Selon la
réponse, le port est classé ouvert (SYN-ACK), fermé (RST) ou **filtré** (pas de réponse).
pfSense jette les paquets sans répondre (action Block) : tous les ports de Wazuh apparaissent
filtrés, et chaque SYN laisse une ligne de blocage.

## 2. Déroulé

| Étape | Action | Résultat |
|---|---|---|
| 1 | `nmap -sS` vers Windows 11 | aucune 100303 : pfSense **autorise** ce trafic (règle 2), qui donne des 100301 |
| 2 | `sudo nmap -sS -T4 -p1-200 10.10.10.100` | « *Host seems down* » : nmap ne scanne rien, trop peu de blocages |
| 3 | `sudo nmap -sS -Pn -T4 -p1-200 10.10.10.100` | 200 SYN bloqués par la règle 3 d'ATTACK |
| 4 | Threat Hunting `rule.id:100302 AND data.srcip:10.10.20.10` | rafale de 100302 vers 10.10.10.100 (`tcp`, `icmp`), interface `em0` (capture 89) |
| 5 | Threat Hunting `rule.id:100303` | **1** alerte niveau 10 à 21:00:45 : « blocages répétés depuis 10.10.20.10 (scan probable) » (capture 90) |

![Alerte 100303 niveau 10](../homelab/screenshots/90-wazuh-100303-scan-probable.png)

## 3. Ce qu'on en apprend

### 3.1 Une détection ne voit que son chemin

La 100303 compte des **refus**. Un scan vers une machine que pfSense laisse passer (Windows 11,
la cible désignée des attaques) ne produit aucun refus, donc aucune alerte de scan. Ce n'est
pas une panne, c'est une conséquence de la conception du lab. Il faut la connaître pour ne
pas conclure « pas d'alerte, pas de scan ». Pour couvrir ce cas, plusieurs pistes sont à
valider : corréler les 100301, ajouter Suricata, ou journaliser le pare-feu Windows.

### 3.2 Un pare-feu silencieux cache la cible

Sans `-Pn`, nmap vérifie d'abord que l'hôte répond. pfSense ne répondant à rien, la cible
paraît éteinte et le scan s'arrête. Pour aller plus loin, l'attaquant doit forcer le scan, ce
qui fait beaucoup plus de bruit et déclenche la corrélation.

### 3.3 Une alerte pour tout un scan

Les 100302 arrivent par centaines, la 100303 une seule fois. `ignore="240"` la fait taire
4 minutes après son déclenchement. L'analyste part de l'alerte de niveau 10, puis descend dans
les 100302 pour voir la cible et les ports visés.

## 4. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| Scan vers une cible bloquée → 100302 | une par paquet | ✅ rafale, `src 10.10.20.10 → 10.10.10.100`, `em0` |
| Corrélation 100303 | niveau 10, une fois | ✅ 21:00:45 |
| Scan sans `-Pn` | détection | ❌ « *Host seems down* », sous le seuil : comportement attendu, documenté |
| Scan vers Windows 11 | 100303 | ❌ trafic autorisé (100301) : angle mort connu |
| Corrélation sur les 100301 | scan de Windows 11 détecté | idée, à valider |

Sources : voir la [fiche du scénario](../scenarios/scan-nmap.md).
