# Writeup 06 : premier scénario de détection, brute force SMB sur Windows 11

> Premier exercice « attaque puis détection » du lab : Kali devine le mot de passe d'un compte
> de Windows 11 en SMB, et on vérifie ce que Wazuh en voit. L'analyse détaillée (règles,
> lecture SOC, MITRE, durcissement) est dans la fiche
> [`docs/scenarios/brute-force-smb.md`](../scenarios/brute-force-smb.md) ; ce writeup raconte le
> déroulé et les incidents.
>
> Versions : Wazuh 4.14.9, Windows 11 Pro (agent 001), pfSense CE 2.9.0, Kali Linux (NetExec).
> Date : 2026-10-22.

![Flux de détection du brute force SMB](../diagrams/detection-brute-force-smb.png)

*Du paquet SMB de Kali à l'alerte : chemin à travers pfSense, chaîne de règles dans Wazuh,
puis la frise des alertes telle que l'analyste la voit. Source :
[`detection-brute-force-smb.html`](../diagrams/detection-brute-force-smb.html).*

## 1. Comprendre

### 1.1 Ce qu'on valide

Un SIEM ne vaut que par ce qu'il détecte **réellement**. On joue donc une attaque connue,
dans un cadre maîtrisé, et on compare la détection **attendue** (documentation, ruleset) à la
détection **observée**. C'est le principe d'une validation de détection (ou exercice
*purple team*) : l'équipe offensive agit, l'équipe défensive vérifie chaque trace.

### 1.2 La chaîne qui produit l'alerte

1. Kali présente un mot de passe à Windows en SMB (445/TCP), authentification NTLM.
2. Windows le refuse et écrit l'événement **4625** dans son journal Security.
3. L'agent Wazuh lit ce journal (canal *eventchannel*) et l'envoie au manager sur 1514/TCP.
4. Le manager décode l'événement en champs `win.*`, puis l'évalue : règle **60122** (un
   échec, niveau 5).
5. Quand 8 échecs arrivent en 240 s depuis la même adresse, la règle de corrélation **60204**
   (niveau 10) se déclenche une fois.
6. Le succès final produit la **92652** (ouverture de session réseau réussie, niveau 6).

Si un maillon manque, l'alerte n'existe pas. Le premier incident ci-dessous en est l'exemple.

## 2. Déroulé

| Étape | Action | Résultat |
|---|---|---|
| 1 | Premiers essais SMB depuis Kali | aucune réponse, **aucun 4625** dans Wazuh |
| 2 | Diagnostic : pare-feu Windows | SMB n'est autorisé que depuis le sous-réseau local |
| 3 | Règle entrante 445/TCP depuis `10.10.20.0/24` | SMB joignable depuis Kali |
| 4 | Devinette du mot de passe de `analyste` avec `nxc smb` | 10 échecs, 1 succès ; la console n'affiche que le succès |
| 5 | Lecture dans Wazuh (Threat Hunting, agent 001) | 60122 ×10, 60204 ×1, 92652 à 02:15:46 |

## 3. Incidents et corrections

### 3.1 Aucun 4625 : le pare-feu Windows jetait SMB

**Constat.** L'attaque partait de Kali, pfSense la laissait passer (règle 2 d'ATTACK), mais
Wazuh ne montrait rien.

**Cause.** Les règles Windows « Partage de fichiers et d'imprimantes (SMB-In) » n'acceptent
par défaut que le **sous-réseau local**. Depuis que Kali est sur son propre réseau
(writeup 05), il n'en fait plus partie.

**Correction.** Une règle entrante 445/TCP limitée à `10.10.20.0/24` (exemple de commande dans
la fiche, § 5). À retirer après les exercices.

**À retenir.** Un SIEM muet ne prouve pas l'absence d'attaque. Il faut d'abord vérifier que
l'attaque atteint la machine qui produit les journaux.

### 3.2 La console de l'attaquant affichait des timeouts

**Constat.** `nxc` répondait « Connection Error / NETBIOS timed out » pour chaque échec et
n'affichait que le succès.

**Vérification.** Wazuh avait bien reçu **dix** 4625 : chaque mot de passe avait été présenté
et refusé.

**À retenir.** Les journaux de la cible font foi, pas l'écran de l'attaquant.

## 4. Ce que l'analyste en tire

- Partir de la **60204** (niveau 10), puis ouvrir les 60122 pour le détail.
- `subStatus 0xC000006A` : le compte existe, le mot de passe est faux. L'attaque visait un
  compte réel.
- Une **92652** pour le même compte juste après la rafale = compromission probable.
- 92652 en ANONYMOUS LOGON (sondage de `nxc`) et 60106 sont du bruit.
- MITRE : l'attaque est T1110 ; l'étiquette native de 60122 (T1531, Impact) est inexacte.

Détail, règle locale proposée pour relier échecs et succès, et durcissement : voir la
[fiche du scénario](../scenarios/brute-force-smb.md).

## 5. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| SMB Kali → Windows 11 à travers pfSense | joignable | ✅ après la règle du pare-feu Windows |
| Un 4625 par essai raté | 10 | ✅ 10 × 60122 (niv. 5) |
| Corrélation brute force | 60204 | ✅ 1 × 60204 (niv. 10) |
| Succès visible | une alerte d'ouverture de session réseau | ✅ 92652 (niv. 6), 02:15:46 |
| Passage dans pfSense journalisé | 100301 | à valider |
| Règle locale « succès après rafale » | alerte niv. 12 | à écrire et tester |
| Captures 78 à 83 | dans `docs/homelab/screenshots/` | à ajouter |

Sources : voir la [fiche du scénario](../scenarios/brute-force-smb.md).
