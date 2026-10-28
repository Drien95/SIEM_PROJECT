# Writeup 16 : mouvement latéral SMB, quand Windows refuse et que Wazuh le voit

> Scénario 6, joué le 2026-10-28. Depuis Kali, un compte valide (celui que le scénario 1 a
> trouvé par brute force) tente d'ouvrir les partages d'administration de Windows 11. Résultat
> double : **Windows refuse** (`NT_STATUS_ACCESS_DENIED`, même pour un administrateur local),
> et **Wazuh voit tout** : la connexion, l'accès au partage, le refus. Une règle locale,
> **100240** (niveau 12), signale l'accès depuis le segment d'attaque.
>
> Fiche : [scenarios/mouvement-lateral-smb.md](../scenarios/mouvement-lateral-smb.md).
> Versions : Wazuh 4.14.9, Windows 11 Professionnel build 26300 en français (agent SIEM-Win11),
> Kali `10.10.20.10`.

## 1. Comprendre

### 1.1 Le mouvement latéral

Une fois un compte obtenu, l'attaquant ne reste pas sur la première machine : il **se déplace**
vers d'autres postes avec ce compte. Sur Windows, le chemin le plus classique est **SMB** et
ses partages cachés d'administration :

| Partage | Rôle | Intérêt pour l'attaquant |
|---|---|---|
| `C$` | racine du disque | copier un outil, lire des fichiers |
| `ADMIN$` | dossier `C:\Windows` | déposer un binaire de service (méthode PsExec) |
| `IPC$` | canal de communication inter-processus | négociation, appels RPC (énumération, services) |

MITRE ATT&CK : **T1021.002** *Remote Services: SMB/Windows Admin Shares*, tactique Lateral
Movement. La fiche MITRE précise que ces partages sont « accessibles uniquement aux
administrateurs » et que l'adversaire s'en sert avec des **comptes valides** de niveau
administrateur. Source : https://attack.mitre.org/techniques/T1021/002/

### 1.2 Dans la chaîne du lab

C'est la suite logique du scénario 1 : T1110 (brute force) → T1078 (compte valide, règle
100400) → **T1021.002** (utilisation du compte pour se déplacer). Un incident complet, de la
tentative à la propagation.

## 2. Prérequis : la télémétrie

| Élément | Réglage | Pourquoi |
|---|---|---|
| Audit « Ouverture de session » | succès et échec (GUID `{0CCE9215-…}`) | événements 4624 / 4625 |
| Audit « Partage de fichiers » | succès et échec (GUID `{0CCE9224-…}`) | événement **5140** : accès à un partage |
| Agent Wazuh | canal `Security` collecté, décodeur `windows_eventchannel` | transport vers le manager |

Ces deux audits font partie de la famille 03 des scripts de durcissement
([writeup 13](13-durcissement-cis-automatise.md)) : le durcissement CIS a directement apporté
la télémétrie de ce scénario.

## 3. L'attaque

Depuis Kali (réseau d'attaque `10.10.20.0/24`, à travers pfSense), contre la VM du lab
uniquement :

```bash
smbclient //10.10.10.101/C$ -U 'analyste%<mot de passe>' -c 'ls'
```

Résultat : `NT_STATUS_ACCESS_DENIED` au moment du *tree connect* (l'ouverture du partage).
Même résultat avec `analyste` (compte standard) et avec `admin-secours` (administrateur local).

## 4. Le finding : le filtrage de jeton UAC à distance

Qu'un compte standard soit refusé, c'est attendu. Qu'un **administrateur local** le soit aussi
est plus intéressant.

**Ce que dit Microsoft (vérifié)** : pour protéger les membres du groupe Administrateurs local,
Windows applique les restrictions UAC **sur le réseau**. Un compte **local** qui se connecte à
distance ne reçoit pas un jeton d'administrateur complet : « l'utilisateur n'a aucun potentiel
d'élévation sur l'ordinateur distant ». Le comportement est piloté par la valeur
`LocalAccountTokenFilterPolicy` sous
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` : **0, valeur par défaut**,
jeton filtré ; 1, jeton élevé. Les comptes de **domaine** ne sont pas concernés.
Source : https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction

**Conséquence dans le lab** : `C$` et `ADMIN$` sont refusés à tout compte local, même
administrateur. `IPC$` reste accessible : il sert à la négociation et n'exige pas de droits
d'administration.

*À valider* : l'exception du compte Administrateur intégré (RID 500), qui échapperait au
filtrage tant que `FilterAdministratorToken` est désactivé. Elle n'est pas décrite dans la page
ci-dessus et n'a pas été testée (ce compte est désactivé par défaut sur Windows 11).

**Lecture SOC** : c'est un bon contrôle anti-mouvement-latéral, actif **par défaut**. Deux
corollaires :

- trouver `LocalAccountTokenFilterPolicy = 1` sur un poste est un signal (outil
  d'administration mal configuré, ou attaquant qui prépare le terrain) : la modification de
  cette clé mérite une détection (piste, à valider) ;
- la protection ne couvre pas les comptes de domaine : dans un vrai réseau, c'est là que se joue
  le mouvement latéral.

## 5. Ce que Wazuh a vu

Quatre règles, trois natives et une locale :

| Règle | Niveau | Événement Windows | Ce qu'elle dit | Lecture |
|---|---|---|---|---|
| **92657** (native) | 6 | 4624, connexion réseau NTLM | « Successful Remote Logon … possible pass-the-hash … **Possible RDP connection** » | le libellé parle de RDP, alors que c'était du **SMB** |
| **67017** (native) | 3 | 5140 succès | « A network share was accessed », T1021.002 | accès à `IPC$` |
| **60104** (native) | 5 | 5140 **échec** (`AUDIT_FAILURE`) | « Windows audit failure event » | **la preuve du refus** sur `C$` |
| **100240** (locale) | **12** | 5140 succès depuis `10.10.20.0/24` | « Mouvement lateral SMB : acces a un partage depuis le segment d attaque (10.10.20.10) - compte analyste - partage `\\*\IPC$` » | alerte à 20:37:03 |

### 5.1 Un titre d'alerte n'est pas un diagnostic

La 92657 (fichier `0840-win_event_channel.xml`) est une enfant de 92652 (connexion réseau
NTLM réussie) : elle se déclenche dès que le champ `workstationName` est rempli, quel que soit
le protocole. Son libellé évoque le pass-the-hash et RDP, et elle porte T1550.002, T1078.002 et
**T1021.001** (RDP). Ici, ni pass-the-hash ni RDP : une connexion SMB avec un mot de passe. Le
titre décrit des **hypothèses** à vérifier, pas un fait. Réflexe d'analyste : lire les champs
(type de connexion, port, processus, événements voisins) avant de reprendre le libellé.

### 5.2 Pourquoi `IPC$` déclenche 67017 (finding)

La 67017 (fichier `0955-WEF-baseline_rules.xml`) a pour commentaire « accès à un partage réseau
**sans** IPC$ et NetLogon », et l'exclusion est écrite ainsi :

```xml
<field name="win.eventdata.shareName" negate="yes">IPC$|NetLogon</field>
```

Or ce champ utilise la syntaxe **OS_Regex** de Wazuh, où `$` signifie « fin du texte »
(documentation : https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html).
`IPC$` cherche donc « IPC » en fin de valeur ; la valeur réelle `\\*\IPC$` se termine par le
caractère `$`, le motif ne correspond pas, l'exclusion ne joue pas et `IPC$` passe. Déduction,
cohérente avec l'alerte observée. L'écriture attendue serait `IPC\$` (`\$` = dollar littéral
d'après la même documentation, à valider avec `wazuh-logtest`).

C'est la troisième fois du projet qu'une règle native ne fait pas ce que son commentaire
annonce (après 60122 et 87105 pour leurs étiquettes MITRE, voir [docs/mitre.md](../mitre.md)).

## 6. La règle locale 100240

```xml
<group name="lateral_movement,windows,">
  <rule id="100240" level="12">
    <if_sid>67017</if_sid>
    <field name="win.eventdata.ipAddress">^10\.10\.20\.</field>
    <description>Mouvement lateral SMB : acces a un partage depuis le segment d attaque ($(win.eventdata.ipAddress)) - compte $(win.eventdata.subjectUserName) - partage $(win.eventdata.shareName)</description>
    <mitre><id>T1021.002</id></mitre>
  </rule>
</group>
```

Dans le dépôt : [`configs/manager/local_rules.xml`](../../configs/manager/local_rules.xml).
Vérifiée avec `wazuh-analysisd -t`, puis déclenchée en live.

- **Enfant de 67017** : on réutilise le travail de la native (bon fournisseur, bon événement
  5140, bonne technique) et on ajoute **le contexte** que seul le lab connaît : la provenance.
- **Pourquoi la source suffit ici** : aucun trafic SMB légitime ne vient de `10.10.20.0/24`.
  Tout accès à un partage depuis ce segment est donc suspect par construction.

### Limites et tuning

| Limite | Effet | Piste |
|---|---|---|
| `IPC$` passe (§ 5.2) | une alerte niveau 12 à **chaque** connexion SMB depuis le segment, même refusée ensuite | exclure `IPC\$` dans 100240 (à valider) |
| 100240 ne voit que les **succès** (67017 descend de 60103, audit success) | la tentative refusée sur `C$` reste en 60104, niveau 5 | règle sœur enfant de 60104 : 5140 en échec, partage `C$` ou `ADMIN$`, source `10.10.20.` (à écrire) |
| Critère d'adresse propre au lab | inutilisable tel quel en production, où le SMB interne est partout | en production : partages `ADMIN$`/`C$`, comptes inhabituels, poste source qui n'administre pas d'habitude, corrélation avec 4624 type 3 |

## 7. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| `smbclient` sur `C$` avec `analyste` (standard) | refus | ✅ `NT_STATUS_ACCESS_DENIED` |
| `smbclient` sur `C$` avec `admin-secours` (admin local) | refus (filtrage UAC à distance) | ✅ `NT_STATUS_ACCESS_DENIED` |
| Connexion réseau vue | 4624 NTLM → 92652 / 92657 | ✅ 92657 niveau 6 (libellé RDP imprécis) |
| Refus vu | 5140 échec → 60104 | ✅ 60104 niveau 5 |
| Accès à `IPC$` vu | 5140 succès → 67017 | ✅ 67017 niveau 3, T1021.002 |
| Règle locale | 100240 niveau 12 | ✅ 2026-10-28 20:37:03, `10.10.20.10`, compte `analyste`, `\\*\IPC$` |
| Compte Administrateur intégré (RID 500) | accès possible | ⏳ non testé (compte désactivé) |

Sources : [docs/sources.md](../sources.md#scénario-6--mouvement-latéral-smb).
