# Writeup 26 : du triage au tuning, trois règles nées des tickets

> Joué le 2026-10-29. Les [tickets de triage 01 et 02](../triage/README.md) ont laissé une liste
> de manques. Ce writeup les traite un par un, avec la même méthode à chaque fois : lire la règle
> native, formuler une hypothèse, la vérifier sur des données réelles, puis écrire la règle et la
> valider en live. Résultat : **100120** (bruit coupé), **100251** (nouvelle technique,
> T1562.002) et **100272/100273** (corrélation). Deux hypothèses de départ se sont révélées
> fausses en chemin.
>
> Versions : Wazuh 4.14.9, Windows 11 en français, Sysmon v15.22.

## 1. Bruit : la native 61618 sonne au niveau 12 sur des svchost légitimes

**Constat (tickets 01 et 02)** : `Sysmon - Suspicious Process - svchost.exe` (61618, niveau 12,
T1055) sur des `svchost.exe -k …` lancés par SYSTEM ou SERVICE LOCAL, cinq fois en dix minutes.
93 alertes sur la journée.

**Règle native** (`0595-win-sysmon_rules.xml`, v4.14.0) : 61618 sonne sur **tout** svchost ;
l'exception **61619** (niveau 0) l'annule si `parentImage` vaut `services.exe`, le parent légitime.

**Hypothèse** : le parent n'est pas transmis, donc l'exception ne s'applique pas. **Vérifiée**
sur trois alertes : `parentImage` absent, `parentProcessGuid` = `{00000000-…}`, seul
`parentProcessId` = 824 est connu. Sur Win11, le PID 824 est `services.exe`, démarré à 15:29:07 ;
`Sysmon64` a démarré à 15:29:13.

**Cause** : Sysmon est un service, lancé **par** `services.exe`. Il ne peut pas connaître un
processus antérieur à lui-même : tous les svchost de service arrivent sans parent. Ce n'est pas
réglable côté Sysmon (déduction, cohérente avec les horodatages).

**Règle 100120** (niveau 0, enfant de 61618) : ignore le svchost **seulement** si les quatre
conditions sont réunies : binaire exact `C:\Windows\System32\svchost.exe`, GUID parent nul,
ligne de commande `svchost.exe -k <groupe>`, compte de service (SYSTEM, SERVICE LOCAL, SERVICE
RÉSEAU). Un svchost lancé par un programme connu de Sysmon (GUID parent non nul), le cas d'un
attaquant, continue d'alerter.

Deux détails d'écriture :

- antislashs **doublés** dans les champs eventchannel (`C:\\Windows\\…`), d'où `\\+`
  ([writeup 25](25-dashboard-couverture-mitre.md)) ;
- le `é` de « Système » peut compter pour deux octets si pcre2 ne travaille pas en UTF-8 : `.{1,2}`
  plutôt que `.` (précaution, non vérifiée).

**Validation** : redémarrage de `W32Time` (SERVICE LOCAL) et `wuauserv` (SYSTEM) : compteur
61618 **93 avant, 93 après**, et 4 événements svchost correspondants bien présents dans
`archives.json`.

## 2. Couper l'audit : de la 60112 à la 100251 (T1562.002)

**Constat (ticket 02)** : `auditpol /set /subcategory:{0CCE9227-…}` n'a produit aucune alerte.

**Règle native** (`0580-win-security_rules.xml`) : **60112** (niveau 8) « Windows Audit Policy
changed » sur l'événement **4719**.

| Hypothèse | Test | Verdict |
|---|---|---|
| L'audit des changements de politique (`{0CCE922F-…}`) est désactivé, donc pas de 4719 | `auditpol /get` : « Réussite » | ❌ fausse |
| Le `/set` du ticket 02 remettait une valeur **déjà en place** : pas de changement, pas de 4719 | désactiver puis réactiver réellement la sous-catégorie | ✅ deux 60112, à 16:57:57 (« Success removed, Failure removed ») et 16:58:02 (« Success added, Failure added ») |

Ce n'était donc pas un trou. Mais la native donne **le même niveau 8** au retrait et à l'ajout.
Retirer l'audit est le geste d'un attaquant qui veut devenir invisible : **T1562.002** *Impair
Defenses: Disable Windows Event Logging*.
Source : https://attack.mitre.org/techniques/T1562/002/

**Règle 100251** (niveau 12, enfant de 60112) : `auditPolicyChanges` contient `removed`. Les
valeurs sont en anglais même sur Windows en français (vu en live).

**Validation** (désactivation puis réactivation, lab) :

```
16:59:26 100251 12 Audit Windows desactive par analyste : Success removed, Failure removed (sous-categorie {0cce9227-…})
16:59:31 60112   8 Windows Audit Policy changed
```

## 3. La tâche éclair : corrélation 4698 → 4699

**Constat (ticket 02)** : la tâche `LabS10` est créée, lancée puis **supprimée 4 secondes après**.
`schtasks /query` ne montre plus rien sur le poste. Ce motif est celui d'un tremplin vers SYSTEM,
pas d'une tâche d'administration.

**Règle native** : aucune règle ne vise le **4699** (suppression de tâche) dans
`0580-win-security_rules.xml` (v4.14.0). Observation d'un 4699 réel dans `archives.json` : il
arrive, sans règle, et porte le **même champ `taskName`** que le 4698.

**Montage** (le même que la corrélation 100282, [writeup 22](22-scenario-collection-exfiltration.md)) :

| Règle | Niveau | Rôle |
|---|---|---|
| 100271 (existante) | 12 | tâche SYSTEM créée (4698) ; reçoit le groupe `sched_task_chain` |
| **100272** | 3 | tâche supprimée (4699), enfant de 60103, groupe `sched_task_chain` |
| **100273** | 13 | `frequency="2" timeframe="60"`, `if_matched_group sched_task_chain`, événement 4699, `same_field win.eventdata.taskName` |

**Validation** (tâche inoffensive `LabS10c`, `cmd.exe /c whoami`) :

```
17:04:12.916 100271 12 Tâche planifiée \LabS10c en SYSTEM créée par analyste (4698)
17:04:12.973 100273 13 Tache SYSTEM \LabS10c creee puis supprimee en moins de 60 s par analyste : execution furtive
```

La corrélation remplace la 100272 sur l'événement de suppression.

**Limites** : une tâche **non SYSTEM** créée puis supprimée n'est pas corrélée (100271 ne la voit
pas), c'est un choix. Deux suppressions de la même tâche en 60 s déclencheraient aussi la
corrélation (cas jugé improbable, non testé). Une tâche gardée plus de 60 s échappe à la
corrélation, mais pas à 100271.

## 4. Bilan

| Manque relevé au triage | Règle | Statut |
|---|---|---|
| 61618 bruyante (svchost sans parent) | **100120** (0) | ✅ validée (93 → 93) |
| Retrait d'audit noyé au niveau 8 | **100251** (12), T1562.002 | ✅ validée |
| Tâche créée puis supprimée | **100272** (3) + **100273** (13) | ✅ validée |
| Bruit LSASS d'outils légitimes ([writeup 25](25-dashboard-couverture-mitre.md)) | **100221** (0) | déployée, validation à faire sur des accès spontanés |
| Preuve réseau de l'exfiltration (ticket 01) | journal pfSense des *pass* LAN → ATTACK | à faire |
| Script invisible (ticket 01) | PowerShell Script Block Logging (4104) | à faire |
| Rafale de 100 × 60104 (4957, règle de pare-feu non appliquée) au redémarrage de services | — | observée, non traitée |

## 5. Lien SOC

1. **Le triage nourrit la détection** : chaque ticket se termine par une liste d'améliorations.
2. **Une hypothèse se teste** : deux sur quatre étaient fausses ici. La vérification a coûté une
   commande chacune.
3. **Une liste blanche se construit sur la cause**, pas sur le symptôme : 100120 n'ignore pas
   « svchost », elle ignore « svchost dont le parent est antérieur à Sysmon ».
