# Writeup 18 : tuning des faux positifs, première séance

> Phase 2, detection engineering. Séance du 2026-10-28 (~22:00-22:30) sur la règle locale
> **100230** (écriture dans une clé Run, [writeup 11](11-scenario-persistance-run-key.md)),
> bruyante à cause de Microsoft Edge. Résultat : une liste blanche validée (**100231**) et trois
> constats sur la façon de régler Wazuh. Versions : Wazuh 4.14.9, agent SIEM-Win11, Sysmon v15.22.

## 1. Le problème

Microsoft Edge écrit lui-même des valeurs dans `HKCU\…\CurrentVersion\Run`
(`MicrosoftEdgeAutoLaunch_…`, `msedge_cleanup`). Pour la règle 100230, c'est une écriture Run
comme une autre : alerte de **niveau 12** pour une activité normale. Un niveau 12 qui sonne pour
rien finit par être ignoré, et la vraie alerte avec lui.

Objectif : faire taire ce cas précis **sans** perdre la détection d'une écriture Run inconnue.

## 2. La liste blanche 100231

```xml
<group name="sysmon,windows,">
  <rule id="100231" level="0">
    <if_sid>100230</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)(MicrosoftEdgeAutoLaunch|msedge_cleanup)</field>
    <description>Persistance Run-key : auto-demarrage Microsoft Edge connu (benin) - ignore</description>
  </rule>
</group>
```

Dans le dépôt : [`configs/manager/local_rules.xml`](../../configs/manager/local_rules.xml).

**Le principe** : une règle **enfant de niveau 0**. Wazuh descend l'arbre des règles et garde la
plus profonde qui correspond ; si 100231 correspond, l'événement s'arrête à elle, niveau 0, pas
d'alerte. Sinon, 100230 reste le résultat, niveau 12.

**Les choix** :

- filtrer sur `targetObject` (le nom de la valeur écrite), pas sur le processus : un attaquant
  peut lancer son code depuis n'importe quel processus, le nom de valeur Edge est spécifique ;
- expression bornée à deux noms connus, insensible à la casse.

**Limite assumée** : un attaquant qui nommerait sa valeur `MicrosoftEdgeAutoLaunch_…` passerait
sous la liste blanche. Durcissement possible : exiger aussi que `win.eventdata.details` pointe
vers l'exécutable d'Edge dans `Program Files` (à valider).

### Validation en live

| Test | Attendu | Obtenu |
|---|---|---|
| Valeur Run contenant `MicrosoftEdgeAutoLaunch` / `msedge_cleanup` | 100231, niveau 0, pas d'alerte | ✅ |
| Valeur Run de test au nom quelconque | 100230, niveau 12 | ✅ toujours détectée |
| `wazuh-analysisd -t` après ajout | configuration valide | ✅ |

Les tests ont été faits avec des valeurs **nommées comme celles d'Edge** (`MicrosoftEdgeAutoLaunch_TEST…`)
et des valeurs de test non Edge, écrites avec `reg add` puis supprimées (`reg delete … /f`).

## 3. Constat A : `wazuh-logtest` n'est pas fidèle pour les événements Windows

Réflexe habituel : coller la ligne `full_log` d'une alerte dans `wazuh-logtest` pour tester une
règle. Pour un événement Windows collecté par l'agent (**EventChannel**), ça ne reproduit pas le
live : la ligne collée est décodée comme du JSON générique (décodeur `json`, le même nom que
notre décodeur Suricata) au lieu de `windows_eventchannel`. Les champs ne portent alors pas les
mêmes noms, et la chaîne Sysmon (92300 → 100230 → 100231) ne se déclenche pas dans logtest,
alors qu'elle se déclenche en live.

Constat observé dans le lab ; l'explication par le chemin de décodage est une **déduction**.
La documentation de `wazuh-logtest` ne parle pas des événements EventChannel ; l'option
`-l` change seulement la *location* (piste à essayer : `-l EventChannel`, à valider).
Source : https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html

**Conséquence pratique** : pour les règles sur événements Windows, valider **en live** (rejouer
l'action, lire `alerts.json`), pas avec logtest sur `full_log`.

## 4. Constat B : une action, plusieurs événements, plusieurs alertes

Même une fois 100230 réglée, le test a encore produit des alertes :

| Règle | Niveau | Événement source | Ce qu'elle voit |
|---|---|---|---|
| 100230 → **100231** | 12 → 0 | Sysmon EID 13 (écriture registre) | la valeur Run écrite (réglé) |
| **92041** (native) | 10 | Sysmon EID 1 (création de processus) | ligne de commande `reg add … /d …` jugée « Base64-like » (T1027, T1112) |
| **67027** (native) | 3 | Security **4688** (création de processus) | le lancement de `reg.exe` |

Une seule action (`reg add`) produit **trois événements** : la création du processus vue par
Sysmon (EID 1) et par le journal Security (4688, actif depuis la famille 03 du
[writeup 13](13-durcissement-cis-automatise.md)), puis l'écriture registre (EID 13). Chaque
événement suit sa propre branche de l'arbre : une liste blanche sur la branche EID 13 ne touche
pas les deux autres.

Note sur 92041 (`0800-sysmon_id_1.xml`) : son expression est
`(?i)add.+\/d\s+(")?(?:[A-Za-z\d+\/]{4})*(?:…)?`. Les groupes Base64 étant facultatifs (`*` et
`?`), elle correspond en pratique à presque toute commande `reg add … /d` (déduction à la lecture
de l'expression, cohérente avec l'alerte sur une valeur ordinaire).

Nuance importante : ces deux alertes viennent de **la façon de tester** (`reg.exe`). Edge écrit
ses valeurs lui-même, sans lancer `reg.exe` : pour le vrai Edge, seul l'événement EID 13 devrait
exister, et 100231 suffirait (déduction, à confirmer en observant une vraie écriture d'Edge). À
l'inverse, un administrateur ou un script qui utilise `reg add` déclenchera 92041 et 67027.

**Leçon** : régler un faux positif, c'est d'abord lister **tous** les événements produits par
l'action et toutes les règles qui les voient, puis régler chacune.

## 5. Constat C : la fille de niveau 0 sous la native 92041 n'a pas suffi

Une règle 100232 (`if_sid 92041`, niveau 0) a été essayée pour faire taire 92041 dans ce cas :
l'alerte 92041 a continué. La règle a été retirée du manager et n'est pas dans le dépôt.

Le même mécanisme fonctionne pour 100231 sous notre 100230. Différence probable (déduction, à
vérifier) : 92041 se déclenche sur un événement **EID 1**, qui n'a pas de champ `targetObject`
(propre aux événements registre). Si 100232 filtrait sur ce champ, comme 100231, elle ne pouvait
jamais correspondre ; pour EID 1, il faut filtrer sur `win.eventdata.commandLine` ou
`win.eventdata.image`. À vérifier en relisant le contenu de 100232 avant de conclure que le
mécanisme lui-même est en cause.

Autre outil, si une fille ne suffit pas : **redéfinir** la règle native dans `local_rules.xml`
avec `overwrite="yes"` (procédure de la documentation, qui préserve la modification lors des
mises à jour). Plus intrusif : on remplace la règle de Wazuh au lieu de l'étendre, ce qui va
contre la convention du projet (étendre par `if_sid`) ; à réserver aux cas où l'extension ne
marche pas, et à documenter.
Source : https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html

## 6. Ce qu'on retient

1. Liste blanche = **règle fille de niveau 0**, la plus étroite possible, avec sa limite écrite.
2. Toujours revérifier qu'un **vrai positif** déclenche encore l'alerte après le réglage.
3. Pour Windows : valider **en live**, logtest ne reproduit pas le décodage EventChannel.
4. Une action produit plusieurs événements : régler **chaque branche**.
5. Si une fille ne prend pas, vérifier d'abord que ses champs **existent** sur l'événement visé.

## 7. Résultats dans notre lab

| Date | Réglage | Résultat | Statut |
|---|---|---|---|
| 2026-10-28 | 100231, liste blanche Edge sous 100230 | Edge silencieux, valeur de test toujours en niveau 12 | ✅ validé en live, commité |
| 2026-10-28 | test de 100230/100231 via `wazuh-logtest` sur `full_log` | aucune règle Sysmon déclenchée | ❌ méthode non fidèle (constat A) |
| 2026-10-28 | 100232, fille niveau 0 sous 92041 | 92041 toujours en alerte | ❌ retirée ; cause à vérifier (constat C) |
| à faire | observer une vraie écriture d'Edge (sans `reg.exe`) ; décider du sort de 92041 (expression trop large) | — | ⏳ |
| à faire | bornage `RunNotification` (sihost.exe) sur 100230, `IPC\$` sur 100240, `wazuh-agent.exe` sur 100220 | — | ⏳ |

Sources : [docs/sources.md](../sources.md#tuning-des-faux-positifs).
