# Scénario — Persistance par clé Run (Sysmon EID 13)

MITRE ATT&CK : **T1547.001** (Boot or Logon Autostart Execution: Registry Run Keys / Startup
Folder).

Statut : **joué le 2026-10-25**, règle 100230 observée en live (Discover et `alerts.json`),
Wazuh 4.14.9.

Sources :
https://attack.mitre.org/techniques/T1547/001/,
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (événement 13),
https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys,
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0860-sysmon_id_13.xml (92300-92303),
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0595-win-sysmon_rules.xml (61600, 61615),
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0575-win-base_rules.xml (60004),
https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html (`logall_json`),
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html.

> Test inoffensif (valeur qui lance le Bloc-notes), sur la VM Windows 11 du lab uniquement.

![Arbre des règles pour une écriture Run](../diagrams/persistance-run-key.png)

*Source : [`persistance-run-key.html`](../diagrams/persistance-run-key.html). Récit complet :
[writeup 11](../writeup/11-scenario-persistance-run-key.md).*

## 1. Objectif

Vérifier que Wazuh alerte quand un programme s'inscrit au démarrage de session par une clé Run,
technique de persistance très courante.

## 2. Topologie

| Rôle | Machine | Détail |
|---|---|---|
| Poste | SIEM-Win11 `10.10.10.101` (agent 001) | Sysmon v15.22, [`sysmon-lab.xml`](../../configs/agent-windows/sysmon-lab.xml) |
| SIEM | Wazuh 4.14.9 `10.10.10.100` | règle locale 100230 |

Pas d'attaquant réseau : le test simule ce que ferait un programme déjà présent sur le poste.

## 3. Prérequis

1. Sysmon avec un filtre `RegistryEvent` qui inclut `\CurrentVersion\Run`
   ([`sysmon-lab.xml`](../../configs/agent-windows/sysmon-lab.xml), appliqué par
   `Sysmon64.exe -c`, qui **remplace** toute la configuration précédente).
2. Canal `Microsoft-Windows-Sysmon/Operational` collecté par l'agent
   ([`agent.conf`](../../configs/manager/shared/default/agent.conf)).
3. Règle 100230 dans `/var/ossec/etc/rules/local_rules.xml`, puis
   `sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager`.

## 4. Test

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LabTest" -Value "C:\Windows\System32\notepad.exe" -PropertyType String
# nettoyage
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LabTest"
```

## 5. Détection : attendu contre observé

| Étape | Règle | Niveau | Attendu | Observé |
|---|---|---|---|---|
| Événement Sysmon 13 | 60004 → 61600 → 61615 | 0 | collecté | ✅ (archives) |
| Écriture Run reconnue | **92300** (native, T1547.001) | 0 | reconnue | ✅ mais aucune alerte |
| Variantes suspectes | 92301 (`.lnk`/`.vbs`/`.vba`), 92302 (`reg.exe`), 92303 (VNC) | 12 / 6 / 12 | pas de correspondance | ✅ aucune |
| 1re règle locale, enfant de 61615 | — | 12 | alerte | ❌ jamais évaluée |
| Règle locale **100230**, enfant de 92300 | **100230** « Persistance Run-key (T1547.001) : … » | 12 | alerte | ✅ 19:12:10, PowerShell → `Run\WazuhLabTest5` |
| Bruit | 100230 sur `sihost.exe` → `RunNotification` | 12 | aucune alerte | ❌ 19:12:20, faux positif (capture 96) |

![Deux alertes 100230 : vrai positif PowerShell, faux positif sihost.exe](../homelab/screenshots/96-wazuh-100230-run-key-vp-et-fp.png)

*Capture 96. Le faux positif vient du nom de clé non borné : `\CurrentVersion\Run` correspond
aussi à `RunNotification`, dans le filtre Sysmon (`contains`) comme dans l'expression de 92300.*

## 6. Pourquoi la première règle ne marchait pas

92300 et la première règle locale étaient **sœurs** sous 61615. Wazuh retient la première sœur
qui correspond ; les fichiers natifs sont chargés avant `local_rules.xml`, donc 92300 gagnait
toujours et laissait l'événement au niveau 0 (déduction sur l'ordre de chargement, cohérente
avec le comportement observé). Correctif : accrocher la règle locale **sous** 92300
(`<if_sid>92300</if_sid>`).

Méthode de diagnostic, utile pour toute règle « muette » :

1. Les règles de niveau 0 n'apparaissent pas dans le dashboard : ne pas conclure que
   l'événement n'arrive pas.
2. Prouver la réception : `<logall_json>yes</logall_json>` dans `<global>` (puis le remettre à
   `no`), lecture de `/var/ossec/logs/archives/archives.json` ; ou `wazuh-logtest`.
3. Chercher dans le ruleset les règles qui partagent le même parent ou le même groupe
   (`if_sid` 61615, `if_group sysmon_event_13`).

## 7. Lecture de l'analyste SOC

1. **Processus écrivain** (`win.eventdata.image`) : installeur de confiance, ou interpréteur
   (`powershell.exe`, `cmd.exe`, `wscript.exe`) ?
2. **Donnée écrite** (`win.eventdata.details`) : programme connu, ou chemin dans un dossier
   utilisateur, `%TEMP%`, script ?
3. **Ruche** : `HKU`/`HKCU` (un utilisateur, sans droits d'administration) ou `HKLM` (tous les
   utilisateurs, droits d'administration).
4. **Suite** : hash du programme visé (VirusTotal), même valeur sur d'autres postes, date de
   création du fichier.

## 8. Remédiation et pistes

| Mesure | Effet | Statut |
|---|---|---|
| Supprimer la valeur et le programme visé après qualification | retire la persistance | manuel |
| Borner le nom de clé dans 100230 : `(?i)\\\\CURRENTVERSION\\\\RUN(ONCE)?\\\\` (échappement de 92300) | supprime le faux positif `RunNotification` | ⏳ à valider avec `wazuh-logtest` |
| Liste blanche (règle enfant de 100230 au niveau 0) pour les installeurs de confiance | réduit le bruit | ✅ 100231 pour Microsoft Edge, validée le 2026-10-28 ([writeup 18](../writeup/18-tuning-faux-positifs.md)) ; autres cas en phase 2 |
| Niveau 12 réservé aux `details` suspects, niveau 3 pour le reste | priorise sans perdre l'historique | ⏳ phase 2, à valider |
| Étendre à `RunOnce`, aux clés `Winlogon` et au dossier Démarrage | couvre les variantes de T1547.001 | ⏳ à étudier (filtre Sysmon à élargir) |

## Résultats dans notre lab

| Date | Cible | Règles observées | Délai de détection | Remarques |
|---|---|---|---|---|
| 2026-10-25 (1er essai) | SIEM-Win11, `HKCU\…\Run` | aucune alerte (92300 niveau 0) | — | 1re règle locale enfant de 61615, jamais évaluée ; réception prouvée par `archives.json` |
| 2026-10-25 19:12 | idem, valeur `WazuhLabTest5` écrite par PowerShell | **100230** niveau 12 (19:12:10) ; faux positif 100230 sur `sihost.exe` → `RunNotification` (19:12:20) | non mesuré | règle locale enfant de 92300 ; nom de clé à borner, liste blanche à prévoir (capture 96) |
