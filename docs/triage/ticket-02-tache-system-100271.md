# Ticket de triage 02 : tâche planifiée en SYSTEM (alerte 100271, niveau 12)

> Exercice de triage, 2026-10-29. Alerte du scénario 10
> ([writeup 21](../writeup/21-scenario-tache-planifiee-system.md)), qualifiée à partir des seules
> données du SIEM.

## 1. Alerte

| Champ | Valeur |
|---|---|
| Règle | **100271**, niveau 12 : « Tâche planifiée \LabS10 en SYSTEM créée par analyste (4698) » |
| Date | 2026-10-29 15:03:34.945 UTC |
| Poste | `DESKTOP-A2AMF2E` (agent `SIEM-Win11`) |
| Règle sœur | **100270** (niveau 12, Sysmon) à 15:03:34.864 sur la commande `schtasks` |
| MITRE | T1053.005 Scheduled Task (Privilege Escalation, aussi Persistence et Execution) |

## 2. Investigation

Pivot : toutes les alertes du poste de 14:58 à 15:08 UTC.

### Chronologie

| Heure (UTC) | Règle (niveau) | Compte | Événement |
|---|---|---|---|
| 15:00:04.806 | 67027 (3) | analyste | `auditpol /set /subcategory:{0CCE9227-…} /success:enable…` : modification de la politique d'audit (« Autres événements d'accès aux objets », qui produit le 4698) |
| 15:03:27.726 | 67027 (3) | système | `consent.exe` : invite UAC, élévation acceptée |
| 15:03:29.354 | 67027 (3) | — | `powershell.exe` élevé |
| 15:03:34.786 | 67027 (3) | analyste | `HOSTNAME.EXE` |
| 15:03:34.848 | 67027 (3) | analyste | `whoami.exe` : « qui suis-je ? » (T1033, déduit) |
| 15:03:34.864 | **100270** (12) | analyste | `schtasks /create /tn LabS10 /tr "cmd.exe /c whoami > C:\Users\Public\s10.txt" … /ru SYSTEM` |
| 15:03:34.945 | **100271** (12) | analyste | événement 4698 : tâche `\LabS10` enregistrée, s'exécute en SYSTEM |
| 15:03:34.992 | 67027 (3) | analyste | `schtasks /run /tn LabS10` : exécution **immédiate** |
| 15:03:35.007 | 92032 (3) | **Système** | native « Suspicious Windows cmd shell execution » : `whoami` |
| 15:03:35.039 | 67027 (3) | `DESKTOP-A2AMF2E$` | `cmd.exe /c whoami > C:\Users\Public\s10.txt` lancé par la tâche |
| 15:03:38.107 | 67027 (3) | analyste | `schtasks /delete /tn LabS10 /f` : **suppression 3 secondes après** |

### Lecture

- **Qui** : `analyste`, en session administrateur après une élévation UAC (`consent.exe`).
- **Quoi** : une tâche dont la seule action est `whoami` en SYSTEM, écrite dans un fichier
  lisible par tous. C'est la vérification typique d'une **élévation réussie** : l'attaquant
  prouve qu'il exécute du code en SYSTEM avant de s'en servir (déduit).
- **Créée, lancée, supprimée en 4 secondes** : la tâche n'est pas une persistance, c'est un
  **tremplin** vers SYSTEM. Sa suppression immédiate efface la trace sur le poste : un
  `schtasks /query` après coup ne montre rien. Le SIEM, lui, a gardé la création (4698), la
  commande (Sysmon) et l'exécution en SYSTEM.
- **Preuve de l'exécution en SYSTEM** : le `cmd.exe` de 15:03:35 tourne sous
  `DESKTOP-A2AMF2E$` (compte machine, ce que Windows journalise pour SYSTEM), et la native 92032
  le rattache à `AUTORITE NT\Système`.
- **Modification de l'audit 3 min avant** (`auditpol /set`) : dans un vrai incident, toucher à la
  politique d'audit est un signal fort (T1562.002 quand on **désactive**). Ici elle **active**
  une catégorie : c'est la préparation du test. Non couvert par une règle locale : à noter.

### Limites

- Le XML de la tâche (`taskContent`) n'a pas été relu correctement par notre extraction
  (antislashs et retours à la ligne échappés). La commande est connue par 100270 : la
  redondance des deux sources (Sysmon et 4698) a servi.
- Le contenu de `s10.txt` n'est pas dans le SIEM (pas de FIM sur `C:\Users\Public`).

## 3. Qualification

| Question | Réponse |
|---|---|
| Vrai positif ? | **Oui** : création d'une tâche SYSTEM par un compte utilisateur, exécutée puis supprimée aussitôt |
| Gravité | **Haute** : obtention de SYSTEM sur le poste, avec nettoyage |
| Faux positif possible ? | Un installeur crée des tâches SYSTEM, mais en tant que SYSTEM (exclu par 100271, 0 faux positif sur 6 tâches légitimes, writeup 21) et sans les supprimer aussitôt |
| Contexte réel | exercice de lab, scénario 10 (connu après coup) |

## 4. Actions recommandées (playbook, non exécutées)

1. **Contenir** : isoler le poste : un attaquant SYSTEM peut désactiver l'agent.
2. **Vérifier l'agent** : dernière remontée de `SIEM-Win11`, service `WazuhSvc` actif.
3. **Chercher la suite** : alertes du poste après 15:03:38 (création de compte, accès LSASS,
   effacement de journaux : scénarios 5 et 7).
4. **Compte** : comment `analyste` est-il administrateur ? Revoir les membres du groupe
   Administrateurs, lien avec le brute force (scénario 1).

## 5. Améliorations de détection issues du ticket

| Manque | Correction proposée | Statut |
|---|---|---|
| Suppression rapide de tâche non corrélée | corrélation **100272/100273** : 4698 puis 4699 de la même tâche en moins de 60 s | ✅ fait ([writeup 26](../writeup/26-du-triage-au-tuning.md)) |
| `auditpol /set` non alerté | pas un trou : le `/set` remettait la valeur en place, sans 4719. Un vrai retrait déclenche 60112 ; **100251** le monte au niveau 12 (T1562.002) | ✅ fait ([writeup 26](../writeup/26-du-triage-au-tuning.md)) |
| `schtasks /run` juste après `/create` | corrélation 100270 puis `/run` | à étudier |
| Bruit **61618** (niveau 12) sur `svchost.exe` légitimes, 5 fois dans la fenêtre | liste blanche **100120** | ✅ fait |
