# Durcissement CIS de Windows 11 (scripts PowerShell)

Scripts de **remédiation** du benchmark CIS Microsoft Windows 11 Enterprise v3.0.0 pour l'agent
du lab (`SIEM-Win11`, Wazuh 4.14.9). Ils corrigent ce que le module SCA mesure (voir
[l'intégration SCA](../../docs/integrations/sca.md) et le [writeup 12](../../docs/writeup/12-sca-cis-windows11.md)),
puis relancent un scan pour **prouver** la correction : mesurer, corriger, re-mesurer.

> **Statut : validés sur la VM le 2026-10-25** (Windows 11 Professionnel build 26300, en
> français) : dry-run, puis application des familles 01, 03 et 02 avec sauvegarde, vérification
> par relecture et garde-fou. Récit et constats : [writeup 13](../../docs/writeup/13-durcissement-cis-automatise.md).
> Le rollback est disponible pour chaque exécution mais n'a pas encore été rejoué sur la VM.

## Contenu

```
scripts/hardening/
├── Invoke-Hardening.ps1          orchestrateur : contrôles, sauvegarde globale, familles, rapport, rescan SCA
├── HardeningLib.psm1             module commun : lecture, comparaison, sauvegarde, restauration, garde-fous, journal
└── families/
    ├── 01-password-policy.ps1    CIS 1.1  politique de mots de passe         risque faible
    ├── 02-account-lockout.ps1    CIS 1.2  verrouillage de comptes            risque ÉLEVÉ (garde-fou)
    ├── 03-audit-policy.ps1       CIS 17   stratégie d'audit avancé (+3)      risque faible
    └── _template.ps1             modèle pour ajouter une famille
```

## Principe

Chaque famille décrit ses réglages comme des **données** (référence CIS, id du check SCA
Wazuh, cible, opérateur de comparaison repris du check). Le moteur commun fait le reste :

1. **Lire** l'état réel (`secedit /export`, `auditpol /backup`, registre).
2. **Comparer** chaque réglage à l'attendu. Déjà conforme : on n'y touche pas (idempotent).
3. Sans `-Apply` : **dry-run**, on affiche seulement ce qui changerait. C'est le mode par défaut.
4. Avec `-Apply` : **garde-fou** (famille 02), **sauvegarde**, application des seuls réglages
   non conformes.
5. **Vérifier** en relisant l'état réel (on ne se fie pas aux codes de retour) : PASS ou FAIL
   par réglage.
6. **Rapport** (`report.md`, `report.csv`) et **journal** horodaté.
7. `-Rescan` : redémarre `WazuhSvc` ; l'agent relance le scan SCA au démarrage
   (`scan_on_start`, actif par défaut).

Tout est rangé par exécution dans `C:\ProgramData\SIEM-Hardening\runs\<AAAAMMJJ-HHmmss>\` :

| Fichier | Contenu |
|---|---|
| `hardening.log` | journal horodaté de l'exécution |
| `report.md`, `report.csv` | rapport : avant, après, attendu, statut (CSV séparé par `;`, s'ouvre dans Excel FR) |
| `global\` | sauvegarde globale avant `-Apply` : `secedit` toutes zones + `auditpol` (filet manuel) |
| `backups\<famille>\` | sauvegarde de la famille : `secpol.inf`, `auditpol.csv`, `registry.json`, `manifest.json` |

Aucun secret dans ces fichiers : l'export `secedit` ne contient pas de hash de mot de passe.

## Garde-fous

| Garde-fou | Où |
|---|---|
| Dry-run par défaut, rien n'est appliqué sans `-Apply` | toutes les familles |
| Refus de démarrer sans PowerShell administrateur | toutes |
| Sauvegarde **avant** toute modification ; arrêt si elle échoue | toutes |
| Vérification par relecture, statut FAIL si la valeur lue n'est pas la bonne | toutes |
| Audit : on **ajoute** succès/échec, on ne retire jamais un audit existant | 03 |
| Exige `-AcceptLockoutRisk`, sinon la famille est ignorée | 02 |
| Exige **deux** comptes administrateurs locaux activés (compte de secours) | 02 |
| Affiche la procédure de déverrouillage **avant** d'appliquer | 02 |
| Confirmation tapée `OUI` (sauf `-Force`, mode automatisé) | 02 |
| Avertit si le poste est en domaine (une GPO écraserait les réglages locaux) | orchestrateur |
| Après `-Rescan`, vérifie que `WazuhSvc` tourne et le relance sinon (incident déjà vu dans le lab) | orchestrateur |

## Mode d'emploi

Tout se fait **sur la VM Windows 11**, dans un **PowerShell ouvert en tant qu'administrateur**.

### 1. Copier les scripts sur la VM

Copier le dossier `scripts\hardening` du dépôt (sur le PC : `C:\Project\SIEM_PROJECT\scripts\hardening`)
vers `C:\Lab\hardening` sur la VM (glisser-déposer VMware ou dossier partagé), puis :

```powershell
Set-Location C:\Lab\hardening
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Get-ChildItem -Recurse | Unblock-File
```

`-Scope Process` : l'autorisation ne vaut que pour cette fenêtre PowerShell. `Unblock-File`
retire la marque « fichier venu d'ailleurs » posée par Windows sur une copie.

### 2. Dry-run de tout

```powershell
.\Invoke-Hardening.ps1
```

Rien n'est modifié. Lire le tableau : `PASS` = déjà conforme, `DRYRUN` = serait modifié.

### 3. Appliquer une famille, puis re-mesurer

Ordre conseillé : **01**, puis **03**, puis **02** en dernier (la seule risquée).

```powershell
.\Invoke-Hardening.ps1 -Families 01 -Apply -Rescan
```

Attendre quelques minutes, puis dans le dashboard : **Endpoint security > Configuration
Assessment > SIEM-Win11**. Les checks 26000 à 26003 doivent passer à Passed.

```powershell
.\Invoke-Hardening.ps1 -Families 03 -Apply -Rescan
```

### 4. Famille 02 (verrouillage de comptes)

Voir d'abord la section [Verrouillage de comptes](#verrouillage-de-comptes). Créer le compte de
secours (une seule fois) : le script demande le mot de passe sans l'afficher.

```powershell
$pw = Read-Host -AsSecureString "Mot de passe du compte de secours"
New-LocalUser -Name "secours-admin" -Password $pw -PasswordNeverExpires -Description "Compte de secours du lab (anti-verrouillage)"
Add-LocalGroupMember -SID "S-1-5-32-544" -Member "secours-admin"
```

`S-1-5-32-544` désigne le groupe Administrateurs quelle que soit la langue de Windows. Noter
ce mot de passe dans `wazuh-passwords.txt` (hors git), jamais dans le dépôt. Puis :

```powershell
.\Invoke-Hardening.ps1 -Families 02 -Apply -AcceptLockoutRisk -Rescan
```

### 5. Revenir en arrière

```powershell
.\Invoke-Hardening.ps1 -Rollback -Families 02 -Rescan
```

Sans `-FromRun`, chaque famille est restaurée depuis **sa dernière sauvegarde appliquée**.
Pour annuler exactement une exécution, reprendre la commande affichée à la fin de celle-ci :
`.\Invoke-Hardening.ps1 -Rollback -FromRun "C:\ProgramData\SIEM-Hardening\runs\..."`.
Les familles sont restaurées dans l'ordre inverse.

### Mode automatisé

Pour enchaîner sans question (après validation manuelle de chaque famille) :

```powershell
.\Invoke-Hardening.ps1 -Apply -AcceptLockoutRisk -Force -Rescan
```

`-Force` supprime seulement la confirmation tapée `OUI` : le compte de secours reste exigé.
Code de sortie : `0` si tout est PASS, `1` sinon, exploitable par une tâche planifiée.

Chaque famille se lance aussi seule (`.\families\01-password-policy.ps1 -Apply`), mais
l'orchestrateur ajoute la sauvegarde globale, le rapport et le rescan.

## Avertissements

### Verrouillage de comptes

La famille 02 verrouille un compte après **5 échecs** pendant **15 minutes**.

- **Scénario 1 (brute force SMB)** : Kali verrouillera le compte visé au 5e essai. C'est
  l'effet recherché en production (et l'événement 4740 est une belle détection), mais pour
  rejouer le scénario 1 tel quel, faire d'abord `-Rollback -Families 02`.
- Compte verrouillé : se connecter avec le compte de secours, puis
  `net user analyste /active:yes` ; ou désactiver le verrouillage : `net accounts /lockoutthreshold:0`.
- CIS 1.2.3 (verrouillage du compte Administrateur intégré) n'est appliqué qu'avec
  `-IncludeAdministratorLockout`. Ce compte est désactivé par défaut sur Windows 11.

### Mots de passe

- Longueur 14 et complexité s'appliquent au **prochain changement** de mot de passe ; les
  mots de passe actuels restent valides.
- Âge maximal 365 jours : un compte dont le mot de passe a plus d'un an devra le changer à la
  prochaine ouverture de session (sauf comptes « le mot de passe n'expire jamais »).

### Audit

- Plus d'événements dans le journal Security, donc plus d'événements envoyés à Wazuh : surveiller
  la charge du manager après la famille 03 (à valider). Le journal Security passe à 192 Mo
  minimum pour ne rien perdre.
- La ligne de commande dans l'événement 4688 peut contenir un mot de passe tapé en clair.
- **Faux « Failed » SCA lié à la langue** (**confirmé** sur la VM le 2026-10-25, voir le writeup 13) : les checks 26139 à 26165
  appellent `auditpol /get /subcategory:"Logon"` avec le nom **anglais** et cherchent le texte
  `Success and Failure`. Sur notre Windows **français**, le nom attendu est traduit et la sortie
  aussi : ces checks risquent de rester Failed même une fois l'audit conforme. Le rapport du
  script, qui lit l'état par **GUID**, fait foi. Pour le vérifier sur la VM :
  `auditpol /get /subcategory:"Logon"` puis `auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"`.
  Si c'est confirmé, piste de la phase 2 : une politique SCA maison basée sur les GUID.

## Résultats dans notre lab

| Date | Famille | Mode | Résultat du script | Score SCA avant → après | Remarques |
|---|---|---|---|---|---|
| 2026-10-25 | 1.1.4 seul (à la main) | `net accounts /minpwlen:14` | - | check 26003 Failed → Passed | validé, voir writeup 12 |
| 2026-10-25 | toutes | dry-run | bilan PASS / DRYRUN | — | rien de modifié |
| 2026-10-25 | 01 | `-Apply -Rescan` | déjà conforme : PASS | inchangé | 1.1.4 corrigé auparavant à la main |
| 2026-10-25 | 03 | `-Apply -Rescan` | 30 réglages PASS | +3 checks (26013, 26222, 26376) | checks 17.x restés Failed : faux échec dû à la langue (confirmé) |
| 2026-10-25 | 02 | `-Apply -Rescan -AcceptLockoutRisk` | PASS=3 (seuil 10→5, durée 10→15, reset 10→15) | 26005-26007 suivent (valeur exacte du score non relevée) | compte de secours `admin-secours` ; `OUI` exigé ; rejouer le scénario 1 : 4740 attendu |

## Ajouter une famille

Copier `families/_template.ps1` en `families/NN-nom.ps1` et suivre les étapes de son en-tête :
reprendre la cible et l'opérateur exacts du check SCA (`ruleset/sca/windows/cis_win11_enterprise.yml`),
commenter chaque réglage, choisir le niveau de risque, tester dry-run, `-Apply`, rescan,
`-Rollback`. Pistes à faible risque : 2.3.x options de sécurité (registre), 18.x modèles
d'administration (registre), 9.x pare-feu Windows (attention à l'accès réseau de l'agent).

## Sources

- Politique SCA Wazuh `cis_win11_enterprise.yml` v4.14.0 (ids des checks, cibles, opérateurs) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/sca/windows/cis_win11_enterprise.yml
- Benchmarks CIS : https://www.cisecurity.org/cis-benchmarks/
- `secedit` : https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
- `auditpol` (GUID acceptés par `/subcategory`) :
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set,
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-backup
- GUID des sous-catégories d'audit (MS-GPAC, vérifiés le 2026-10-25 pour les 27 GUID de la famille 03) :
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
- Politique de verrouillage :
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-policy
- SCA, `scan_on_start` : https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/sca.html

Liste complète : [docs/sources.md](../../docs/sources.md).
