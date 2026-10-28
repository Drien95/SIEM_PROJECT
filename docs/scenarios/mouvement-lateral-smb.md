# Scénario 6 — Mouvement latéral SMB (partages d'administration)

MITRE ATT&CK : **T1021.002** (Remote Services: SMB/Windows Admin Shares), tactique Lateral
Movement.

Statut : **joué le 2026-10-28**, règle locale 100240 observée en live (`alerts.json`),
Wazuh 4.14.9.

Sources :
https://attack.mitre.org/techniques/T1021/002/,
https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction,
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0955-WEF-baseline_rules.xml (67017),
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0840-win_event_channel.xml (92652, 92657),
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0580-win-security_rules.xml (60103, 60104),
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html.

> Test contre la VM Windows 11 du lab uniquement, depuis le réseau d'attaque isolé.
> Récit complet : [writeup 16](../writeup/16-scenario-mouvement-lateral-smb.md).

## 1. Objectif

Vérifier que Wazuh voit l'utilisation d'un compte valide pour atteindre les partages
d'administration d'un poste (suite du scénario 1 : T1110 → T1078 → T1021.002).

## 2. Topologie

| Rôle | Machine | Détail |
|---|---|---|
| Attaquant | Kali `10.10.20.10` (VMnet11) | `smbclient`, à travers pfSense |
| Cible | SIEM-Win11 `10.10.10.101` (agent 001) | audits « Ouverture de session » et « Partage de fichiers » en succès et échec |
| SIEM | Wazuh 4.14.9 `10.10.10.100` | règle locale 100240 |

## 3. Prérequis

1. Audit `{0CCE9215-69AE-11D9-BED3-505054503030}` (Ouverture de session) et
   `{0CCE9224-69AE-11D9-BED3-505054503030}` (Partage de fichiers) en succès et échec
   (famille 03 des [scripts de durcissement](../../scripts/hardening/README.md)).
2. Règle 100240 ([`local_rules.xml`](../../configs/manager/local_rules.xml)) dans
   `/var/ossec/etc/rules/local_rules.xml`, puis
   `sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager`.

## 4. Test

```bash
# sur Kali
smbclient //10.10.10.101/C$ -U 'analyste%<mot de passe>' -c 'ls'
```

Rejoué avec le compte administrateur local `admin-secours`.

## 5. Détection : attendu contre observé

| Étape | Règle | Niveau | Attendu | Observé |
|---|---|---|---|---|
| Accès à `C$` | — | — | refusé | ✅ `NT_STATUS_ACCESS_DENIED`, compte standard **et** admin local |
| Connexion réseau NTLM (4624) | 92652 → **92657** (native) | 6 | alerte | ✅ libellé « possible RDP » imprécis (c'était du SMB) |
| Refus sur `C$` (5140 échec) | **60104** (native) | 5 | alerte | ✅ preuve du refus |
| Accès à `IPC$` (5140 succès) | **67017** (native, T1021.002) | 3 | alerte | ✅ (l'exclusion d'IPC$ de la native ne fonctionne pas, voir writeup 16 § 5.2) |
| Accès depuis le segment d'attaque | **100240** (locale) | 12 | alerte | ✅ 2026-10-28 20:37:03, `10.10.20.10`, compte `analyste`, `\\*\IPC$` |

## 6. Pourquoi l'accès est refusé

Filtrage de jeton UAC à distance : un compte **local** membre des Administrateurs reçoit un
jeton filtré lorsqu'il se connecte par le réseau (`LocalAccountTokenFilterPolicy` = 0, valeur
par défaut, documentation Microsoft). `C$` et `ADMIN$` sont refusés ; `IPC$` reste accessible.
Exception du compte Administrateur intégré (RID 500) : à valider, non testée.

## 7. Lecture de l'analyste SOC

1. **Source** : IP du segment d'attaque, ou poste d'administration connu ?
2. **Compte** : compte de service, administrateur, ou compte utilisateur qui n'a rien à faire
   en SMB vers ce poste ?
3. **Partage** : `IPC$` seul (négociation), ou `C$` / `ADMIN$` (copie, service) ?
4. **Suite** : 5140 en échec (60104) = tentative bloquée ; en succès sur `ADMIN$`, chercher un
   service créé (7045) et un nouveau processus (Sysmon EID 1).

## 8. Remédiation et pistes

| Mesure | Effet | Statut |
|---|---|---|
| Laisser `LocalAccountTokenFilterPolicy` à 0 | bloque le mouvement latéral par comptes locaux | ✅ défaut constaté |
| Détecter la mise à 1 de `LocalAccountTokenFilterPolicy` | signale qu'on affaiblit ce contrôle | ⏳ piste |
| Exclure `IPC\$` dans 100240 | moins de bruit | ⏳ à valider avec `wazuh-logtest` |
| Règle sœur sous 60104 : 5140 en échec sur `C$`/`ADMIN$` depuis `10.10.20.` | voir les tentatives refusées en niveau élevé | ⏳ à écrire |
| Pare-feu : bloquer SMB (445) depuis le segment d'attaque | coupe le chemin | ⏳ volontairement ouvert pour le lab |

## Résultats dans notre lab

| Date | Cible | Règles observées | Délai de détection | Remarques |
|---|---|---|---|---|
| 2026-10-28 20:37 | SIEM-Win11, `C$` puis `IPC$`, comptes `analyste` et `admin-secours` | 92657 (6), 60104 (5), 67017 (3), **100240** (12) | ~1 s (événement 20:37:02, alerte 20:37:03) | accès à `C$` refusé par le filtrage UAC à distance ; 100240 déclenchée sur `IPC$` |
