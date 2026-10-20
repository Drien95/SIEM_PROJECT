# Scénario — Brute force SSH / RDP

MITRE ATT&CK : **T1110** (Brute Force), sous-technique T1110.001 (Password Guessing).

Sources : PDF `SSH_Brute_Force` (marxgoo),
https://documentation.wazuh.com/current/proof-of-concept-guide/detect-brute-force-attack.html

> À jouer **uniquement** contre des VM du lab, sur un réseau isolé.

## Familles d'attaque

Simple (toutes les combinaisons), dictionnaire, hybride (dictionnaire + variantes),
inversée (un mot de passe, beaucoup d'utilisateurs : *password spraying*), credential
stuffing (couples fuités). Outils : Hydra (en ligne, plus de 50 protocoles), John the Ripper
et Hashcat (hors ligne, sur des hashes).

## Préparation

- Attaquant : Kali, avec Hydra.
- Cible Windows : installer et démarrer **OpenSSH Server**, qui n'est pas actif par défaut :

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
```

- Cible Linux : `sshd` avec l'authentification par mot de passe activée, à remettre en
  l'état après le test.
- Une liste `passwords.txt` d'une dizaine de mots de passe.

## Attaque

```bash
hydra -l <utilisateur> -P passwords.txt ssh://<IP_CIBLE>      # SSH
hydra -l <utilisateur> -P passwords.txt rdp://<IP_CIBLE>      # RDP Windows
```

`-l` désigne un utilisateur connu, `-L` un fichier d'utilisateurs.

## Détection attendue

| Cible | Règles Wazuh | Recherche Threat Hunting |
|---|---|---|
| Linux sshd | 5710, 5711, 5716, puis **5712** / **5551** (corrélation) | `rule.id:(5551 OR 5712)` |
| Windows RDP | **60122**, **60204** | `rule.id:(60122 OR 60204)` |
| Windows SSH (OpenSSH) | Événement 4625 → 60122 (niveau 5 dans le PDF) | `data.win.system.eventID:4625` |

Champs utiles d'une alerte 4625 (relevés dans le PDF) :

| Champ | Valeur | Lecture |
|---|---|---|
| `data.win.system.eventID` | 4625 | Échec d'ouverture de session |
| `data.win.eventdata.logonType` | 8 | NetworkCleartext, typique de sshd |
| `data.win.eventdata.processName` | `C:\Windows\System32\OpenSSH\sshd.exe` | La tentative passe par SSH |
| `data.win.eventdata.status` / `subStatus` | `0xc000006d` / `0xc0000064` | Échec : utilisateur inconnu ou mauvais mot de passe |
| `data.win.eventdata.failureReason` | `%%2313` | Idem, sous forme de code |
| `rule.firedtimes` | 14 | Nombre de déclenchements : ce n'est pas un événement isolé |

## Réponse

- **Réponse active Wazuh** : bloquer l'IP source sur alerte 5712 ou 60204
  (`firewall-drop` sous Linux, `netsh` sous Windows). Configuration à écrire et à tester.
- Durcissement : mots de passe forts, MFA, verrouillage de compte, limitation du débit,
  désactivation de l'authentification SSH par mot de passe.

## Résultats dans notre lab

| Date | Cible | Règles observées | Délai de détection | Remarques |
|---|---|---|---|---|
| à remplir | | | | |
