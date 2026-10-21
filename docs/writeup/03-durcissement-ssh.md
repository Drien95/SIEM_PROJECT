# Writeup 03 : SSH par clé vers Wazuh et pfSense

> Remplacer les connexions par mot de passe (console, SSH) par des clés SSH, puis interdire
> le mot de passe. Document vivant.
>
> Versions : Wazuh OVA 4.14.9 (Amazon Linux 2023, OpenSSH), pfSense CE 2.9.0.

## 1. Comprendre

- **Mot de passe** : un secret qu'on envoie au serveur. S'il est faible, réutilisé ou vu (ce qui
  nous est arrivé dans le writeup 01), n'importe qui peut se connecter, et la force brute
  marche.
- **Clé SSH** : une paire. La **clé privée** reste sur le poste et ne circule jamais. La **clé
  publique** est déposée sur le serveur (`~/.ssh/authorized_keys`). Le serveur envoie un défi,
  que seul le détenteur de la clé privée sait signer. Rien de réutilisable ne passe sur le
  réseau.
- **ed25519** : algorithme de clé moderne, court et rapide. On protège la clé privée par une
  **phrase de passe** : volée seule, elle ne suffit pas.
- Une fois les clés en place, on **désactive le mot de passe** côté serveur : la force brute
  SSH devient inutile. C'est exactement l'attaque que le scénario brute force simulera ensuite.

**Depuis quel poste ?** La clé privée donne un accès administrateur au SIEM. Elle doit vivre sur
le poste d'administration, c'est-à-dire **l'hôte**, pas sur la VM Windows 11, qui est la
**cible** des attaques du lab. Si cette VM est compromise, l'attaquant hérite de l'accès au SIEM.
(Recommandation ; Adrien a commencé depuis la VM Windows.)

## 2. Wazuh (Amazon Linux 2023)

### 2.1 Générer la clé (PowerShell, poste d'administration)

```powershell
ssh-keygen -t ed25519 -C "admin-siem-lab"      # phrase de passe recommandée
```

Fichiers : `%USERPROFILE%\.ssh\id_ed25519` (privée, ne jamais copier ni versionner) et
`id_ed25519.pub` (publique).

### 2.2 Déposer la clé publique

Windows n'a pas `ssh-copy-id`. Équivalent :

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh wazuh-user@10.10.10.100 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Les droits comptent : OpenSSH refuse une clé si `~/.ssh` ou `authorized_keys` est accessible en
écriture par d'autres (`StrictModes`).

Test, qui ne doit plus demander que la phrase de passe de la clé :

```powershell
ssh wazuh-user@10.10.10.100
```

### 2.3 Interdire le mot de passe

**Garder une session SSH ouverte** pendant toute l'opération : en cas d'erreur, elle permet de
corriger sans repasser par la console.

```bash
sudo tee /etc/ssh/sshd_config.d/00-durcissement.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF
sudo sshd -t && sudo systemctl reload sshd
sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) '
```

Pourquoi le préfixe `00-` : `sshd_config` inclut `sshd_config.d/*.conf` **au début**, et pour
OpenSSH c'est la **première** valeur lue qui gagne. Un fichier livré par la distribution (par
exemple un `50-*.conf` avec `PasswordAuthentication yes`) l'emporterait sinon. `sshd -T`
affiche la configuration réellement appliquée. C'est elle qui fait foi. (Ordre des fichiers sur
cette OVA : à vérifier avec `ls /etc/ssh/sshd_config.d/`.)

Test depuis une **nouvelle** fenêtre, la première restant ouverte :

```powershell
ssh -o PubkeyAuthentication=no wazuh-user@10.10.10.100
```

Attendu : `Permission denied (publickey…)`. Le mot de passe est bien refusé.

## 3. pfSense

1. *System > User Manager > admin* : coller le contenu de `id_ed25519.pub` dans
   **Authorized SSH Keys**, puis *Save*.
2. *System > Advanced > Admin Access*, section *Secure Shell* : cocher **Enable Secure Shell**,
   *SSHd Key Only* = **Public Key Only**, puis *Save*.
3. Test : `ssh admin@10.10.10.254`, qui ouvre le menu console de pfSense.

L'interface web garde son mot de passe : ce réglage ne concerne que SSH.

## 4. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| Clé ed25519 générée | `id_ed25519` / `.pub` | ✅ (sur la VM Windows 11) |
| Connexion par clé à Wazuh | session ouverte sans mot de passe | ✅ selon Adrien |
| Mot de passe refusé sur Wazuh | `Permission denied (publickey)` | à faire |
| Connexion par clé à pfSense | menu console pfSense | à faire |

Sources : `man sshd_config` (OpenSSH, règle « first obtained value »),
https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html
