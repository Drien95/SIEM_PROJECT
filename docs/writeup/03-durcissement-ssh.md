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

**Qui se connecte à quoi** (choix d'Adrien) :

| Client | Clé | Vers | Usage |
|---|---|---|---|
| Hôte (PC, `10.10.10.1`) | `id_ed25519_siemlab` | Wazuh `wazuh-user@10.10.10.100`, pfSense `admin@10.10.10.254` | administration |
| VM Windows 11 (`10.10.10.101`) | `id_ed25519` (générée dans la VM) | Wazuh uniquement | tests depuis le poste du lab |

- **Une clé par poste client** : si la VM Windows (la cible des attaques) est compromise, on
  retire sa seule clé de `authorized_keys`, sans toucher à celle de l'hôte.
- **Une clé dédiée au lab** sur l'hôte, distincte des clés personnelles existantes (GitLab…) :
  `IdentitiesOnly yes` dans `~/.ssh/config` empêche SSH de proposer les autres clés.
- Chaque ligne de `authorized_keys` porte un commentaire (`-C`) qui dit à qui elle appartient.

## 2. Wazuh (Amazon Linux 2023)

### 2.1 Générer les clés (PowerShell)

Sur l'**hôte** :

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519_siemlab -C "adrien@hote-siemlab"
```

Dans la **VM Windows 11** (déjà faite) :

```powershell
ssh-keygen -t ed25519 -C "adrien@siem-win11"
```

Phrase de passe recommandée. La clé privée (sans `.pub`) ne se copie ni ne se versionne jamais.

Alias ajoutés au `~/.ssh/config` de l'hôte (sauvegarde `config.bak-siemlab`) :

```
Host siem-wazuh
    HostName 10.10.10.100
    User wazuh-user
    IdentityFile ~/.ssh/id_ed25519_siemlab
    IdentitiesOnly yes

Host siem-pfsense
    HostName 10.10.10.254
    User admin
    IdentityFile ~/.ssh/id_ed25519_siemlab
    IdentitiesOnly yes
```

Ensuite `ssh siem-wazuh` suffit.

### 2.2 Déposer la clé publique

Windows n'a pas `ssh-copy-id`. Équivalent, depuis l'hôte (le mot de passe est encore
accepté à ce stade) :

```powershell
type $env:USERPROFILE\.ssh\id_ed25519_siemlab.pub | ssh wazuh-user@10.10.10.100 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

La clé de la VM Windows a déjà été ajoutée de la même façon. Contrôle, une ligne par clé :

```bash
cut -d' ' -f3 ~/.ssh/authorized_keys
```

Les droits comptent : OpenSSH refuse une clé si `~/.ssh` ou `authorized_keys` est accessible en
écriture par d'autres (`StrictModes`).

Test, qui ne doit plus demander que la phrase de passe de la clé :

```powershell
ssh siem-wazuh                      # depuis l'hôte
ssh wazuh-user@10.10.10.100         # depuis la VM Windows 11
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
3. Test depuis l'hôte : `ssh siem-pfsense`, qui ouvre le menu console de pfSense.

Constaté le 2026-10-21 : le port 22 de pfSense est **fermé** (`Test-NetConnection 10.10.10.254
-Port 22` → `False`) ; SSH est désactivé par défaut. La règle LAN par défaut (« Default allow LAN
to any ») laisse passer l'hôte, et l'« anti-lockout rule » protège l'accès d'administration
depuis le LAN.

L'interface web garde son mot de passe : ce réglage ne concerne que SSH.

## 4. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| Hôte sur VMnet10 | `10.10.10.1` | ✅ |
| Port 22 Wazuh depuis l'hôte | ouvert | ✅ |
| Port 22 pfSense depuis l'hôte | ouvert après activation | ❌ fermé (SSH désactivé par défaut) |
| Clé VM Windows → Wazuh | session sans mot de passe | ✅ selon Adrien |
| Clé hôte `id_ed25519_siemlab` → Wazuh | session sans mot de passe | à faire |
| Mot de passe refusé sur Wazuh | `Permission denied (publickey)` | à faire |
| Connexion par clé à pfSense | menu console pfSense | à faire |

Sources : `man sshd_config` (OpenSSH, règle « first obtained value »),
https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html
