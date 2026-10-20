# Installation

Version de référence : **Wazuh 4.14**.

## Prérequis matériels (all-in-one)

| Agents | CPU | RAM | Disque (90 jours) |
|---|---|---|---|
| 1-25 | 4 vCPU | 8 GiB | 50 GB |
| 26-50 | 8 vCPU | 8 GiB | 100 GB |
| 51-100 | 8 vCPU | 8 GiB | 200 GB |

OS supportés (64 bits) : Ubuntu 16.04 à 24.04, RHEL 7 à 10, CentOS Stream 10,
Amazon Linux 2/2023. Source : https://documentation.wazuh.com/current/quickstart.html

Avec seulement 4 Go de RAM, voir « Machine modeste » ci-dessous.

## Option A — Assistant all-in-one (recommandé par la doc officielle)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

- Dashboard : `https://<IP_DU_SERVEUR>`, utilisateur `admin`.
- Mot de passe : affiché en fin d'installation, ou :

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

- Certificat auto-signé : l'avertissement du navigateur est attendu.
- Ensuite, désactiver le dépôt pour éviter une mise à jour involontaire
  (Debian/Ubuntu : `sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list && apt update`).
- Désinstallation : `sudo bash ./wazuh-install.sh -u`.

**Ne jamais versionner** `wazuh-install-files.tar` ni les mots de passe.

## Option B — OVA officielle

Utilisée par les deux dépôts de référence : importer l'OVA dans VMware/VirtualBox,
adaptateur réseau en **pont**, récupérer l'IP avec `ip a`, puis ouvrir `https://<IP>`.
Voir https://documentation.wazuh.com/current/deployment-options/index.html

## Machine modeste (4-8 Go de RAM)

Astuces issues de UsmanPrime/Wazuh-Setup, **à valider** dans notre lab :

```bash
# Limiter le tas Java de l'indexeur
sudo nano /etc/wazuh-indexer/jvm.options          # -Xms1g et -Xmx1g

# Laisser plus de temps au démarrage de l'indexeur
sudo nano /etc/systemd/system/wazuh-indexer.service.d/startup-timeout.conf
# [Service]
# TimeoutStartSec=1200

sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard
```

Ordre de démarrage : indexeur d'abord (vérifier `sudo ss -tulpn | grep 9200`), puis
manager, puis dashboard.

## Agents

Le dashboard génère la commande d'installation (menu *Deploy new agent*) avec l'IP du
serveur et le nom de l'agent.

**Windows**

- Configuration : `C:\Program Files (x86)\ossec-agent\ossec.conf`
- Journal : `C:\Program Files (x86)\ossec-agent\ossec.log`
- Service : `WazuhSvc`

```powershell
NET START WazuhSvc
Set-Service -Name WazuhSvc -StartupType Automatic
Restart-Service -Name WazuhSvc
Test-NetConnection -ComputerName <IP_SERVEUR> -Port 1514
```

**Linux** : paquet `wazuh-agent` ; configuration `/var/ossec/etc/ossec.conf` ;
`sudo systemctl enable --now wazuh-agent`.

## Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| « Wazuh dashboard server is not ready yet » | Indexeur à court de mémoire ou démarrage trop lent | Appliquer les réglages mémoire/délai, redémarrer |
| Erreur SSL dans le navigateur | Certificat auto-signé | Accepter l'exception ou installer un certificat de confiance |
| Pas de ping vers la VM | Adaptateur pas en mode pont | Corriger le réseau de la VM |
| Agent enregistré mais déconnecté | Port 1514 bloqué | Vérifier le pare-feu, `Test-NetConnection`, lire `ossec.log` |
| `WazuhSvc` ne s'arrête pas | Processus bloqué | `Stop-Process` puis redémarrer le service |

Sources : UsmanPrime/Wazuh-Setup, documentation Wazuh (quickstart, architecture).
